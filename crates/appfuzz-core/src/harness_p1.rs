//! Preview 1 uses the SDK's descriptor table and ABI, with virtual timers.
//! Its built-in poll_oneoff waits on real Tokio deadlines, independently of
//! the component linker overrides, so modules need this separate entry point.

use wasmtime::{AsContextMut, Caller, Extern, Linker};
use wasmtime_wasi::p1::{WasiP1Ctx, types, wasi_snapshot_preview1::WasiSnapshotPreview1};
use wiggle::{GuestMemory, GuestPtr, GuestType};

use super::Host;
use crate::wasi::VirtualClock;

pub(super) fn link(linker: &mut Linker<Host>) -> wasmtime::Result<()> {
    wasmtime_wasi::p1::add_to_linker_sync(linker, |host: &mut Host| host.p1.as_mut().expect("plain-module runs have a WASI p1 context"))?;
    linker.allow_shadowing(true);
    linker.func_wrap("wasi_snapshot_preview1", "poll_oneoff", |mut caller: Caller<'_, Host>, subs: i32, events: i32, count: i32, result: i32| {
        let fuel = caller.as_context_mut().hostcall_fuel();
        let clock = caller.data().clock.clone();
        let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
            return Err(wasmtime::Error::msg("missing required memory export"));
        };
        // Shared memories are rejected by App before linking.
        let (bytes, host) = memory.data_and_store_mut(&mut caller);
        let mut memory = GuestMemory::Unshared(bytes);
        let ctx = host.p1.as_mut().expect("plain-module runs have a WASI p1 context");
        match poll(ctx, &mut memory, GuestPtr::new(subs as u32), GuestPtr::new(events as u32), count as u32, fuel, &clock) {
            Ok(count) => {
                memory.write(GuestPtr::new(result as u32), count)?;
                Ok(0i32)
            }
            Err(error) => error.downcast().map(|errno| i32::from(u16::from(errno))),
        }
    })?;
    linker.allow_shadowing(false);
    Ok(())
}

struct Timer {
    index: usize,
    userdata: u64,
    delay: u64,
}

fn poll(
    ctx: &mut WasiP1Ctx,
    memory: &mut GuestMemory<'_>,
    subs: GuestPtr<types::Subscription>,
    events: GuestPtr<types::Event>,
    count: u32,
    fuel: usize,
    clock: &VirtualClock,
) -> Result<u32, types::Error> {
    if count == 0 {
        return Err(types::Errno::Inval.into());
    }
    // Preserve the SDK's per-host-call allocation quota, before copying an
    // untrusted array. This quota is separate from guest instruction fuel.
    let bytes = (count as usize).checked_mul(size_of::<types::Subscription>() + size_of::<types::Event>()).ok_or(types::Errno::Overflow)?;
    if bytes > fuel {
        return Err(types::Errno::Nomem.into());
    }
    let wall = clock.with(|state| state.base_wall_ns.saturating_add(state.elapsed_ns()));
    let monotonic = clock.monotonic_now();
    let mut timers = Vec::new();
    let mut descriptors = Vec::new();
    // Snapshot inputs before writing any events: input and output may alias.
    for (index, sub) in subs.as_array(count).iter().enumerate() {
        let sub = memory.read(sub?)?;
        match &sub.u {
            types::SubscriptionU::Clock(timer) => {
                let now = match timer.id {
                    types::Clockid::Realtime => wall,
                    types::Clockid::Monotonic => monotonic,
                    _ => return Err(types::Errno::Inval.into()),
                };
                let absolute = timer.flags.contains(types::Subclockflags::SUBSCRIPTION_CLOCK_ABSTIME);
                timers.push(Timer { index, userdata: sub.userdata, delay: if absolute { timer.timeout.saturating_sub(now) } else { timer.timeout } });
            }
            _ => descriptors.push((index, sub)),
        }
    }
    let mut ready = descriptor_events(ctx, &descriptors, fuel)?;
    let delay = if ready.is_empty() { timers.iter().map(|timer| timer.delay).min().unwrap_or(0) } else { 0 };
    if !timers.is_empty() {
        clock.with(|state| {
            state.sleep_ns = state.sleep_ns.saturating_add(delay);
            state.sleeps = state.sleeps.saturating_add(1);
        });
    }
    for timer in timers.into_iter().filter(|timer| timer.delay <= delay) {
        ready.push((
            timer.index,
            types::Event {
                userdata: timer.userdata,
                error: types::Errno::Success,
                type_: types::Eventtype::Clock,
                fd_readwrite: types::EventFdReadwrite { nbytes: 0, flags: types::Eventrwflags::empty() },
            },
        ));
    }
    ready.sort_unstable_by_key(|(index, _)| *index);
    let count = ready.len() as u32;
    for (pointer, (_, event)) in events.as_array(count).iter().zip(ready) {
        memory.write(pointer?, event)?;
    }
    Ok(count)
}

/// Keep the SDK's descriptor validation, readiness and event metadata. The
/// sandbox provides closed stdin and captured stdout/stderr, all immediately
/// ready; guests may close or renumber these, but cannot open external files.
fn descriptor_events(ctx: &mut WasiP1Ctx, descriptors: &[(usize, types::Subscription)], fuel: usize) -> Result<Vec<(usize, types::Event)>, types::Error> {
    if descriptors.is_empty() {
        return Ok(Vec::new());
    }
    let count = descriptors.len() as u32;
    let output = count.checked_mul(types::Subscription::guest_size()).ok_or(types::Errno::Overflow)?;
    let length = output.checked_add(count.checked_mul(types::Event::guest_size()).ok_or(types::Errno::Overflow)?).ok_or(types::Errno::Overflow)?;
    let mut bytes = vec![0; length as usize];
    let mut memory = GuestMemory::Unshared(&mut bytes);
    for (index, (_, sub)) in descriptors.iter().enumerate() {
        let mut sub = sub.clone();
        // Map by index, not userdata: guests may give several subscriptions
        // identical userdata, including subscriptions to different descriptors.
        sub.userdata = index as u64;
        memory.write(GuestPtr::<types::Subscription>::new(0).add(index as u32)?, sub)?;
    }
    ctx.set_hostcall_fuel(fuel);
    let count = wasmtime_wasi::runtime::in_tokio(ctx.poll_oneoff(&mut memory, GuestPtr::new(0), GuestPtr::new(output), count))?;
    let mut ready = Vec::new();
    for pointer in GuestPtr::<types::Event>::new(output).as_array(count).iter() {
        let mut event = memory.read(pointer?)?;
        let (index, sub) = descriptors.get(event.userdata as usize).ok_or(types::Errno::Io)?;
        event.userdata = sub.userdata;
        ready.push((*index, event));
    }
    Ok(ready)
}
