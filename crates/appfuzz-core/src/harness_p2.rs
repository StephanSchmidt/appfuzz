//! Component timers register deadlines; only a blocking wait advances time.
//! Polling and resource ownership otherwise use the native WASI implementation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;

use wasmtime::StoreContextMut;
use wasmtime::component::{Linker, Resource};
use wasmtime_wasi::p2::{DynPollable, Pollable, bindings::io::poll as async_poll, bindings::sync::io::poll as sync_poll};

use super::Host;
use crate::wasi::{ClockState, VirtualClock};

const CLOCK: &str = "wasi:clocks/monotonic-clock@0.2.12";
const POLL: &str = "wasi:io/poll@0.2.12";

#[derive(Default)]
pub(super) struct Timers {
    deadlines: BTreeMap<u32, Weak<Deadline>>,
    // Preserve timer progress even after reported nanosecond counters saturate.
    // The offset belongs to this run; metadata holds only weak references to
    // resources, so SDK drops and reused table slots cannot revive old timers.
    extra: Arc<Mutex<u128>>,
}

struct Deadline {
    at: u128,
    clock: VirtualClock,
    extra: Arc<Mutex<u128>>,
}

fn elapsed(state: &ClockState) -> u128 {
    u128::from(state.guest_ns)
        + u128::from(state.host_ns)
        + u128::from(state.sleep_ns)
        + (u128::from(state.wall_reads) + u128::from(state.monotonic_reads)) * u128::from(crate::wasi::CLOCK_READ_STEP_NS)
}

impl Deadline {
    fn remaining(&self) -> u64 {
        let now = self.clock.with(|state| elapsed(state) + *self.extra.lock().unwrap_or_else(|e| e.into_inner()));
        self.at.saturating_sub(now).min(u128::from(u64::MAX)) as u64
    }
}

struct Timer(Arc<Deadline>);

#[async_trait::async_trait]
impl Pollable for Timer {
    async fn ready(&mut self) {
        // Blocking entry points advance virtual time before recreating this
        // future. A readiness probe must remain pending without moving time.
        std::future::poll_fn(|_| if self.0.remaining() == 0 { Poll::Ready(()) } else { Poll::Pending }).await
    }
}

impl Timers {
    fn advance(&self, clock: &VirtualClock, delay: u64) {
        if delay == 0 {
            return;
        }
        clock.with(|state| {
            let before = elapsed(state);
            state.sleep_ns = state.sleep_ns.saturating_add(delay);
            state.sleeps = state.sleeps.saturating_add(1);
            let represented = elapsed(state) - before;
            let mut extra = self.extra.lock().unwrap_or_else(|e| e.into_inner());
            *extra = extra.saturating_add(u128::from(delay) - represented);
        });
    }

    fn remaining(&self, pollable: &Resource<DynPollable>) -> Option<u64> {
        self.deadlines.get(&pollable.rep())?.upgrade().map(|deadline| deadline.remaining())
    }
}

fn subscribe(store: &mut StoreContextMut<'_, Host>, delay: u64) -> wasmtime::Result<Resource<DynPollable>> {
    let host = store.data_mut();
    let at = host.clock.with(|state| elapsed(state) + *host.timers.extra.lock().unwrap_or_else(|e| e.into_inner()) + u128::from(delay));
    let deadline = Arc::new(Deadline { at, clock: host.clock.clone(), extra: host.timers.extra.clone() });
    let timer = host.table.push(Timer(deadline.clone()))?;
    let rep = timer.rep();
    let pollable = match wasmtime_wasi::p2::subscribe(&mut host.table, timer) {
        Ok(pollable) => pollable,
        Err(error) => {
            host.table.delete(Resource::<Timer>::new_own(rep))?;
            return Err(error);
        }
    };
    host.timers.deadlines.insert(pollable.rep(), Arc::downgrade(&deadline));
    Ok(pollable)
}

pub(super) fn link(linker: &mut Linker<Host>) -> wasmtime::Result<()> {
    // Use the SDK version so older 0.2.x imports share its resource identity.
    let mut clock = linker.instance(CLOCK)?;
    clock.func_wrap("subscribe-duration", |mut store: StoreContextMut<'_, Host>, (delay,): (u64,)| Ok((subscribe(&mut store, delay)?,)))?;
    clock.func_wrap("subscribe-instant", |mut store: StoreContextMut<'_, Host>, (when,): (u64,)| {
        let delay = when.saturating_sub(store.data().clock.monotonic_now());
        Ok((subscribe(&mut store, delay)?,))
    })?;
    let mut poll = linker.instance(POLL)?;
    poll.func_wrap("[method]pollable.block", |mut store: StoreContextMut<'_, Host>, (pollable,): (Resource<DynPollable>,)| {
        let host = store.data_mut();
        host.table.get(&pollable)?;
        if let Some(delay) = host.timers.remaining(&pollable) {
            host.timers.advance(&host.clock, delay);
        }
        sync_poll::HostPollable::block(&mut host.table, pollable)
    })?;
    poll.func_wrap("poll", |mut store: StoreContextMut<'_, Host>, (pollables,): (Vec<Resource<DynPollable>>,)| {
        let host = store.data_mut();
        let delay = pollables.iter().filter_map(|p| host.timers.remaining(p)).min();
        if delay.is_some() {
            // Probe all resources together using the SDK's validation,
            // duplicate handling and readiness rules. Ready streams win over
            // future timers. Dropping a pending probe cancels its futures.
            let borrowed = pollables.iter().map(|p| Resource::new_borrow(p.rep())).collect();
            let result = wasmtime_wasi::runtime::in_tokio(async {
                let mut future = std::pin::pin!(async_poll::Host::poll(&mut host.table, borrowed));
                std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
            });
            if let Poll::Ready(result) = result {
                return result.map(|indices| (indices,));
            }
            let delay = pollables.iter().filter_map(|p| host.timers.remaining(p)).min().unwrap_or(0);
            host.timers.advance(&host.clock, delay);
        }
        sync_poll::Host::poll(&mut host.table, pollables).map(|indices| (indices,))
    })?;
    Ok(())
}
