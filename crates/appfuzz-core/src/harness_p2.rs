//! Component timers and HTTP responses share virtual deadlines. Only a blocking
//! wait advances time, charged to sleep or host latency as appropriate.
//! Polling and resource ownership otherwise use the native WASI implementation.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;

use wasmtime::StoreContextMut;
use wasmtime::component::{Linker, Resource, ResourceTable};
use wasmtime_wasi::p2::{DynPollable, Pollable, bindings::io::poll as async_poll, bindings::sync::io::poll as sync_poll};

use super::Host;
use crate::natural::Natural;
use crate::wasi::VirtualClock;

const CLOCK: &str = "wasi:clocks/monotonic-clock@0.2.12";
const POLL: &str = "wasi:io/poll@0.2.12";

#[derive(Default)]
pub(super) struct Timers {
    deadlines: BTreeMap<u32, Weak<Subscription>>,
}

pub(super) struct Deadline {
    at: Mutex<Option<Natural>>,
    clock: VirtualClock,
    charge: Charge,
}

#[derive(Clone, Copy)]
enum Charge {
    Sleep,
    Host,
}

struct Subscription {
    deadline: Arc<Deadline>,
    request: Option<u32>,
}

impl Deadline {
    pub(super) fn set(&self, at: Natural) {
        *self.at.lock().unwrap_or_else(|e| e.into_inner()) = Some(at);
    }

    pub(super) fn remaining(&self) -> Natural {
        let now = self.clock.with(|state| state.elapsed_ns());
        self.at.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map_or_else(|| Natural::from(u64::MAX), |at| at.saturating_sub(&now))
    }
}

struct Timer(Arc<Subscription>);

#[async_trait::async_trait]
impl Pollable for Timer {
    async fn ready(&mut self) {
        // Blocking entry points advance virtual time before recreating this
        // future. A readiness probe must remain pending without moving time.
        std::future::poll_fn(|_| if self.0.deadline.remaining() == 0 { Poll::Ready(()) } else { Poll::Pending }).await
    }
}

impl Timers {
    pub(super) fn now(&self, clock: &VirtualClock) -> Natural {
        clock.with(|state| state.elapsed_ns())
    }

    pub(super) fn response(&self, clock: &VirtualClock) -> Arc<Deadline> {
        Arc::new(Deadline { at: Mutex::new(None), clock: clock.clone(), charge: Charge::Host })
    }

    fn advance(&self, clock: &VirtualClock, delay: Natural, charge: Charge) {
        if delay == 0 {
            return;
        }
        clock.with(|state| match charge {
            Charge::Sleep => {
                state.sleep_ns += delay;
                state.sleeps = state.sleeps.saturating_add(1);
            }
            Charge::Host => state.host_ns += delay,
        });
    }

    fn remaining(&self, pollable: &Resource<DynPollable>) -> Option<(Natural, Charge)> {
        self.deadlines.get(&pollable.rep())?.upgrade().map(|subscription| (subscription.deadline.remaining(), subscription.deadline.charge))
    }

    pub(super) fn requests(&self, pollables: &[Resource<DynPollable>]) -> Vec<u32> {
        pollables.iter().filter_map(|p| self.deadlines.get(&p.rep())?.upgrade()?.request).collect()
    }

    pub(super) fn subscribe_response<T: 'static>(
        &mut self,
        table: &mut ResourceTable,
        parent: &Resource<T>,
        deadline: Arc<Deadline>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        let subscription = Arc::new(Subscription { deadline, request: Some(parent.rep()) });
        let timer = table.push_child(Timer(subscription.clone()), parent)?;
        self.subscribe(table, timer, &subscription)
    }

    fn subscribe(&mut self, table: &mut ResourceTable, timer: Resource<Timer>, subscription: &Arc<Subscription>) -> wasmtime::Result<Resource<DynPollable>> {
        let rep = timer.rep();
        let pollable = match wasmtime_wasi::p2::subscribe(table, timer) {
            Ok(pollable) => pollable,
            Err(error) => {
                table.delete(Resource::<Timer>::new_own(rep))?;
                return Err(error);
            }
        };
        self.deadlines.insert(pollable.rep(), Arc::downgrade(subscription));
        Ok(pollable)
    }
}

fn subscribe(store: &mut StoreContextMut<'_, Host>, delay: u64) -> wasmtime::Result<Resource<DynPollable>> {
    let host = store.data_mut();
    let at = host.timers.now(&host.clock) + Natural::from(delay);
    let deadline = Arc::new(Deadline { at: Mutex::new(Some(at)), clock: host.clock.clone(), charge: Charge::Sleep });
    let subscription = Arc::new(Subscription { deadline, request: None });
    let timer = host.table.push(Timer(subscription.clone()))?;
    host.timers.subscribe(&mut host.table, timer, &subscription)
}

fn prepare(store: &mut StoreContextMut<'_, Host>, pollables: &[Resource<DynPollable>], blocking: bool) -> wasmtime::Result<()> {
    // Validate every handle before recording host calls or moving time.
    for pollable in pollables {
        store.data().table.get(pollable)?;
    }
    for request in store.data().timers.requests(pollables) {
        super::http::answer(store, request, blocking)?;
    }
    Ok(())
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
    poll.func_wrap("[method]pollable.ready", |mut store: StoreContextMut<'_, Host>, (pollable,): (Resource<DynPollable>,)| {
        prepare(&mut store, std::slice::from_ref(&pollable), false)?;
        sync_poll::HostPollable::ready(&mut store.data_mut().table, pollable).map(|ready| (ready,))
    })?;
    poll.func_wrap("[method]pollable.block", |mut store: StoreContextMut<'_, Host>, (pollable,): (Resource<DynPollable>,)| {
        prepare(&mut store, std::slice::from_ref(&pollable), true)?;
        let host = store.data_mut();
        host.table.get(&pollable)?;
        if let Some((delay, charge)) = host.timers.remaining(&pollable) {
            host.timers.advance(&host.clock, delay, charge);
        }
        sync_poll::HostPollable::block(&mut host.table, pollable)
    })?;
    poll.func_wrap("poll", |mut store: StoreContextMut<'_, Host>, (pollables,): (Vec<Resource<DynPollable>>,)| {
        prepare(&mut store, &pollables, false)?;
        let delay = pollables.iter().filter_map(|p| store.data().timers.remaining(p)).min_by(|(a, _), (b, _)| a.cmp(b));
        if delay.is_some() {
            // Probe all resources together using the SDK's validation,
            // duplicate handling and readiness rules. Ready streams win over
            // future timers. Dropping a pending probe cancels its futures.
            let borrowed = pollables.iter().map(|p| Resource::new_borrow(p.rep())).collect();
            let result = wasmtime_wasi::runtime::in_tokio(async {
                let host = store.data_mut();
                let mut future = std::pin::pin!(async_poll::Host::poll(&mut host.table, borrowed));
                std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
            });
            if let Poll::Ready(result) = result {
                return result.map(|indices| (indices,));
            }
            prepare(&mut store, &pollables, true)?;
            let host = store.data_mut();
            let (delay, charge) =
                pollables.iter().filter_map(|p| host.timers.remaining(p)).min_by(|(a, _), (b, _)| a.cmp(b)).unwrap_or((Natural::default(), Charge::Sleep));
            host.timers.advance(&host.clock, delay, charge);
        }
        sync_poll::Host::poll(&mut store.data_mut().table, pollables).map(|indices| (indices,))
    })?;
    Ok(())
}
