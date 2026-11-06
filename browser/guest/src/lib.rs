//! A browser in a Wasm component: QuickJS runs a page's scripts against a
//! DOM shim, on virtual time. appfuzz's harness runs this guest, so fuel,
//! the virtual clock, records and shrinking work for pages as for apps.
//! What the page sends out (requests, navigations, markup and code it
//! builds) goes to the host as calls of the `appfuzz:browser` world.

pub mod driver;

#[cfg(target_arch = "wasm32")]
pub(crate) mod component {
    wit_bindgen::generate!({ world: "browser", path: "../wit" });

    pub(crate) use appfuzz::browser::{nav, net, sink};

    struct Browser;
    export!(Browser);

    impl exports::appfuzz::browser::page::Guest for Browser {
        fn session(input: String) -> String {
            crate::driver::session(&input)
        }
    }

    impl Guest for Browser {
        fn wizer_initialize() {
            crate::driver::initialize();
        }
    }
}
