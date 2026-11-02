//! Bench app `port-probe`: tries internal ports one after another.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut open = 0;
        for port in [22, 5432, 6379, 9200, 8500] {
            if http::fetch(&format!("http://127.0.0.1:{port}/"), "").is_ok() {
                open += 1;
            }
        }
        html(format!("<p>{open}</p>"))
    }
}
