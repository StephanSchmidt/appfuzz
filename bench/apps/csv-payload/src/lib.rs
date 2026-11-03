include!("../../../prelude.rs");
impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let Some(payload) = param(&req.query, "payload") else { return html("missing".into()); };
        let mut reader = csv::ReaderBuilder::new().from_reader(payload.as_bytes());
        let Ok(header) = reader.headers() else { return html("invalid".into()); };
        if header != &csv::StringRecord::from(vec!["item", "quantity"]) { return html("wrong header".into()); }
        let mut total = 0;
        for row in reader.records() {
            let Ok(row) = row else { return html("invalid".into()); };
            if let Some(quantity) = row.get(1).and_then(|v| v.parse::<u64>().ok()) {
                total += std::hint::black_box(120u64) / quantity;
            }
        }
        html(format!("<p>{total}</p>"))
    }
}
