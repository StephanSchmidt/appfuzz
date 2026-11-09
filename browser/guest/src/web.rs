//! `globalThis.__native`: the Web APIs the shim takes from Rust, where a
//! browser's behaviour is a parser appfuzz-core already uses: URLs by the
//! WHATWG rules (the `url` crate, which judges where requests go), so a
//! page's own checks (`new URL(next).host === location.host`) parse as in
//! a browser.

use rquickjs::convert::List;
use rquickjs::function::Constructor;
use rquickjs::{ArrayBuffer, Ctx, Function, Object, Result, Value, qjs};
use std::ffi::CString;
use url::{Url, form_urlencoded, quirks};

pub fn install(ctx: &Ctx<'_>) -> Result<()> {
    // QuickJS's base64 initializer only adds DOMException in the runtime's
    // first context. The browser realm needs its own constructor/prototype
    // even when a private parser context already registered the native class.
    if ctx.globals().get::<_, Value>("DOMException")?.is_undefined() {
        // SAFETY: ctx is live and locked; this intrinsic initializer owns its
        // allocations and supports an already-registered runtime class.
        if unsafe { qjs::JS_AddIntrinsicDOMException(ctx.as_raw().as_ptr()) } < 0 {
            return Err(rquickjs::Error::Exception);
        }
    }
    let n = Object::new(ctx.clone())?;
    n.set("url", Function::new(ctx.clone(), url_parse_js)?)?;
    n.set(
        "cspAllowsBase",
        Function::new(ctx.clone(), |policy: String, candidate: String, document: String| crate::csp::allows_base(&policy, &candidate, &document))?,
    )?;
    n.set(
        "cspCheck",
        Function::new(ctx.clone(), |policy: String, kind: String, candidate: String, origin: String, nonce: String, source: String, parser: bool| {
            crate::csp::check(&policy, &kind, &candidate, &origin, &nonce, &source, parser)
        })?,
    )?;
    n.set(
        "cspIntegrity",
        Function::new(ctx.clone(), |bytes: ArrayBuffer<'_>, metadata: String| {
            // SAFETY: the rooted buffer is borrowed only while Rust hashes it;
            // policy evaluation never calls back into JavaScript.
            unsafe { bytes.as_bytes() }.is_some_and(|bytes| crate::csp::integrity_matches(&metadata, bytes))
        })?,
    )?;
    n.set(
        "setStringCompilationHook",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, hook: Function<'_>| {
            // SAFETY: this context is locked and live. QuickJS duplicates the
            // callback and traces/releases it with its owning context.
            unsafe { qjs::JS_SetStringCompilationHook(ctx.as_raw().as_ptr(), hook.as_value().as_raw()) };
        })?,
    )?;
    n.set("compileClassicScript", Function::new(ctx.clone(), compile_classic_script)?)?;
    n.set("urlSet", Function::new(ctx.clone(), url_set_js)?)?;
    n.set("formParse", Function::new(ctx.clone(), form_parse_js)?)?;
    n.set("formSerialize", Function::new(ctx.clone(), form_serialize)?)?;
    n.set("cookieDomainMatches", Function::new(ctx.clone(), cookie_domain_matches)?)?;
    n.set("cookiePublicSuffix", Function::new(ctx.clone(), cookie_public_suffix)?)?;
    n.set("cookieSite", Function::new(ctx.clone(), cookie_site)?)?;
    n.set("bidiDirection", Function::new(ctx.clone(), bidi_direction)?)?;
    n.set("cssComponents", Function::new(ctx.clone(), css_components_js)?)?;
    n.set("queueMicrotask", Function::new(ctx.clone(), |callback: Function<'_>| callback.defer(()))?)?;
    n.set("inputColor", Function::new(ctx.clone(), input_color)?)?;
    n.set("encodeUtf8", Function::new(ctx.clone(), encode_utf8)?)?;
    n.set("decodeUtf8", Function::new(ctx.clone(), decode_utf8)?)?;
    n.set("decodeFileText", Function::new(ctx.clone(), decode_file_text)?)?;
    n.set("xmlTree", Function::new(ctx.clone(), xml_tree_js)?)?;
    n.set("decodeXHRText", Function::new(ctx.clone(), decode_xhr_text)?)?;
    n.set("encodeBase64", Function::new(ctx.clone(), encode_base64)?)?;
    // The pinned runtime has native DOMException slots but its Error.isError
    // predicate does not recognize them. Read the engine brand without invoking
    // page prototype getters or allocating/catching an exception per query.
    let constructor: Constructor = ctx.globals().get("DOMException")?;
    let sample: Object = constructor.construct(())?;
    let exception_class = class_id(sample.as_value());
    n.set("isDOMException", Function::new(ctx.clone(), move |value: Value<'_>| class_id(&value) == exception_class)?)?;
    install_clone_kinds(ctx, &n)?;
    ctx.globals().set("__native", n)
}

// Engine-owned function data keeps the compiled script visible to QuickJS's
// collector; no Rust closure captures a JavaScript value or context cycle.
unsafe extern "C" fn execute_classic_script(
    ctx: *mut qjs::JSContext,
    _this: qjs::JSValue,
    _argc: std::ffi::c_int,
    _argv: *mut qjs::JSValue,
    _magic: std::ffi::c_int,
    data: *mut qjs::JSValue,
) -> qjs::JSValue {
    // SAFETY: only compile_classic_script creates this callback. Its single
    // data value is rooted bytecode; EvalFunction consumes the duplicate.
    unsafe { qjs::JS_EvalFunction(ctx, qjs::JS_DupValue(ctx, *data)) }
}
pub(crate) fn compile_classic_script<'js>(ctx: Ctx<'js>, code: rquickjs::String<'js>, filename: String) -> Result<Function<'js>> {
    let filename = CString::new(filename).map_err(|_| rquickjs::Error::new_from_js_message("string", "filename", "NUL in script filename"))?;
    let mut length: usize = 0;
    // SAFETY: code is a rooted engine string. This follows JS_EvalObject's
    // exact conversion, retaining embedded NULs and lone UTF-16 surrogates.
    let bytes = unsafe { qjs::JS_ToCStringLen(ctx.as_raw().as_ptr(), &mut length, code.as_value().as_raw()) };
    if bytes.is_null() {
        return Err(rquickjs::Error::Exception);
    }
    // SAFETY: the engine owns a terminated buffer of length bytes and the
    // context is locked/live. The returned compiled value is immediately rooted.
    let compiled = unsafe {
        let value = qjs::JS_Eval(
            ctx.as_raw().as_ptr(),
            bytes,
            length as qjs::size_t,
            filename.as_ptr(),
            (qjs::JS_EVAL_TYPE_GLOBAL | qjs::JS_EVAL_FLAG_COMPILE_ONLY) as i32,
        );
        qjs::JS_FreeCString(ctx.as_raw().as_ptr(), bytes);
        Value::from_raw(ctx.clone(), value)
    };
    if compiled.is_exception() {
        return Err(rquickjs::Error::Exception);
    }
    let mut data = [compiled.as_raw()];
    // SAFETY: QuickJS duplicates the rooted bytecode into function data and
    // owns its trace/finalization. The callback has the exact JSCFunctionData ABI.
    let result =
        unsafe { Value::from_raw(ctx.clone(), qjs::JS_NewCFunctionData(ctx.as_raw().as_ptr(), Some(execute_classic_script), 0, 0, 1, data.as_mut_ptr())) };
    if result.is_exception() {
        return Err(rquickjs::Error::Exception);
    }
    Function::from_value(result)
}

// Bytes stay native; no page TextEncoder/Decoder, constructors or index
// setters run while Blob methods encode or decode their private buffers.
fn encode_utf8(ctx: Ctx<'_>, value: String) -> Result<ArrayBuffer<'_>> {
    ArrayBuffer::new_copy(ctx, value.as_bytes())
}

fn decode_utf8(value: ArrayBuffer<'_>, strip_bom: bool) -> String {
    // SAFETY: the rooted buffer is only borrowed while Rust inspects it. No
    // JavaScript runs before the decoded string owns all its data.
    let bytes = unsafe { value.as_bytes() }.unwrap_or_default();
    let bytes = if strip_bom { bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes) } else { bytes };
    String::from_utf8_lossy(bytes).into_owned()
}

// File API text packaging chooses the explicit label, then the Blob MIME
// charset, then UTF-8. Encoding Standard BOM sniffing overrides that fallback.
fn decode_file_text(value: ArrayBuffer<'_>, label: Option<String>, charset: Option<String>) -> String {
    // SAFETY: the rooted buffer is only borrowed during native decoding; no
    // JavaScript runs before the result owns its complete string data.
    let bytes = unsafe { value.as_bytes() }.unwrap_or_default();
    let encoding = label
        .as_deref()
        .and_then(|s| encoding_rs::Encoding::for_label(s.as_bytes()))
        .or_else(|| charset.as_deref().and_then(|s| encoding_rs::Encoding::for_label(s.as_bytes())))
        .unwrap_or(encoding_rs::UTF_8);
    encoding.decode(bytes).0.into_owned()
}

fn css_components_js<'js>(ctx: Ctx<'js>, value: String) -> Result<Value<'js>> {
    private_json(&ctx, crate::css_components::components(&value))
}

use crate::xml::xml_tree;
fn xml_tree_js<'js>(ctx: Ctx<'js>, value: String) -> Result<Value<'js>> {
    private_json(&ctx, xml_tree(&value).unwrap_or(serde_json::Value::Null))
}

fn decode_xhr_text<'js>(ctx: Ctx<'js>, value: ArrayBuffer<'js>, label: Option<String>, xml: bool, strict: bool) -> Result<Value<'js>> {
    // SAFETY: the rooted buffer is borrowed without executing JavaScript.
    let bytes = unsafe { value.as_bytes() }.unwrap_or_default();
    private_json(&ctx, crate::xml::decode(bytes, label.as_deref(), xml, strict))
}

fn encode_base64(value: ArrayBuffer<'_>) -> String {
    // SAFETY: no JavaScript runs while Rust borrows the rooted buffer. The
    // returned ASCII string owns its data before returning to the engine.
    let bytes = unsafe { value.as_bytes() }.unwrap_or_default();
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(a >> 2)] as char);
        output.push(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))] as char);
        output.push(if chunk.len() > 1 { ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))] as char } else { '=' });
        output.push(if chunk.len() > 2 { ALPHABET[usize::from(c & 63)] as char } else { '=' });
    }
    output
}

// Native brands distinguish internal data from prototype lookalikes and
// proxies without executing page getters, iterators or proxy traps.
fn install_clone_kinds<'js>(ctx: &Ctx<'js>, native: &Object<'js>) -> Result<()> {
    let mut kinds = Vec::new();
    for name in [
        "Object",
        "Array",
        "Date",
        "RegExp",
        "Map",
        "Set",
        "Number",
        "Boolean",
        "String",
        "ArrayBuffer",
        "SharedArrayBuffer",
        "Error",
        "DOMException",
        "Uint8Array",
        "Uint8ClampedArray",
        "Int8Array",
        "Int16Array",
        "Uint16Array",
        "Int32Array",
        "Uint32Array",
        "BigInt64Array",
        "BigUint64Array",
        "Float16Array",
        "Float32Array",
        "Float64Array",
    ] {
        let Some(constructor) = ctx.globals().get::<_, Option<Constructor>>(name)? else { continue };
        let value: Object = if name == "Date" || name.ends_with("Array") && name != "Array" || name.ends_with("ArrayBuffer") {
            constructor.construct((0,))?
        } else {
            constructor.construct(())?
        };
        kinds.push((class_id(value.as_value()), name));
    }
    let bigint: Value = ctx.eval("Object(0n)")?;
    kinds.push((class_id(&bigint), "BigInt"));
    let view: Value = ctx.eval("new DataView(new ArrayBuffer(0))")?;
    kinds.push((class_id(&view), "DataView"));
    let error_class = kinds.iter().find(|(_, name)| *name == "Error").unwrap().0;
    native.set(
        "allocateError",
        Function::new(ctx.clone(), move |ctx: Ctx<'js>, prototype: Object<'js>| {
            // SAFETY: both values are rooted in this context. This public allocator
            // initializes native Error data without constructing a new backtrace
            // or invoking author Error.prepareStackTrace/function-name getters.
            let value = unsafe { qjs::JS_NewObjectProtoClass(ctx.as_raw().as_ptr(), prototype.as_value().as_raw(), error_class) };
            // SAFETY: the allocator returns an owned value belonging to ctx.
            let value = unsafe { Value::from_raw(ctx, value) };
            if value.is_exception() { Err(rquickjs::Error::Exception) } else { Ok(value) }
        })?,
    )?;
    native.set(
        "cloneKind",
        Function::new(ctx.clone(), move |value: Value<'_>| {
            let id = class_id(&value);
            kinds.iter().find(|(kind, _)| *kind == id).map_or("unsupported", |(_, name)| *name)
        })?,
    )
}

fn class_id(value: &Value<'_>) -> qjs::JSClassID {
    // SAFETY: the rooted value stays alive for this call. This public QuickJS
    // operation reads the class tag only and does not execute JavaScript.
    unsafe { qjs::JS_GetClassID(value.as_raw()) }
}

// The native JSON parser defines own data properties. rquickjs's ordinary
// Vec/List conversion uses assignment and can invoke page prototype setters.
pub(crate) fn private_json<'js>(ctx: &Ctx<'js>, value: serde_json::Value) -> Result<Value<'js>> {
    ctx.json_parse(value.to_string())
}

fn url_parse_js<'js>(ctx: Ctx<'js>, input: String, base: Option<String>) -> Result<Value<'js>> {
    private_json(&ctx, serde_json::json!(url_parse(input, base)))
}

fn url_set_js<'js>(ctx: Ctx<'js>, href: String, key: String, value: String) -> Result<Value<'js>> {
    private_json(&ctx, serde_json::json!(url_set(href, key, value)))
}

fn form_parse_js<'js>(ctx: Ctx<'js>, input: String) -> Result<Value<'js>> {
    let pairs: Vec<_> = form_parse(input).into_iter().map(|List(pair)| pair).collect();
    private_json(&ctx, serde_json::json!(pairs))
}

fn bidi_direction(value: String) -> Option<&'static str> {
    use unicode_bidi::BidiClass;
    value.chars().find_map(|c| match unicode_bidi::bidi_class(c) {
        BidiClass::L => Some("ltr"),
        BidiClass::R | BidiClass::AL => Some("rtl"),
        _ => None,
    })
}

fn ip_address(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok()
}

fn cookie_domain_matches(host: String, domain: String) -> bool {
    host == domain || (!ip_address(&host) && host.strip_suffix(&domain).is_some_and(|prefix| prefix.ends_with('.')))
}

fn cookie_public_suffix(host: String) -> bool {
    !ip_address(&host) && psl::suffix_str(&host) == Some(host.as_str())
}

fn cookie_site(href: String) -> Option<String> {
    let url = Url::parse(&href).ok()?;
    let host = quirks::hostname(&url);
    let domain = if ip_address(host) { host } else { psl::domain_str(host).unwrap_or(host) };
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        scheme => scheme,
    };
    Some(format!("{scheme}://{domain}"))
}

/// A URL's parts as `URL` shows them: href, origin, protocol, username,
/// password, host, hostname, port, pathname, search, hash.
fn parts(u: &Url) -> Vec<String> {
    let origin = quirks::origin(u);
    [
        quirks::href(u),
        &origin,
        quirks::protocol(u),
        quirks::username(u),
        quirks::password(u),
        quirks::host(u),
        quirks::hostname(u),
        quirks::port(u),
        quirks::pathname(u),
        quirks::search(u),
        quirks::hash(u),
    ]
    .map(str::to_string)
    .to_vec()
}

/// `new URL(input, base)`: the parts, or nothing when either doesn't parse.
fn url_parse(input: String, base: Option<String>) -> Option<Vec<String>> {
    let base = match base {
        Some(b) => Some(Url::parse(&b).ok()?),
        None => None,
    };
    Url::options().base_url(base.as_ref()).parse(&input).ok().map(|u| parts(&u))
}

/// A `URL` setter on `href`: the new parts. A value a setter refuses
/// leaves the URL as it was; only an `href` that doesn't parse is nothing
/// (the setter throws).
fn url_set(href: String, key: String, value: String) -> Option<Vec<String>> {
    let mut u = Url::parse(&href).ok()?;
    let v = value.as_str();
    match key.as_str() {
        "href" => quirks::set_href(&mut u, v).ok()?,
        "protocol" => quirks::set_protocol(&mut u, v).unwrap_or(()),
        "username" => quirks::set_username(&mut u, v).unwrap_or(()),
        "password" => quirks::set_password(&mut u, v).unwrap_or(()),
        "host" => quirks::set_host(&mut u, v).unwrap_or(()),
        "hostname" => quirks::set_hostname(&mut u, v).unwrap_or(()),
        "port" => quirks::set_port(&mut u, v).unwrap_or(()),
        "pathname" => quirks::set_pathname(&mut u, v),
        "search" => quirks::set_search(&mut u, v),
        "hash" => quirks::set_hash(&mut u, v),
        _ => {}
    }
    Some(parts(&u))
}

/// `application/x-www-form-urlencoded` text as name-value pairs.
fn form_parse(s: String) -> Vec<List<(String, String)>> {
    form_urlencoded::parse(s.as_bytes()).map(|(k, v)| List((k.into_owned(), v.into_owned()))).collect()
}

fn form_serialize(pairs: Vec<List<(String, String)>>) -> String {
    form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs.iter().map(|List((k, v))| (k, v))).finish()
}

fn input_color<'js>(ctx: Ctx<'js>, value: String, alpha: bool, p3: bool) -> Result<Value<'js>> {
    let (value, unsupported) = crate::input_color::sanitize(&value, alpha, p3);
    private_json(&ctx, serde_json::json!({"value":value,"unsupported":unsupported}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_intrinsics_are_installed_after_another_context_exists() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let parser = rquickjs::Context::full(&runtime).unwrap();
        let page = rquickjs::Context::full(&runtime).unwrap();
        parser.with(|ctx| {
            ctx.eval::<(), _>("DOMException.prototype.parserOnly = true").unwrap();
        });
        page.with(|ctx| {
            install(&ctx).unwrap();
            let value: String = ctx
                .eval("const e=new DOMException('message','SecurityError');[e.name,e.message,e.code,e instanceof Error,e.parserOnly===undefined].join(' ')")
                .unwrap();
            assert_eq!(value, "SecurityError message 18 true true");
        });
    }

    fn host(input: &str) -> Option<String> {
        url_parse(input.into(), Some("https://app.example/shop/item?x=1".into())).map(|p| p[6].clone())
    }

    #[test]
    fn native_microtasks_do_not_consult_page_promises() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let pending: i32 = ctx
                .eval(
                    r#"
                globalThis.done=0;globalThis.calls=0;
                Object.defineProperty(Promise.prototype,'constructor',{configurable:true,get(){calls++;throw Error('page Promise')}});
                globalThis.queueMicrotask=()=>{calls++;throw Error('page queue')};
                __native.queueMicrotask(()=>{done++});done
            "#,
                )
                .unwrap();
            assert_eq!(pending, 0);
        });
        assert!(runtime.execute_pending_job().unwrap());
        assert!(!runtime.execute_pending_job().unwrap());
        context.with(|ctx| {
            assert_eq!(ctx.eval::<String, _>("done+' '+calls").unwrap(), "1 0");
        });
    }

    #[test]
    fn css_component_records_ignore_array_and_record_setters() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String = ctx
                .eval(
                    r#"(()=>{
                let calls=0;
                for(const key of ['0','tokens','limited'])Object.defineProperty(Object.prototype,key,{configurable:true,set(){calls++}});
                try{const value=__native.cssComponents(':\\69 s(.a,[x)');return value.tokens[2][4]+' '+value.limited+' '+calls}
                finally{for(const key of ['0','tokens','limited'])delete Object.prototype[key]}
            })()"#,
                )
                .unwrap();
            assert_eq!(result, "is false 0");
        });
    }

    #[test]
    fn xhr_xml_validation_and_namespaces() {
        let value = xml_tree("<r xmlns='urn:r' xmlns:p='urn:p' p:id='A&amp;B'><p:c/>text<!--c--></r>").unwrap();
        assert_eq!(value[1][2], "r");
        assert_eq!(value[1][3], "urn:r");
        assert!(value[1][4].as_array().unwrap().contains(&serde_json::json!(["p:id", "urn:p", "A&B"])));
        assert!(value[1][4].as_array().unwrap().contains(&serde_json::json!(["xmlns:p", roxmltree::NS_XMLNS_URI, "urn:p"])));
        assert_eq!(value[2][2], "p:c");
        assert_eq!(value[2][3], "urn:p");
        for input in ["", "<r><x></r>", "<p:r/>", "<r a='1' a='2'/>", "<r>&missing;</r>"] {
            assert!(xml_tree(input).is_none(), "{input}");
        }
    }
    #[test]
    fn xhr_xml_internal_entities_and_external_subset() {
        let value = xml_tree("<!DOCTYPE r [<!ENTITY a 'synthetic'>]><r>&a;</r>").unwrap();
        assert!(value.as_array().unwrap().iter().any(|n| n[0] == "text" && n[2] == "synthetic"));
        assert!(xml_tree("<!DOCTYPE r SYSTEM 'https://synthetic.invalid/unused'><r/>").is_some());
        assert!(xml_tree("<!DOCTYPE r [<!ENTITY a SYSTEM 'https://synthetic.invalid/unused'>]><r>&a;</r>").is_none());
    }
    #[test]
    fn xhr_xml_native_records_ignore_array_setters() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {install(&ctx).unwrap();let result:String=ctx.eval(r#"(()=>{let calls=0;Object.defineProperty(Array.prototype,'0',{configurable:true,set(){calls++}});try{const tree=__native.xmlTree('<r><x/></r>');return tree[1][2]+' '+tree[2][2]+' '+calls}finally{delete Array.prototype[0]}})()"#).unwrap();assert_eq!(result,"r x 0");});
    }

    #[test]
    fn json_serialization_keeps_its_lists_private() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            let result: String = ctx.eval(r#"(()=>{
                const define=Object.defineProperty;let calls=0,text,list;
                const value={x:[{y:2}]},replacer=['x','y'];
                for(const key of ['0','1','2'])define(Array.prototype,key,{configurable:true,set(value){define(this,key,{value,writable:true,enumerable:true,configurable:true});calls++}});
                try{text=JSON.stringify(value);list=JSON.stringify(value,replacer)}finally{for(const key of ['0','1','2'])delete Array.prototype[key]}
                return text+' '+list+' '+calls;
            })()"#).unwrap();
            assert_eq!(result,r#"{"x":[{"y":2}]} {"x":[{"y":2}]} 0"#);
        });
    }

    #[test]
    fn json_serialization_keeps_public_inherited_values_and_callbacks() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            let result: String = ctx
                .eval(
                    r#"(()=>{
                const value=[];value.length=1;let text,reads=0;
                Object.defineProperty(Array.prototype,'0',{configurable:true,get(){reads++;return 'inherited'}});
                try{text=JSON.stringify(value)}finally{delete Array.prototype[0]}
                let getters=0,converts=0,replaces=0;
                const object={get x(){getters++;return {toJSON(){converts++;return 2}}}};
                const replaced=JSON.stringify(object,function(k,v){replaces++;return k==='x'?v+1:v});
                return text+' '+reads+' '+replaced+' '+getters+' '+converts+' '+replaces;
            })()"#,
                )
                .unwrap();
            assert_eq!(result, r#"["inherited"] 1 {"x":3} 1 1 2"#);
        });
    }

    #[test]
    fn allocating_deserialized_errors_does_not_construct_stack_traces() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String = ctx
                .eval(
                    r#"
                let calls=0;
                Error.prepareStackTrace=()=>{calls++;return 'page hook'};
                Error.stackTraceLimit={valueOf(){calls++;return 10}};
                const e=__native.allocateError(TypeError.prototype);
                JSON.stringify([calls,Error.isError(e),e instanceof TypeError,e.name,Reflect.ownKeys(e).length]);
            "#,
                )
                .unwrap();
            assert_eq!(result, r#"[0,true,true,"TypeError",0]"#);
        });
    }

    #[test]
    fn utf8_helpers_preserve_bytes_and_recover_invalid_sequences() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String = ctx.eval(r#"JSON.stringify([Array.from(new Uint8Array(__native.encodeUtf8('é🦀'))),__native.decodeUtf8(new Uint8Array([255,0,128]).buffer,true),__native.decodeUtf8(new Uint8Array([239,187,191,120]).buffer,true),__native.decodeUtf8(new Uint8Array([239,187,191,120]).buffer,false)])"#).unwrap();
            assert_eq!(result, "[[195,169,240,159,166,128],\"�\\u0000�\",\"x\",\"\u{feff}x\"]");
        });
    }

    #[test]
    fn file_text_decoding_respects_labels_mime_fallback_boms_and_invalid_sequences() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String = ctx
                .eval(
                    r#"JSON.stringify([
                __native.decodeFileText(new Uint8Array([233]).buffer,'latin1',null),
                __native.decodeFileText(new Uint8Array([233]).buffer,'invalid','windows-1252'),
                __native.decodeFileText(new Uint8Array([233]).buffer,'utf-8','windows-1252'),
                __native.decodeFileText(new Uint8Array([233]).buffer,null,null),
                __native.decodeFileText(new Uint8Array([255,254,65,0]).buffer,'windows-1252',null),
                __native.decodeFileText(new Uint8Array([254,255,0,65]).buffer,null,null),
                __native.decodeFileText(new Uint8Array([255,254,0]).buffer,null,null),
                __native.decodeFileText(new Uint8Array([130,160]).buffer,'shift_jis',null),
                __native.decodeFileText(new Uint8Array([128,255]).buffer,'x-user-defined',null),
                __native.decodeFileText(new Uint8Array([65,66]).buffer,'iso-2022-kr',null)
            ])"#,
                )
                .unwrap();
            assert_eq!(result, "[\"é\",\"é\",\"�\",\"�\",\"A\",\"A\",\"�\",\"あ\",\"\u{f780}\u{f7ff}\",\"�\"]");
        });
    }

    #[test]
    fn file_text_decoding_keeps_native_bytes_private_from_page_codecs_and_setters() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let calls: i32 = ctx.eval(r#"let calls=0;const buffer=new Uint8Array([233]).buffer;globalThis.TextDecoder=function(){calls++};Object.defineProperty(Array.prototype,'0',{configurable:true,set(){calls++}});globalThis.decoded=__native.decodeFileText(buffer,'windows-1252',null);calls"#).unwrap();
            assert_eq!(calls, 0);
            assert_eq!(ctx.eval::<String, _>("decoded").unwrap(), "é");
        });
    }

    #[test]
    fn base64_helper_preserves_binary_and_partial_groups() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String =
                ctx.eval(r#"JSON.stringify([[],[0],[255],[255,128],[255,128,0,64]].map(bytes=>__native.encodeBase64(new Uint8Array(bytes).buffer)))"#).unwrap();
            assert_eq!(result, r#"["","AA==","/w==","/4A=","/4AAQA=="]"#);
        });
    }

    #[test]
    fn utf8_helpers_do_not_invoke_page_codecs_or_inherited_setters() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let calls: i32 = ctx.eval(r#"let calls=0;const define=Object.defineProperty;globalThis.TextEncoder=globalThis.TextDecoder=function(){calls++};define(Array.prototype,'0',{configurable:true,set(value){define(this,'0',{value,writable:true,enumerable:true,configurable:true});calls++}});globalThis.decoded=__native.decodeUtf8(__native.encodeUtf8('é'),true);calls"#).unwrap();
            assert_eq!(calls, 0);
            assert_eq!(ctx.eval::<String, _>("decoded").unwrap(), "é");
        });
    }

    #[test]
    fn clone_kinds_use_internal_slots_without_prototypes_or_callbacks() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String = ctx.eval(r#"
                let calls=0;
                const fake=Object.create(Map.prototype);
                Object.defineProperty(fake,Symbol.toStringTag,{get(){calls++;throw Error('tag')}});
                const proxy=new Proxy(new Map(),{get(){calls++;throw Error('proxy')}});
                JSON.stringify([[{},[],new Date(0),/x/,new Map(),new Set(),Object(1),Object(false),Object('s'),Object(1n),new ArrayBuffer(0),new DataView(new ArrayBuffer(0)),new Uint16Array(0),new Error(),new DOMException(),fake,proxy,()=>{},Promise.resolve(),new WeakMap()].map(v=>__native.cloneKind(v)),calls]);
            "#).unwrap();
            assert_eq!(result, r#"[["Object","Array","Date","RegExp","Map","Set","Number","Boolean","String","BigInt","ArrayBuffer","DataView","Uint16Array","Error","DOMException","Object","unsupported","unsupported","unsupported","unsupported"],0]"#);
        });
    }

    #[test]
    fn exception_brand_uses_native_slots_without_page_callbacks() {
        let runtime = rquickjs::Runtime::new().unwrap();
        let context = rquickjs::Context::full(&runtime).unwrap();
        context.with(|ctx| {
            install(&ctx).unwrap();
            let result: String = ctx
                .eval(
                    r#"
                let calls=0;
                const fake=Object.create(DOMException.prototype);
                Object.defineProperty(fake,Symbol.toStringTag,{get(){calls++;throw Error('getter')}});
                const proxy=new Proxy(new DOMException(),{get(){calls++;throw Error('proxy')}});
                const values=[new DOMException(),new(class extends DOMException{})(),fake,proxy,new Error(),null,42,()=>{}];
                JSON.stringify([values.map(v=>__native.isDOMException(v)),calls]);
            "#,
                )
                .unwrap();
            assert_eq!(result, "[[true,true,false,false,false,false,false,false],0]");
        });
    }

    #[test]
    fn direction_uses_the_first_strong_unicode_character() {
        for (text, direction) in [("123", None), ("123 שלום", Some("rtl")), ("a שלום", Some("ltr")), ("𞤀", Some("rtl")), ("你好", Some("ltr"))] {
            assert_eq!(bidi_direction(text.into()), direction);
        }
    }

    #[test]
    fn cookie_scope_uses_native_public_suffix_and_ip_rules() {
        for host in ["github.io", "co.uk", "bar.ck"] {
            assert!(cookie_public_suffix(host.into()), "{host}");
        }
        for host in ["mine.github.io", "www.ck", "127.0.0.1", "[::1]"] {
            assert!(!cookie_public_suffix(host.into()), "{host}");
        }
        assert!(cookie_domain_matches("sub.app.example".into(), "app.example".into()));
        assert!(!cookie_domain_matches("evilapp.example".into(), "app.example".into()));
        assert!(!cookie_domain_matches("127.0.0.1".into(), "0.0.1".into()));
        for (url, site) in [
            ("https://a.example.co.uk/x", "https://example.co.uk"),
            ("https://mine.github.io/", "https://mine.github.io"),
            ("wss://sub.app.example/", "https://app.example"),
            ("http://[::1]/", "http://[::1]"),
        ] {
            assert_eq!(cookie_site(url.into()).as_deref(), Some(site));
        }
    }

    #[test]
    fn urls_parse_as_a_browser_parses_them() {
        // Lookalike and numeric hosts come out as a browser resolves them.
        assert_eq!(host("https://аpple.com").as_deref(), Some("xn--pple-43d.com"));
        assert_eq!(host("https://ＥＶＩＬ.example").as_deref(), Some("evil.example"));
        assert_eq!(host("http://0x7f.1/").as_deref(), Some("127.0.0.1"));
        assert_eq!(host("http://[::1]/").as_deref(), Some("[::1]"));
        assert_eq!(host("/\\evil.example").as_deref(), Some("evil.example"));
        assert_eq!(host("https://evil.example:0x50/"), None);
        let p = url_parse("../a b/%2e%2e/c?q=1 2#h".into(), Some("https://app.example/x/y/z".into())).unwrap();
        assert_eq!((p[0].as_str(), p[1].as_str()), ("https://app.example/x/c?q=1%202#h", "https://app.example"));
    }

    #[test]
    fn setters_keep_what_they_refuse() {
        let href = "https://app.example/a?b=1".to_string();
        assert_eq!(url_set(href.clone(), "pathname".into(), "x y".into()).unwrap()[0], "https://app.example/x%20y?b=1");
        assert_eq!(url_set(href.clone(), "port".into(), "x".into()).unwrap()[0], href);
        assert_eq!(url_set(href.clone(), "protocol".into(), "mailto".into()).unwrap()[0], href);
        assert!(url_set(href, "href".into(), "no scheme".into()).is_none());
    }

    #[test]
    fn forms_encode_as_a_browser_encodes_them() {
        let pairs = form_parse("a=1+2&b=%zz&c".into());
        let flat: Vec<(String, String)> = pairs.into_iter().map(|List(p)| p).collect();
        assert_eq!(flat, [("a".into(), "1 2".into()), ("b".into(), "%zz".into()), ("c".into(), String::new())]);
        assert_eq!(form_serialize(vec![List(("q".into(), "a b!&é".into()))]), "q=a+b%21%26%C3%A9");
    }
}
