//! CSS color-control values, alpha/colorSpace reflection and native state.
//! CSS grammar cases were checked in Firefox 158 and Chrome 157. Firefox's
//! named-color whitespace/escape handling follows CSS tokenization. Alpha
//! expectations use Chrome's experimental feature (Firefox lacks alpha).
//! P3 conversion expectations use Firefox/Linebender's CSS matrices. HTML
//! requires 8-bit rounding only in limited-sRGB, including alpha; Chrome's
//! experimental float-color and legacy-alpha exceptions are not copied.
//! Type transitions use Firefox's behavior, consistent with existing tests.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let script = format!("const CASE={};{};for(const line of lines)console.log(line)", json!(case), include_str!("fixtures/color_controls.js"));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn color_basic() {
    assert_eq!(
        visit("color-basic"),
        [
            "color-basic [\"\",\"#000000\"]",
            "color-basic [\"bad\",\"#000000\"]",
            "color-basic [\"#000000\",\"#000000\"]",
            "color-basic [\"#ABCDEF\",\"#abcdef\"]",
            "color-basic [\"#abc\",\"#aabbcc\"]",
            "color-basic [\"#abcd\",\"#aabbcc\"]",
            "color-basic [\"#12345678\",\"#123456\"]",
            "color-basic [\"red\",\"#ff0000\"]",
            "color-basic [\"rebeccapurple\",\"#663399\"]",
            "color-basic [\"transparent\",\"#000000\"]",
            "color-basic [\"rgb(255, 0, 0)\",\"#ff0000\"]",
            "color-basic [\"hsl(120 100% 50%)\",\"#00ff00\"]",
            "color-basic [\"hwb(120 0% 0%)\",\"#00ff00\"]",
            "color-basic [\"lab(50% 0 0)\",\"#777777\"]",
            "color-basic [\"lch(50 20 30)\",\"#976c67\"]",
            "color-basic [\"oklab(.7 .2 .1)\",\"#ff524c\"]",
            "color-basic [\"oklch(.7 .2 30)\",\"#ff614d\"]",
            "color-basic [\"color(display-p3 1 0 0)\",\"#ff0000\"]",
            "color-basic [\"color(srgb-linear .5 .5 .5)\",\"#bcbcbc\"]",
            "color-basic [\"color(xyz-d50 .2 .3 .4)\",\"#00a8bd\"]",
            "color-basic [\"color(a98-rgb .2 .3 .4)\",\"#1d4b67\"]",
            "color-basic [\"color(prophoto-rgb .2 .3 .4)\",\"#00647d\"]",
            "color-basic [\"color(rec2020 .2 .3 .4)\",\"#245e76\"]",
            "color-basic [\"currentcolor\",\"#000000\"]"
        ]
    );
}

#[test]
fn color_syntax() {
    assert_eq!(
        visit("color-syntax"),
        [
            "color-syntax [\" RED \",\"#ff0000\"]",
            "color-syntax [\"red\\n\",\"#ff0000\"]",
            "color-syntax [\" red \",\"#000000\"]",
            "color-syntax [\"/**/red/**/\",\"#ff0000\"]",
            "color-syntax [\"r\\\\65 d\",\"#ff0000\"]",
            "color-syntax [\"rgb(1/**/ 2 3)\",\"#010203\"]",
            "color-syntax [\"rgb(1 2 3 / .5)\",\"#010203\"]",
            "color-syntax [\"rgb(1, 2, 3, .5)\",\"#010203\"]",
            "color-syntax [\"rgba(1 2 3)\",\"#010203\"]",
            "color-syntax [\"rgb(1, 2%, 3)\",\"#000000\"]",
            "color-syntax [\"rgb(1% 2 3%)\",\"#030208\"]",
            "color-syntax [\"rgb(1 2,3)\",\"#000000\"]",
            "color-syntax [\"rgb(1,2,3 / .5)\",\"#000000\"]",
            "color-syntax [\"hsl(120 1 .5)\",\"#010101\"]",
            "color-syntax [\"hsl(120, 100%, 50%)\",\"#00ff00\"]",
            "color-syntax [\"hsl(.5turn 100% 50%)\",\"#00ffff\"]",
            "color-syntax [\"hsl(200grad 100% 50%)\",\"#00ffff\"]",
            "color-syntax [\"hsl(3.141592653589793rad 100% 50%)\",\"#00ffff\"]",
            "color-syntax [\"#12\",\"#000000\"]",
            "color-syntax [\"#12345\",\"#000000\"]",
            "color-syntax [\"123456\",\"#000000\"]",
            "color-syntax [\"#123456x\",\"#000000\"]",
            "color-syntax [\"red blue\",\"#000000\"]",
            "color-syntax [\"red;\",\"#000000\"]",
            "color-syntax [\"var(--x)\",\"#000000\"]",
            "color-syntax [\"color-mix(in srgb,red,blue)\",\"#800080\"]"
        ]
    );
}

#[test]
fn color_calc() {
    assert_eq!(
        visit("color-calc"),
        [
            "color-calc [\"rgb(calc(100 + 155) 0 0)\",\"#ff0000\"]",
            "color-calc [\"rgb(1 2 3 / calc(.5))\",\"#010203\"]",
            "color-calc [\"rgb(calc(100% / 2) 0% 0%)\",\"#800000\"]",
            "color-calc [\"hsl(calc(.25turn + 90deg) 100% 50%)\",\"#00ffff\"]",
            "color-calc [\"rgb(min(10, 20) 0 0)\",\"#0a0000\"]",
            "color-calc [\"rgb(max(10, 20) 0 0)\",\"#140000\"]",
            "color-calc [\"rgb(clamp(0, 200, 100) 0 0)\",\"#640000\"]",
            "color-calc [\"rgb(calc(2 * (30 + 10)) 0 0)\",\"#500000\"]",
            "color-calc [\"rgb(calc(10-2) 0 0)\",\"#000000\"]",
            "color-calc [\"rgb(calc(1px) 0 0)\",\"#000000\"]",
            "color-calc [\"rgb(calc(1 + 20%) 0 0)\",\"#000000\"]",
            "color-calc [\"rgb(calc(1 / 0) 0 0)\",\"#ff0000\"]",
            "color-calc [\"rgb(calc(0 / 0) 0 0)\",\"#000000\"]",
            "color-calc [\"rgb(calc(1e999) 0 0)\",\"#ff0000\"]"
        ]
    );
}

#[test]
fn color_rounding() {
    assert_eq!(
        visit("color-rounding"),
        [
            "color-rounding [\"rgb(.49 .5 1.5)\",\"#000102\"]",
            "color-rounding [\"rgb(1.49 1.5 2.5)\",\"#010203\"]",
            "color-rounding [\"rgb(-10 300 1e999)\",\"#00ffff\"]",
            "color-rounding [\"rgb(none none none)\",\"#000000\"]",
            "color-rounding [\"rgba(255,0,0,-1)\",\"#ff0000\"]",
            "color-rounding [\"rgba(255,0,0,2)\",\"#ff0000\"]",
            "color-rounding [\"hsl(1e999 100% 50%)\",\"#ff0000\"]",
            "color-rounding [\"color(srgb 1e999 0 0)\",\"#ff0000\"]",
            "color-rounding [\"color(display-p3 1.84 -.19 .72 / .6)\",\"#ff00b2\"]"
        ]
    );
}

#[test]
fn color_alpha() {
    assert_eq!(
        visit("color-alpha"),
        [
            "color-alpha [\"#12345678\",[\"srgb\",0.071,0.204,0.337,0.471]]",
            "color-alpha [\"rgba(255,0,0,.5)\",[\"srgb\",1,0,0,0.502]]",
            "color-alpha [\"transparent\",[\"srgb\",0,0,0,0]]",
            "color-alpha [\"#abcd\",[\"srgb\",0.667,0.733,0.8,0.867]]",
            "color-alpha [\"red\",[\"srgb\",1,0,0]]",
            "color-alpha [\"color(srgb .1 .2 .3 / .1)\",[\"srgb\",0.102,0.2,0.302,0.102]]"
        ]
    );
}

#[test]
fn color_p3() {
    assert_eq!(
        visit("color-p3"),
        [
            "color-p3 [\"#12345678\",[\"display-p3\",0.107,0.201,0.327]]",
            "color-p3 [\"rgba(255,0,0,.5)\",[\"display-p3\",0.917,0.2,0.139]]",
            "color-p3 [\"color(display-p3 1 0 0)\",[\"display-p3\",1,0,0]]",
            "color-p3 [\"color(display-p3 1.84 -.19 .72 / .6)\",[\"display-p3\",1.84,-0.19,0.72]]"
        ]
    );
}

#[test]
fn color_p3_alpha() {
    assert_eq!(
        visit("color-p3-alpha"),
        [
            "color-p3-alpha [\"#12345678\",[\"display-p3\",0.107,0.201,0.327,0.471]]",
            "color-p3-alpha [\"rgba(255,0,0,.5)\",[\"display-p3\",0.917,0.2,0.139,0.5]]",
            "color-p3-alpha [\"color(display-p3 1 0 0)\",[\"display-p3\",1,0,0]]",
            "color-p3-alpha [\"color(display-p3 1.84 -.19 .72 / .6)\",[\"display-p3\",1.84,-0.19,0.72,0.6]]"
        ]
    );
}

#[test]
fn color_dynamic() {
    assert_eq!(
        visit("color-dynamic"),
        [
            "color-dynamic [false,\"alpha\",\"\",[\"srgb\",0.071,0.204,0.337,0.471],\"#12345678\"]",
            "color-dynamic [false,\"colorspace\",\"display-p3\",[\"display-p3\",0.107,0.201,0.327,0.471],\"#12345678\"]",
            "color-dynamic [false,\"colorspace\",\"limited-srgb\",[\"srgb\",0.071,0.204,0.337,0.471],\"#12345678\"]",
            "color-dynamic [false,\"alpha\",null,\"#123456\",\"#12345678\"]",
            "color-dynamic [false,\"alpha\",\"\",[\"srgb\",0.071,0.204,0.337,0.471],\"#12345678\"]",
            "color-dynamic [true,\"alpha\",\"\",[\"srgb\",0.071,0.204,0.337,0.471],\"#12345678\"]",
            "color-dynamic [true,\"colorspace\",\"display-p3\",[\"display-p3\",0.107,0.201,0.327,0.471],\"#12345678\"]",
            "color-dynamic [true,\"colorspace\",\"limited-srgb\",[\"srgb\",0.071,0.204,0.337,0.471],\"#12345678\"]",
            "color-dynamic [true,\"alpha\",null,\"#123456\",\"#12345678\"]",
            "color-dynamic [true,\"alpha\",\"\",[\"srgb\",0.071,0.204,0.337],\"#12345678\"]"
        ]
    );
}

#[test]
fn color_reflection() {
    assert_eq!(
        visit("color-reflection"),
        [
            "color-reflection initial false limited-srgb",
            "color-reflection [true,\"display-p3\",\"\",\"DISPLAY-P3\",[\"display-p3\",0.917,0.2,0.139]]",
            "color-reflection [false,\"limited-srgb\",null,\"unknown\",\"#ff0000\"]"
        ]
    );
}

#[test]
fn color_parser_order() {
    assert_eq!(
        visit("color-parser-order"),
        [
            "color-parser-order <input type=color value=#ABC> \"#aabbcc\"",
            "color-parser-order <input value=#ABC type=color> \"#aabbcc\"",
            "color-parser-order <input type=color value=#12345678 alpha> [\"srgb\",0.071,0.204,0.337,0.471]",
            "color-parser-order <input alpha type=color value=#12345678> [\"srgb\",0.071,0.204,0.337,0.471]",
            "color-parser-order <input type=color colorspace=display-p3 value=red> [\"display-p3\",0.917,0.2,0.139]",
            "color-parser-order <input value=red colorspace=display-p3 type=color> [\"display-p3\",0.917,0.2,0.139]"
        ]
    );
}

#[test]
fn color_copies_reset() {
    assert_eq!(
        visit("color-copies-reset"),
        [
            "color-copies-reset copy c [\"#abcdef\",\"#abcdef\",\"#123\"]",
            "color-copies-reset copy a [[\"srgb\",0.671,0.804,0.937],[\"srgb\",0.671,0.804,0.937],\"#123\"]",
            "color-copies-reset data [[\"c\",\"#abcdef\"],[\"a\",[\"srgb\",0.671,0.804,0.937]]]",
            "color-copies-reset reset [[\"c\",\"#112233\"],[\"a\",[\"srgb\",0.067,0.133,0.2]]]"
        ]
    );
}

#[test]
fn color_type_changes() {
    assert_eq!(
        visit("color-type-changes"),
        [
            "color-type-changes [false,\"color\",\"#aabbcc\",\"#ABC\"]",
            "color-type-changes [false,\"text\",\"#ABC\",\"#ABC\"]",
            "color-type-changes [false,\"hidden\",\"#aabbcc\",\"#aabbcc\"]",
            "color-type-changes [true,\"color\",\"#ff0000\",\"#ABC\"]",
            "color-type-changes [true,\"text\",\"#ff0000\",\"#ABC\"]",
            "color-type-changes [true,\"hidden\",\"#ff0000\",\"#ff0000\"]"
        ]
    );
}

#[test]
fn color_intrinsics() {
    assert_eq!(visit("color-intrinsics"), ["color-intrinsics #ff614d 0"]);
}

fn session(script: &str) -> Value {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    report
}
#[test]
fn driver_selects_colors_and_ranges_with_native_events() {
    let report = session(
        r#"
const f=document.createElement('form');document.body.append(f);
for(const type of ['color','range']){
 const i=document.createElement('input');i.type=type;i.name=type;i.readOnly=true;f.append(i);
 const get=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').get;
 Object.defineProperty(i,'value',{get(){return 'author shadow'},set(){throw Error('author setter')}});
 for(const event of ['input','change'])i.addEventListener(event,e=>console.log(type,event,JSON.stringify([get.call(i),new FormData(f).get(type),e.isTrusted,e.bubbles,e.composed,e instanceof InputEvent])));
}
"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|x| x["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "color input [\"#336699\",\"#336699\",true,true,true,false]",
            "color change [\"#336699\",\"#336699\",true,true,false,false]",
            "range input [\"100\",\"100\",true,true,true,false]",
            "range change [\"100\",\"100\",true,true,false,false]"
        ]
    );
    assert!(report["actions"].as_array().unwrap().iter().all(|a| a["kind"] == "select"), "{report}");
}
#[test]
fn driver_respects_cancellation_disabled_controls_and_fixed_ranges() {
    let report = session(
        r#"
const box=document.createElement('div');box.innerHTML='<input type=color id=canceled><input type=color disabled id=disabled><input type=range min=10 max=10 id=fixed><input type=range id=changed>';document.body.append(box);
box.querySelector('#canceled').addEventListener('click',e=>e.preventDefault());
box.querySelector('#changed').addEventListener('click',e=>e.currentTarget.type='text');
for(const i of box.querySelectorAll('input'))for(const type of ['input','change'])i.addEventListener(type,()=>console.log('unexpected',i.id,type));
"#,
    );
    assert_eq!(report["console"], json!([]), "{report}");
}
#[test]
fn unsupported_css_color_expressions_are_visible() {
    let report = session("const i=document.createElement('input');i.type='color';i.value='rgb(from red r g b)';i.value='rgb(sqrt(4) 0 0)';i.value='Canvas';");
    assert_eq!(report["unmodelled"], json!(["input[type=color]:CSS color expression"]), "{report}");
}
#[test]
fn color_property_brand_and_conversion_semantics() {
    let report = session(
        r#"
const i=document.createElement('input');i.type='color';
for(const k of ['alpha','colorSpace']){const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,k);try{d.get.call({})}catch(e){console.log(k,e.name)}try{d.set.call({},'x')}catch(e){console.log(k,'setter',e.name)}}
let calls=0;i.colorSpace={toString(){calls++;return 'display-p3'}};i.alpha=false;console.log('conversion',calls,i.colorSpace,i.alpha);
i.colorSpace=' display-p3 ';console.log('invalid',i.colorSpace,i.getAttribute('colorspace'));
"#,
    );
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|x| x["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "alpha TypeError",
            "alpha setter TypeError",
            "colorSpace TypeError",
            "colorSpace setter TypeError",
            "conversion 1 display-p3 false",
            "invalid limited-srgb  display-p3 "
        ]
    );
}

#[test]
fn color_mix() {
    assert_eq!(
        visit("color-mix"),
        [
            "color-mix [\"color-mix(in srgb, red 25%, blue)\",\"#4000bf\"]",
            "color-mix [\"color-mix(in srgb, red 20%, blue 20%)\",\"#800080\"]",
            "color-mix [\"color-mix(in srgb, transparent, red)\",\"#ff0000\"]",
            "color-mix [\"color-mix(in oklab, red, blue)\",\"#8c53a2\"]",
            "color-mix [\"color-mix(in hsl longer hue,red,blue)\",\"#00ff00\"]",
            "color-mix [\"color-mix(in srgb,20% red, blue 40%)\",\"#5500aa\"]",
            "color-mix [\"color-mix(in srgb,red calc(10% + 20%),blue)\",\"#4d00b3\"]",
            "color-mix [\"color-mix(in srgb,red 0%,blue 0%)\",\"#800080\"]",
            "color-mix [\"color-mix(in srgb longer hue,red,blue)\",\"#000000\"]",
            "color-mix [\"color-mix(in srgb,red -1%,blue)\",\"#000000\"]",
            "color-mix [\"color-mix(in srgb,red 101%,blue)\",\"#000000\"]",
            "color-mix [\"color-mix(in srgb,red,green,blue)\",\"#552b55\"]"
        ]
    );
}

#[test]
fn color_math_grammar() {
    assert_eq!(
        visit("color-math-grammar"),
        [
            "color-math-grammar [\"rgb(calc(1/**/+/**/2) 0 0)\",\"#000000\"]",
            "color-math-grammar [\"rgb(calc(1/**/ + /**/2) 0 0)\",\"#030000\"]",
            "color-math-grammar [\"rgb(calc(10 + -2) 0 0)\",\"#080000\"]",
            "color-math-grammar [\"rgb(calc(10 - -2) 0 0)\",\"#0c0000\"]",
            "color-math-grammar [\"rgb(calc(10 +2) 0 0)\",\"#000000\"]",
            "color-math-grammar [\"rgb(calc(2*3 + 4/2) 0 0)\",\"#080000\"]",
            "color-math-grammar [\"rgb(calc((1 + 2)*3) 0 0)\",\"#090000\"]",
            "color-math-grammar [\"rgb(calc(10% / 2%) 0 0)\",\"#050000\"]",
            "color-math-grammar [\"rgb(abs(-3) 0 0)\",\"#030000\"]",
            "color-math-grammar [\"rgb(sign(-3) 0 0)\",\"#000000\"]",
            "color-math-grammar [\"rgb(min(NaN,10) 0 0)\",\"#000000\"]",
            "color-math-grammar [\"rgb(clamp(10,5,0) 0 0)\",\"#0a0000\"]",
            "color-math-grammar [\"hwb(120 0 0)\",\"#00ff00\"]",
            "color-math-grammar [\"hsl(120,100,50)\",\"#000000\"]",
            "color-math-grammar [\"rgba(1,2,3,none)\",\"#000000\"]",
            "color-math-grammar [\"rgb(1 2 3 / none)\",\"#010203\"]",
            "color-math-grammar [\"color(display-p3 1 0 0 / none)\",\"#ff0000\"]"
        ]
    );
}

// CSS Color 5 normalization/interpolation plus HTML color well alpha rules.
// In particular, a zero-weight mix retains its mixed components at alpha 0.
// Native browsers differ at these recent CSS Color 5 boundaries.
#[test]
fn color_mix_default() {
    assert_eq!(
        visit("color-mix-default"),
        [
            "color-mix-default [\"color-mix(red,blue)\",[\"srgb\",0.549,0.325,0.635]]",
            "color-mix-default [\"color-mix(in srgb,red)\",[\"srgb\",1,0,0]]",
            "color-mix-default [\"color-mix(in srgb,red 50%)\",[\"srgb\",1,0,0,0.502]]",
            "color-mix-default [\"color-mix(in srgb,red 0%,blue 0%)\",[\"srgb\",0.502,0,0.502,0]]",
            "color-mix-default [\"color-mix(in srgb,red 100%,green 100%,blue)\",[\"srgb\",0.502,0.251,0]]",
            "color-mix-default [\"color-mix(in hsl longer hue,red,green,blue)\",[\"srgb\",0.835,0,0]]"
        ]
    );
}

#[test]
fn system_colors_are_reported_without_a_platform_palette() {
    let report = session("const i=document.createElement('input');i.type='color';i.value='Canvas';");
    assert_eq!(report["unmodelled"], json!(["input[type=color]:CSS color expression"]), "{report}");
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
