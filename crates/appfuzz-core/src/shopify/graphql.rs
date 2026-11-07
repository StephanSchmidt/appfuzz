//! A Shopify Function's GraphQL types as WIT, and the JSON Shopify uses.
//!
//! The input is what the function's input query selects from the schema's
//! query root: only the selected fields, under their response keys
//! (aliases), with `__typename` filled in by Shopify. The output is the
//! input object the target's mutation field takes. Both become WIT types in
//! one world, so appfuzz generates, fuzzes and shrinks them like any other
//! typed value. [`Model::encode`] turns a WIT value into the JSON a
//! function reads; [`Model::decode`] checks the JSON a function wrote the
//! way Shopify does (GraphQL input coercion) and turns it into a WIT value.
//!
//! The mapping: `Int` is `s32`, `Float` and `Decimal` are `f64` (Shopify
//! sends a decimal as a string), `JSON` is a string holding the JSON text,
//! other scalars are strings, a nullable type is an `option`, an object
//! selection is a record, an interface or union selection is a variant with
//! one case per possible type, and a `@oneOf` input object is a variant.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context, Result, anyhow, bail};
use graphql_parser::query as gq;
use graphql_parser::schema as gs;
use serde_json::{Map, Value, json};

type Doc = gs::Document<'static, String>;
type Query = gq::Document<'static, String>;
type GType = graphql_parser::schema::Type<'static, String>;

/// A scalar as the function sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scalar {
    Bool,
    Int,
    Float,
    Str,
    Id,
    /// A decimal number, sent as a string ("12.5").
    Decimal,
    /// Any JSON; WIT holds its text.
    Json,
    /// `2026-11-02`, as a string.
    Date,
    /// `2026-11-02T10:00:00Z`, as a string.
    DateTime,
    /// Another scalar Shopify sends as a string (`Handle`, `URL`).
    Other,
}

/// A type in the model; records, enums and variants by index.
#[derive(Debug, Clone, PartialEq)]
pub enum Ty {
    Scalar(Scalar),
    Enum(usize),
    Record(usize),
    Union(usize),
    List(Box<Ty>),
    Option(Box<Ty>),
}

/// A field of an object selection or an input object.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// The JSON key: the response key (alias or name) in input, the field name in output.
    pub json: String,
    /// The schema's name of the field (`quantity` for `qty: quantity`).
    pub name: String,
    /// The WIT field name.
    pub wit: String,
    pub ty: Ty,
    /// `@scaleLimits(rate:)`: how much this list or string raises the function's limits.
    pub rate: Option<f64>,
    /// `__typename`: Shopify fills in the object's type name; not in WIT.
    pub typename: bool,
    /// Output: the field must be present (non-null, no default).
    pub required: bool,
}

/// An object selection or an input object (a WIT record), or a `@oneOf`
/// input object (a WIT variant, one case per field).
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub wit: String,
    pub gql: String,
    pub fields: Vec<Field>,
    pub one_of: bool,
}

impl Record {
    /// The fields that are in WIT (all but `__typename`).
    fn wit_fields(&self) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(|f| !f.typename)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Enum {
    pub wit: String,
    pub gql: String,
    /// (WIT case, GraphQL value)
    pub values: Vec<(String, String)>,
}

/// An interface or union selection: one case per possible object type.
#[derive(Debug, Clone, PartialEq)]
pub struct Union {
    pub wit: String,
    pub gql: String,
    /// (WIT case, object type name, its selection as a record)
    pub cases: Vec<(String, String, usize)>,
}

/// One target: the WIT export, the input record and the output type.
#[derive(Debug, Clone)]
pub struct Target {
    /// `cart.lines.discounts.generate.run`
    pub target: String,
    /// The module export (`cart_lines_discounts_generate_run`).
    pub export: String,
    /// The WIT export name.
    pub wit: String,
    pub input: Ty,
    pub output: Ty,
}

/// The types of one function: every target's input and output.
#[derive(Debug, Clone, Default)]
pub struct Model {
    pub records: Vec<Record>,
    pub enums: Vec<Enum>,
    pub unions: Vec<Union>,
    pub targets: Vec<Target>,
}

/// What a target needs to be built: its name, export, input query text.
pub struct TargetSource<'a> {
    pub target: &'a str,
    pub export: &'a str,
    pub query: &'a str,
    pub query_name: &'a str,
}

struct Schema {
    doc: Doc,
    types: HashMap<String, usize>,
    query_root: String,
    mutation_root: String,
}

impl Schema {
    fn new(text: &str) -> Result<Schema> {
        let doc: Doc = gs::parse_schema::<String>(text).map_err(|e| anyhow!("{e}"))?.into_static();
        let mut types = HashMap::new();
        let (mut query_root, mut mutation_root) = (None, None);
        for (i, d) in doc.definitions.iter().enumerate() {
            match d {
                gs::Definition::TypeDefinition(t) => {
                    types.insert(type_name(t).to_string(), i);
                }
                gs::Definition::SchemaDefinition(s) => {
                    query_root = s.query.clone();
                    mutation_root = s.mutation.clone();
                }
                _ => {}
            }
        }
        let pick = |given: Option<String>, defaults: &[&str]| given.or_else(|| defaults.iter().find(|d| types.contains_key(**d)).map(|d| d.to_string()));
        let query_root = pick(query_root, &["Input", "Query"]).ok_or_else(|| anyhow!("the schema has no query root (`schema {{ query: Input }}`)"))?;
        let mutation_root = pick(mutation_root, &["MutationRoot", "Mutation"]).ok_or_else(|| anyhow!("the schema has no mutation root"))?;
        Ok(Schema { doc, types, query_root, mutation_root })
    }

    fn get(&self, name: &str) -> Option<&gs::TypeDefinition<'static, String>> {
        match self.types.get(name).map(|i| &self.doc.definitions[*i]) {
            Some(gs::Definition::TypeDefinition(t)) => Some(t),
            _ => None,
        }
    }

    /// The fields of an object or interface type.
    fn fields(&self, name: &str) -> &[gs::Field<'static, String>] {
        match self.get(name) {
            Some(gs::TypeDefinition::Object(o)) => &o.fields,
            Some(gs::TypeDefinition::Interface(i)) => &i.fields,
            _ => &[],
        }
    }

    fn implements(&self, object: &str, interface: &str) -> bool {
        match self.get(object) {
            Some(gs::TypeDefinition::Object(o)) => o.implements_interfaces.iter().any(|i| i == interface),
            _ => false,
        }
    }

    /// The object types an abstract type can be, in schema order.
    fn possible(&self, name: &str) -> Vec<String> {
        match self.get(name) {
            Some(gs::TypeDefinition::Union(u)) => u.types.clone(),
            Some(gs::TypeDefinition::Interface(_)) => self
                .doc
                .definitions
                .iter()
                .filter_map(|d| match d {
                    gs::Definition::TypeDefinition(gs::TypeDefinition::Object(o)) if o.implements_interfaces.iter().any(|i| i == name) => Some(o.name.clone()),
                    _ => None,
                })
                .collect(),
            _ => vec![name.to_string()],
        }
    }

    /// Whether a fragment on `condition` applies to an object of type `object`.
    fn applies(&self, condition: &str, object: &str) -> bool {
        condition == object
            || self.implements(object, condition)
            || matches!(self.get(condition), Some(gs::TypeDefinition::Union(u)) if u.types.iter().any(|t| t == object))
    }
}

fn type_name<'a>(t: &'a gs::TypeDefinition<'static, String>) -> &'a str {
    match t {
        gs::TypeDefinition::Scalar(s) => &s.name,
        gs::TypeDefinition::Object(o) => &o.name,
        gs::TypeDefinition::Interface(i) => &i.name,
        gs::TypeDefinition::Union(u) => &u.name,
        gs::TypeDefinition::Enum(e) => &e.name,
        gs::TypeDefinition::InputObject(i) => &i.name,
    }
}

fn scalar(name: &str) -> Scalar {
    match name {
        "Boolean" => Scalar::Bool,
        "Int" => Scalar::Int,
        "Float" => Scalar::Float,
        "String" => Scalar::Str,
        "ID" => Scalar::Id,
        "Decimal" => Scalar::Decimal,
        "JSON" => Scalar::Json,
        "Date" => Scalar::Date,
        "DateTime" => Scalar::DateTime,
        _ => Scalar::Other,
    }
}

/// `@scaleLimits(rate: 0.005)` on a field definition.
fn rate(f: &gs::Field<'static, String>) -> Option<f64> {
    let d = f.directives.iter().find(|d| d.name == "scaleLimits")?;
    d.arguments.iter().find(|(n, _)| n == "rate").and_then(|(_, v)| match v {
        graphql_parser::query::Value::Float(x) => Some(*x),
        graphql_parser::query::Value::Int(n) => n.as_i64().map(|n| n as f64),
        _ => None,
    })
}

/// A GraphQL name as a WIT identifier: kebab-case words, each starting
/// with a letter (`subtotalAmount` → `subtotal-amount`, `address1` →
/// `address1`, `__typename` → `typename`, `FIRST_LINE` → `first-line`).
pub fn kebab(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let prev = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1).copied();
        let boundary = c.is_ascii_uppercase()
            && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit() || (p.is_ascii_uppercase() && next.is_some_and(|n| n.is_ascii_lowercase())));
        if boundary && !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    // A word may not start with a digit: join it to the one before.
    let mut out: Vec<String> = Vec::new();
    for w in words {
        match out.last_mut() {
            Some(last) if w.starts_with(|c: char| c.is_ascii_digit()) => last.push_str(&w),
            _ if w.starts_with(|c: char| c.is_ascii_digit()) => out.push(format!("n{w}")),
            _ => out.push(w),
        }
    }
    if out.is_empty() { "x".to_string() } else { out.join("-") }
}

/// A name not yet in `taken`: `name`, else `name-2`, `name-3`, …
fn fresh(name: String, taken: &mut BTreeSet<String>) -> String {
    let mut n = 1;
    let mut candidate = name.clone();
    while !taken.insert(candidate.clone()) {
        n += 1;
        candidate = format!("{name}-{n}");
    }
    candidate
}

struct Builder<'a> {
    schema: &'a Schema,
    fragments: HashMap<String, &'a gq::FragmentDefinition<'static, String>>,
    model: Model,
    /// Type names in use, so WIT names stay unique.
    names: BTreeSet<String>,
    /// Records by structure, so equal selections share one WIT type.
    seen: HashMap<String, usize>,
    enums: HashMap<String, usize>,
    unions: HashMap<String, usize>,
    /// Input objects being built: WIT has no recursive types.
    building: Vec<String>,
}

impl<'a> Builder<'a> {
    fn named(&mut self, gql: &str) -> String {
        fresh(kebab(gql), &mut self.names)
    }

    fn record(&mut self, gql: &str, fields: Vec<Field>, one_of: bool) -> usize {
        let key = format!("{gql}|{one_of}|{fields:?}");
        if let Some(i) = self.seen.get(&key) {
            return *i;
        }
        let wit = self.named(gql);
        self.model.records.push(Record { wit, gql: gql.to_string(), fields, one_of });
        let i = self.model.records.len() - 1;
        self.seen.insert(key, i);
        i
    }

    fn enumeration(&mut self, gql: &str) -> Result<usize> {
        if let Some(i) = self.enums.get(gql) {
            return Ok(*i);
        }
        let Some(gs::TypeDefinition::Enum(e)) = self.schema.get(gql) else { bail!("{gql} is not an enum") };
        let mut cases = BTreeSet::new();
        let values = e.values.iter().map(|v| (fresh(kebab(&v.name), &mut cases), v.name.clone())).collect();
        let wit = self.named(gql);
        self.model.enums.push(Enum { wit, gql: gql.to_string(), values });
        let i = self.model.enums.len() - 1;
        self.enums.insert(gql.to_string(), i);
        Ok(i)
    }

    /// The fields a selection gives an object of type `object`, by response
    /// key in first-seen order, merging repeated keys.
    fn collect(
        &self,
        object: &str,
        sets: &[&'a gq::SelectionSet<'static, String>],
        out: &mut Vec<(String, Vec<&'a gq::Field<'static, String>>)>,
    ) -> Result<()> {
        for set in sets {
            for item in &set.items {
                match item {
                    gq::Selection::Field(f) => {
                        let key = f.alias.clone().unwrap_or_else(|| f.name.clone());
                        match out.iter_mut().find(|(k, _)| *k == key) {
                            Some((_, fs)) => fs.push(f),
                            None => out.push((key, vec![f])),
                        }
                    }
                    gq::Selection::InlineFragment(fr) => {
                        let applies = match &fr.type_condition {
                            None => true,
                            Some(gq::TypeCondition::On(c)) => self.schema.applies(c, object),
                        };
                        if applies {
                            self.collect(object, &[&fr.selection_set], out)?;
                        }
                    }
                    gq::Selection::FragmentSpread(s) => {
                        let fr = self.fragments.get(&s.fragment_name).ok_or_else(|| anyhow!("no fragment {}", s.fragment_name))?;
                        let gq::TypeCondition::On(c) = &fr.type_condition;
                        if self.schema.applies(c, object) {
                            self.collect(object, &[&fr.selection_set], out)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The record an object of type `object` gets from a selection.
    fn object(&mut self, object: &str, sets: &[&'a gq::SelectionSet<'static, String>], path: &str) -> Result<usize> {
        let mut selected = Vec::new();
        self.collect(object, sets, &mut selected)?;
        let mut wit_names = BTreeSet::new();
        let mut fields = Vec::new();
        for (key, fs) in selected {
            let name = &fs[0].name;
            let at = format!("{path}.{key}");
            if name == "__typename" {
                fields.push(Field {
                    json: key,
                    name: name.clone(),
                    wit: String::new(),
                    ty: Ty::Scalar(Scalar::Str),
                    rate: None,
                    typename: true,
                    required: true,
                });
                continue;
            }
            let def = self.schema.fields(object).iter().find(|d| d.name == *name).ok_or_else(|| anyhow!("{at}: {object} has no field {name}"))?;
            let subs: Vec<&'a gq::SelectionSet<'static, String>> = fs.iter().map(|f| &f.selection_set).collect();
            let ty = self.output_type(&def.field_type, &subs, &at)?;
            let wit = fresh(kebab(&key), &mut wit_names);
            fields.push(Field { json: key, name: name.clone(), wit, ty, rate: rate(def), typename: false, required: true });
        }
        Ok(self.record(object, fields, false))
    }

    /// The type of a selected field (an "output type" in GraphQL terms).
    fn output_type(&mut self, t: &GType, subs: &[&'a gq::SelectionSet<'static, String>], path: &str) -> Result<Ty> {
        Ok(match t {
            GType::NonNullType(inner) => match self.output_type(inner, subs, path)? {
                Ty::Option(t) => *t,
                t => t,
            },
            GType::ListType(inner) => Ty::Option(Box::new(Ty::List(Box::new(self.output_type(inner, subs, path)?)))),
            GType::NamedType(name) => Ty::Option(Box::new(match self.schema.get(name) {
                None | Some(gs::TypeDefinition::Scalar(_)) => Ty::Scalar(scalar(name)),
                Some(gs::TypeDefinition::Enum(_)) => Ty::Enum(self.enumeration(name)?),
                Some(gs::TypeDefinition::Object(_)) => Ty::Record(self.object(name, subs, path)?),
                Some(gs::TypeDefinition::Interface(_) | gs::TypeDefinition::Union(_)) => Ty::Union(self.abstract_type(name, subs, path)?),
                Some(gs::TypeDefinition::InputObject(_)) => bail!("{path}: {name} is an input type"),
            })),
        })
    }

    fn abstract_type(&mut self, name: &str, subs: &[&'a gq::SelectionSet<'static, String>], path: &str) -> Result<usize> {
        let mut cases = Vec::new();
        let mut taken = BTreeSet::new();
        for object in self.schema.possible(name) {
            let r = self.object(&object, subs, &format!("{path}<{object}>"))?;
            cases.push((fresh(kebab(&object), &mut taken), object, r));
        }
        if cases.is_empty() {
            bail!("{path}: no object type is a {name}");
        }
        let key = format!("{name}|{cases:?}");
        if let Some(i) = self.unions.get(&key) {
            return Ok(*i);
        }
        let wit = self.named(name);
        self.model.unions.push(Union { wit, gql: name.to_string(), cases });
        let i = self.model.unions.len() - 1;
        self.unions.insert(key, i);
        Ok(i)
    }

    /// The type of an input value: output fields of the function.
    fn input_type(&mut self, t: &GType, path: &str) -> Result<Ty> {
        Ok(match t {
            GType::NonNullType(inner) => match self.input_type(inner, path)? {
                Ty::Option(t) => *t,
                t => t,
            },
            GType::ListType(inner) => Ty::Option(Box::new(Ty::List(Box::new(self.input_type(inner, path)?)))),
            GType::NamedType(name) => Ty::Option(Box::new(match self.schema.get(name) {
                None | Some(gs::TypeDefinition::Scalar(_)) => Ty::Scalar(scalar(name)),
                Some(gs::TypeDefinition::Enum(_)) => Ty::Enum(self.enumeration(name)?),
                Some(gs::TypeDefinition::InputObject(_)) => Ty::Record(self.input_object(name, path)?),
                Some(_) => bail!("{path}: {name} is not an input type"),
            })),
        })
    }

    fn input_object(&mut self, name: &str, path: &str) -> Result<usize> {
        if self.building.iter().any(|b| b == name) {
            bail!("{path}: {name} contains itself, which appfuzz cannot type yet");
        }
        let Some(gs::TypeDefinition::InputObject(o)) = self.schema.get(name) else { bail!("{name} is not an input object") };
        let one_of = o.directives.iter().any(|d| d.name == "oneOf");
        self.building.push(name.to_string());
        let mut taken = BTreeSet::new();
        let mut fields = Vec::new();
        for v in &o.fields {
            let at = format!("{path}.{}", v.name);
            let mut ty = self.input_type(&v.value_type, &at)?;
            let required = matches!(v.value_type, GType::NonNullType(_)) && v.default_value.is_none();
            if one_of {
                // A @oneOf field is nullable in the schema; as a case it holds the value.
                if let Ty::Option(t) = ty {
                    ty = *t;
                }
            } else if !required && !matches!(ty, Ty::Option(_)) {
                ty = Ty::Option(Box::new(ty));
            }
            fields.push(Field {
                json: v.name.clone(),
                name: v.name.clone(),
                wit: fresh(kebab(&v.name), &mut taken),
                ty,
                rate: None,
                typename: false,
                required,
            });
        }
        self.building.pop();
        if fields.is_empty() {
            bail!("{path}: {name} has no fields");
        }
        Ok(self.record(name, fields, one_of))
    }

    /// The input object a target's result is: the mutation field named after
    /// the target (`cartLinesDiscountsGenerateRun`), the one whose description
    /// names it, the export's name, or `handleResult`.
    fn output(&mut self, target: &str, export: &str) -> Result<Ty> {
        let root = self.schema.mutation_root.clone();
        let fields = self.schema.fields(&root);
        let camel = |s: &str| -> String {
            let mut out = String::new();
            for (i, part) in s.split(['.', '-', '_']).filter(|p| !p.is_empty()).enumerate() {
                let mut c = part.chars();
                if let Some(f) = c.next() {
                    if i == 0 {
                        out.push(f.to_ascii_lowercase());
                    } else {
                        out.push(f.to_ascii_uppercase());
                    }
                    out.extend(c);
                }
            }
            out
        };
        let by_target = camel(target);
        let field = fields
            .iter()
            .find(|f| f.name == by_target)
            .or_else(|| {
                fields.iter().find(|f| f.description.as_deref().is_some_and(|d| d.contains(&format!(" {target} ")) || d.contains(&format!(" {target}."))))
            })
            .or_else(|| fields.iter().find(|f| f.name == camel(export)))
            .or_else(|| fields.iter().find(|f| f.name == "handleResult"))
            .ok_or_else(|| anyhow!("the schema's {root} has no field for target {target} (looked for {by_target})"))?;
        let arg = field.arguments.first().ok_or_else(|| anyhow!("{root}.{} takes no result", field.name))?;
        let ty = self.input_type(&arg.value_type, &format!("{root}.{}", field.name))?;
        Ok(match ty {
            Ty::Option(t) => *t,
            t => t,
        })
    }
}

impl Model {
    /// The types of a function with these targets.
    pub fn new(schema: &str, targets: &[TargetSource]) -> Result<Model> {
        let schema = Schema::new(schema).context("parsing the GraphQL schema")?;
        let queries: Vec<Query> = targets
            .iter()
            .map(|t| gq::parse_query::<String>(t.query).map(|d| d.into_static()).map_err(|e| anyhow!("parsing {}: {e}", t.query_name)))
            .collect::<Result<_>>()?;
        let mut b = Builder {
            schema: &schema,
            fragments: HashMap::new(),
            model: Model::default(),
            names: BTreeSet::new(),
            seen: HashMap::new(),
            enums: HashMap::new(),
            unions: HashMap::new(),
            building: Vec::new(),
        };
        let mut exports = BTreeSet::new();
        for (t, q) in targets.iter().zip(&queries) {
            b.fragments = q
                .definitions
                .iter()
                .filter_map(|d| match d {
                    gq::Definition::Fragment(f) => Some((f.name.clone(), f)),
                    _ => None,
                })
                .collect();
            let set = q
                .definitions
                .iter()
                .find_map(|d| match d {
                    gq::Definition::Operation(gq::OperationDefinition::Query(q)) => Some(&q.selection_set),
                    gq::Definition::Operation(gq::OperationDefinition::SelectionSet(s)) => Some(s),
                    _ => None,
                })
                .ok_or_else(|| anyhow!("{} has no query", t.query_name))?;
            let root = schema.query_root.clone();
            let input = Ty::Record(b.object(&root, &[set], "input").with_context(|| format!("in {}", t.query_name))?);
            let output = b.output(t.target, t.export)?;
            let wit = fresh(kebab(t.export), &mut exports);
            b.model.targets.push(Target { target: t.target.to_string(), export: t.export.to_string(), wit, input, output });
        }
        Ok(b.model)
    }

    /// The model as a WIT package: every type in one world, one export per target.
    pub fn wit(&self) -> String {
        let mut s = String::from("package appfuzz:shopify;\n\nworld function {\n");
        for e in &self.enums {
            s.push_str(&format!("  enum %{} {{\n", e.wit));
            for (c, _) in &e.values {
                s.push_str(&format!("    %{c},\n"));
            }
            s.push_str("  }\n");
        }
        // Records and unions refer to ones built before them.
        let mut order: Vec<(usize, bool)> = Vec::new();
        let mut done_r = vec![false; self.records.len()];
        let mut done_u = vec![false; self.unions.len()];
        for i in 0..self.records.len() {
            self.order(Ty::Record(i), &mut order, &mut done_r, &mut done_u);
        }
        for i in 0..self.unions.len() {
            self.order(Ty::Union(i), &mut order, &mut done_r, &mut done_u);
        }
        for (i, record) in order {
            if record {
                let r = &self.records[i];
                if r.one_of {
                    s.push_str(&format!("  variant %{} {{\n", r.wit));
                    for f in r.wit_fields() {
                        s.push_str(&format!("    %{}({}),\n", f.wit, self.wit_type(&f.ty)));
                    }
                } else {
                    s.push_str(&format!("  record %{} {{\n", r.wit));
                    let mut any = false;
                    for f in r.wit_fields() {
                        s.push_str(&format!("    %{}: {},\n", f.wit, self.wit_type(&f.ty)));
                        any = true;
                    }
                    if !any {
                        // WIT has no empty records; this field is not in the JSON.
                        s.push_str("    %present: bool,\n");
                    }
                }
                s.push_str("  }\n");
            } else {
                let u = &self.unions[i];
                s.push_str(&format!("  variant %{} {{\n", u.wit));
                for (c, _, r) in &u.cases {
                    s.push_str(&format!("    %{c}(%{}),\n", self.records[*r].wit));
                }
                s.push_str("  }\n");
            }
        }
        for t in &self.targets {
            s.push_str(&format!("  /// The function's {} target.\n", t.target));
            s.push_str(&format!("  export %{}: func(input: {}) -> {};\n", t.wit, self.wit_type(&t.input), self.wit_type(&t.output)));
        }
        s.push_str("}\n");
        s
    }

    fn order(&self, t: Ty, out: &mut Vec<(usize, bool)>, done_r: &mut [bool], done_u: &mut [bool]) {
        match t {
            Ty::Record(i) if !done_r[i] => {
                done_r[i] = true;
                for f in self.records[i].wit_fields() {
                    self.order(f.ty.clone(), out, done_r, done_u);
                }
                out.push((i, true));
            }
            Ty::Union(i) if !done_u[i] => {
                done_u[i] = true;
                for (_, _, r) in &self.unions[i].cases {
                    self.order(Ty::Record(*r), out, done_r, done_u);
                }
                out.push((i, false));
            }
            Ty::List(t) | Ty::Option(t) => self.order(*t, out, done_r, done_u),
            _ => {}
        }
    }

    fn wit_type(&self, t: &Ty) -> String {
        match t {
            Ty::Scalar(Scalar::Bool) => "bool".into(),
            Ty::Scalar(Scalar::Int) => "s32".into(),
            Ty::Scalar(Scalar::Float | Scalar::Decimal) => "f64".into(),
            Ty::Scalar(_) => "string".into(),
            Ty::Enum(i) => format!("%{}", self.enums[*i].wit),
            Ty::Record(i) => format!("%{}", self.records[*i].wit),
            Ty::Union(i) => format!("%{}", self.unions[*i].wit),
            Ty::List(t) => format!("list<{}>", self.wit_type(t)),
            Ty::Option(t) => format!("option<{}>", self.wit_type(t)),
        }
    }

    pub fn target(&self, wit: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.wit == wit)
    }

    /// A WIT value (as `val_to_json` writes it) as the JSON Shopify sends.
    pub fn encode(&self, v: &Value, t: &Ty) -> Value {
        self.encode_as(v, t, true)
    }

    /// Like `encode`, with decimals as numbers: what a rule compares.
    pub fn readable(&self, v: &Value, t: &Ty) -> Value {
        self.encode_as(v, t, false)
    }

    fn encode_as(&self, v: &Value, t: &Ty, text: bool) -> Value {
        match (t, v) {
            (Ty::Option(_), Value::Null) => Value::Null,
            (Ty::Option(t), Value::Object(m)) if m.len() == 1 && m.contains_key("some") => self.encode_as(&m["some"], t, text),
            (Ty::Option(t), v) => self.encode_as(v, t, text),
            (Ty::List(t), Value::Array(a)) => Value::Array(a.iter().map(|x| self.encode_as(x, t, text)).collect()),
            (Ty::Scalar(Scalar::Decimal), Value::Number(n)) if text => Value::String(decimal(n.as_f64().unwrap_or(0.0))),
            (Ty::Scalar(Scalar::Json), Value::String(s)) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
            (Ty::Enum(i), Value::String(c)) => {
                json!(self.enums[*i].values.iter().find(|(w, _)| w == c).map_or(c.as_str(), |(_, g)| g.as_str()))
            }
            (Ty::Record(i), v) => self.encode_record(*i, v, text),
            (Ty::Union(i), Value::Object(m)) if m.len() == 1 => {
                let (case, payload) = m.iter().next().expect("one entry");
                match self.unions[*i].cases.iter().find(|(c, _, _)| c == case) {
                    Some((_, _, r)) => self.encode_record(*r, payload, text),
                    None => v.clone(),
                }
            }
            (_, v) => v.clone(),
        }
    }

    fn encode_record(&self, i: usize, v: &Value, text: bool) -> Value {
        let r = &self.records[i];
        if r.one_of {
            if let Value::Object(m) = v
                && let Some((case, payload)) = m.iter().next()
                && let Some(f) = r.fields.iter().find(|f| f.wit == *case)
            {
                return json!({ f.json.clone(): self.encode_as(payload, &f.ty, text) });
            }
            return v.clone();
        }
        let empty = Map::new();
        let m = v.as_object().unwrap_or(&empty);
        let mut out = Map::new();
        for f in &r.fields {
            if f.typename {
                out.insert(f.json.clone(), Value::String(r.gql.clone()));
            } else if let Some(x) = m.get(&f.wit) {
                out.insert(f.json.clone(), self.encode_as(x, &f.ty, text));
            }
        }
        Value::Object(out)
    }

    /// The JSON a function wrote as a WIT value, checked as Shopify checks
    /// it. Problems are listed with their JSON paths.
    pub fn decode(&self, v: &Value, t: &Ty) -> std::result::Result<Value, Vec<String>> {
        let mut problems = Vec::new();
        let out = self.decode_at(v, t, "$", &mut problems);
        if problems.is_empty() { Ok(out) } else { Err(problems) }
    }

    fn decode_at(&self, v: &Value, t: &Ty, path: &str, problems: &mut Vec<String>) -> Value {
        let wrong = |problems: &mut Vec<String>, what: &str| {
            problems.push(format!("{path}: expected {what}, got {}", short(v)));
            Value::Null
        };
        match t {
            Ty::Option(_) if v.is_null() => Value::Null,
            Ty::Option(t) => json!({ "some": self.decode_at(v, t, path, problems) }),
            _ if v.is_null() => {
                problems.push(format!("{path}: null where a value is required"));
                Value::Null
            }
            // Input coercion: one value where a list is expected is a list of one.
            Ty::List(t) => match v {
                Value::Array(a) => Value::Array(a.iter().enumerate().map(|(i, x)| self.decode_at(x, t, &format!("{path}[{i}]"), problems)).collect()),
                one => Value::Array(vec![self.decode_at(one, t, path, problems)]),
            },
            Ty::Scalar(s) => match (s, v) {
                (Scalar::Bool, Value::Bool(_)) | (Scalar::Str | Scalar::Date | Scalar::DateTime | Scalar::Other, Value::String(_)) => v.clone(),
                (Scalar::Int, Value::Number(n)) => match n.as_i64().filter(|n| i32::try_from(*n).is_ok()) {
                    Some(n) => json!(n),
                    None => wrong(problems, "a 32-bit integer"),
                },
                (Scalar::Float, Value::Number(n)) => json!(n.as_f64().unwrap_or(0.0)),
                (Scalar::Decimal, Value::Number(n)) => json!(n.as_f64().unwrap_or(0.0)),
                (Scalar::Decimal, Value::String(s)) => match s.trim().parse::<f64>() {
                    Ok(x) if x.is_finite() => json!(x),
                    _ => wrong(problems, "a decimal number"),
                },
                (Scalar::Id, Value::String(_)) => v.clone(),
                (Scalar::Id, Value::Number(n)) if n.is_i64() || n.is_u64() => Value::String(n.to_string()),
                (Scalar::Json, v) => Value::String(v.to_string()),
                (Scalar::Bool, _) => wrong(problems, "true or false"),
                (Scalar::Int, _) => wrong(problems, "an integer"),
                (Scalar::Float, _) => wrong(problems, "a number"),
                (Scalar::Decimal, _) => wrong(problems, "a decimal number"),
                (Scalar::Id, _) => wrong(problems, "an ID"),
                (Scalar::Str | Scalar::Date | Scalar::DateTime | Scalar::Other, _) => wrong(problems, "a string"),
            },
            Ty::Enum(i) => {
                let e = &self.enums[*i];
                match v.as_str().and_then(|s| e.values.iter().find(|(_, g)| g == s)) {
                    Some((w, _)) => json!(w),
                    None => wrong(problems, &format!("one of {}", e.values.iter().map(|(_, g)| g.as_str()).collect::<Vec<_>>().join(", "))),
                }
            }
            Ty::Record(i) => {
                let r = &self.records[*i];
                let Value::Object(m) = v else { return wrong(problems, &format!("an object ({})", r.gql)) };
                for k in m.keys() {
                    if !r.fields.iter().any(|f| f.json == *k) {
                        problems.push(format!("{path}: {} has no field {k}", r.gql));
                    }
                }
                if r.one_of {
                    let set: Vec<(&String, &Value)> = m.iter().filter(|(_, x)| !x.is_null()).collect();
                    let [(k, x)] = set.as_slice() else {
                        problems.push(format!("{path}: {} takes exactly one field, got {}", r.gql, set.len()));
                        return Value::Null;
                    };
                    let Some(f) = r.fields.iter().find(|f| f.json == **k) else { return Value::Null };
                    return json!({ f.wit.clone(): self.decode_at(x, &f.ty, &format!("{path}.{k}"), problems) });
                }
                let mut out = Map::new();
                for f in r.wit_fields() {
                    let at = format!("{path}.{}", f.json);
                    match m.get(&f.json) {
                        Some(x) => {
                            out.insert(f.wit.clone(), self.decode_at(x, &f.ty, &at, problems));
                        }
                        None if f.required => problems.push(format!("{at}: missing; {} requires it", r.gql)),
                        None => {
                            out.insert(f.wit.clone(), Value::Null);
                        }
                    }
                }
                if r.wit_fields().next().is_none() {
                    out.insert("present".into(), json!(true));
                }
                Value::Object(out)
            }
            // Only in an input (a query's answer): the object of one of
            // its types, named by `__typename` when the query asks for it.
            Ty::Union(i) => {
                let u = &self.unions[*i];
                let Value::Object(m) = v else { return wrong(problems, "an object") };
                let named = m.get("__typename").and_then(Value::as_str);
                let mut first = None;
                for (case, object, r) in u.cases.iter().filter(|(_, object, _)| named.is_none_or(|n| n == object)) {
                    let mut p = Vec::new();
                    let x = self.decode_at(v, &Ty::Record(*r), &format!("{path}<{object}>"), &mut p);
                    if p.is_empty() {
                        return json!({ case.clone(): x });
                    }
                    first.get_or_insert(p);
                }
                match first {
                    Some(p) => problems.extend(p),
                    None => problems.push(format!("{path}: {} is none of the types of {}", named.unwrap_or("?"), u.gql)),
                }
                Value::Null
            }
        }
    }

    /// How much the limits scale for this input (WIT-shaped): for each
    /// `@scaleLimits` field, its length (items, or characters of a string)
    /// times its rate, summed over every place it occurs; the largest
    /// sum, between 1 and 10. This is how Shopify scales limits for big carts.
    pub fn scale(&self, input: &Value, t: &Ty) -> f64 {
        self.sizes(input, t).into_values().map(|(_, s)| s).fold(1.0, f64::max).clamp(1.0, 10.0)
    }

    /// Per `@scaleLimits` field (`cart.lines`): its total length over
    /// the input, and that length times its rate.
    pub fn sizes(&self, input: &Value, t: &Ty) -> BTreeMap<String, (u64, f64)> {
        let mut sums = BTreeMap::new();
        self.scale_walk(input, t, "", &mut sums);
        sums.into_iter().map(|(k, v)| (k.trim_start_matches('.').to_string(), v)).collect()
    }

    fn scale_walk(&self, v: &Value, t: &Ty, path: &str, sums: &mut BTreeMap<String, (u64, f64)>) {
        match (t, v) {
            (Ty::Option(t), Value::Object(m)) if m.len() == 1 && m.contains_key("some") => self.scale_walk(&m["some"], t, path, sums),
            (Ty::Option(t), v) if !v.is_null() => self.scale_walk(v, t, path, sums),
            (Ty::List(t), Value::Array(a)) => a.iter().for_each(|x| self.scale_walk(x, t, path, sums)),
            (Ty::Record(i), Value::Object(m)) => {
                for f in self.records[*i].wit_fields() {
                    let at = format!("{path}.{}", f.json);
                    let x = m.get(&f.wit).unwrap_or(&Value::Null);
                    if let Some(rate) = f.rate {
                        let mut inner = x;
                        if let Value::Object(o) = inner
                            && o.len() == 1
                            && let Some(s) = o.get("some")
                        {
                            inner = s;
                        }
                        let len = match inner {
                            Value::Array(a) => a.len(),
                            Value::String(s) => s.len(),
                            _ => 1,
                        };
                        let sum = sums.entry(at.clone()).or_default();
                        sum.0 += len as u64;
                        sum.1 += len as f64 * rate;
                    }
                    self.scale_walk(x, &f.ty, &at, sums);
                }
            }
            (Ty::Union(i), Value::Object(m)) if m.len() == 1 => {
                let (case, payload) = m.iter().next().expect("one entry");
                if let Some((_, object, r)) = self.unions[*i].cases.iter().find(|(c, _, _)| c == case) {
                    let _ = object;
                    self.scale_walk(payload, &Ty::Record(*r), path, sums);
                }
            }
            _ => {}
        }
    }

    /// The values of an input (WIT-shaped) Shopify never sends: (JSON
    /// path, what Shopify sends there, the value).
    pub fn unsendable(&self, input: &Value, t: &Ty) -> Vec<(String, String, Value)> {
        let mut v = input.clone();
        let mut out = Vec::new();
        self.sent_walk(&mut v, t, "", None, &mut |p, s, x| {
            if !s.holds(x) {
                out.push((p.trim_start_matches('.').to_string(), s.what(), x.clone()));
            }
        });
        out
    }

    /// Makes every value of an input (WIT-shaped) one Shopify could send.
    pub fn conform(&self, input: &mut Value, t: &Ty) {
        self.sent_walk(input, t, "", None, &mut |_, s, x| {
            if !s.holds(x) {
                *x = s.repair(x);
            }
        });
    }

    fn sent_walk<'a>(&'a self, v: &mut Value, t: &Ty, path: &str, rule: Option<Sent<'a>>, f: &mut dyn FnMut(&str, Sent<'a>, &mut Value)) {
        match t {
            Ty::Option(_) if v.is_null() => {}
            Ty::Option(t) => match v {
                Value::Object(m) if m.len() == 1 && m.contains_key("some") => self.sent_walk(m.get_mut("some").expect("checked"), t, path, rule, f),
                v => self.sent_walk(v, t, path, rule, f),
            },
            Ty::List(t) => {
                if let Value::Array(a) = v {
                    for (i, x) in a.iter_mut().enumerate() {
                        self.sent_walk(x, t, &format!("{path}[{i}]"), rule, f);
                    }
                }
            }
            Ty::Scalar(_) => {
                if let Some(r) = rule {
                    f(path, r, v);
                }
            }
            Ty::Record(i) => {
                let r = &self.records[*i];
                let Value::Object(m) = v else { return };
                for field in r.wit_fields() {
                    if let Some(x) = m.get_mut(&field.wit) {
                        self.sent_walk(x, &field.ty, &format!("{path}.{}", field.json), Sent::of(&r.gql, field), f);
                    }
                }
            }
            Ty::Union(i) => {
                if let Value::Object(m) = v
                    && m.len() == 1
                {
                    let (case, payload) = m.iter_mut().next().expect("one entry");
                    if let Some((_, _, r)) = self.unions[*i].cases.iter().find(|(c, _, _)| c == case) {
                        self.sent_walk(payload, &Ty::Record(*r), path, None, f);
                    }
                }
            }
            Ty::Enum(_) => {}
        }
    }
}

/// The largest amount appfuzz tries: Shopify sends none that large.
const MAX_AMOUNT: f64 = 1e12;

/// What Shopify sends in a scalar of an input, by its type and field.
#[derive(Debug, Clone, Copy)]
enum Sent<'a> {
    /// A `Decimal`: an amount, never negative.
    Amount,
    /// A `Float`: a finite number.
    Finite,
    /// A line's `quantity`: at least 1.
    Quantity,
    /// An `ID`: `gid://shopify/<Type>/<n>`, the type being the object's.
    Gid(&'a str),
    Date,
    DateTime,
}

impl<'a> Sent<'a> {
    fn of(object: &'a str, f: &Field) -> Option<Self> {
        let mut t = &f.ty;
        while let Ty::Option(x) | Ty::List(x) = t {
            t = x;
        }
        Some(match t {
            Ty::Scalar(Scalar::Decimal) => Sent::Amount,
            Ty::Scalar(Scalar::Float) => Sent::Finite,
            Ty::Scalar(Scalar::Int) if f.name == "quantity" => Sent::Quantity,
            Ty::Scalar(Scalar::Id) => Sent::Gid(object),
            Ty::Scalar(Scalar::Date) => Sent::Date,
            Ty::Scalar(Scalar::DateTime) => Sent::DateTime,
            _ => return None,
        })
    }

    fn what(&self) -> String {
        match self {
            Sent::Amount => "an amount from 0 (Shopify sends no negative amount)".into(),
            Sent::Finite => "a finite number".into(),
            Sent::Quantity => "a quantity of at least 1".into(),
            Sent::Gid(t) => format!("a Shopify ID (gid://shopify/{t}/…)"),
            Sent::Date => "a date (2026-11-02)".into(),
            Sent::DateTime => "a date and time (2026-11-02T10:00:00Z)".into(),
        }
    }

    fn holds(&self, v: &Value) -> bool {
        match self {
            Sent::Amount => v.as_f64().is_some_and(|x| (0.0..=MAX_AMOUNT).contains(&x)),
            Sent::Finite => v.as_f64().is_some_and(f64::is_finite),
            Sent::Quantity => v.as_i64().is_some_and(|n| n >= 1),
            Sent::Gid(_) => v.as_str().and_then(|s| s.strip_prefix("gid://shopify/")).is_some_and(|rest| rest.contains('/')),
            Sent::Date => v.as_str().is_some_and(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()),
            Sent::DateTime => v
                .as_str()
                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok() || chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").is_ok()),
        }
    }

    /// A value Shopify could send, made from this one: the same value
    /// always gives the same repair, so ids that matched still match.
    fn repair(&self, v: &Value) -> Value {
        let h = fnv(&v.to_string());
        match self {
            Sent::Amount => json!((v.as_f64().filter(|x| x.is_finite()).unwrap_or(0.0).abs().min(MAX_AMOUNT) * 100.0).round() / 100.0),
            Sent::Finite => json!(v.as_f64().filter(|x| x.is_finite()).unwrap_or(0.0)),
            Sent::Quantity => json!(v.as_i64().map_or(1, |n| (n.unsigned_abs() % 1000).max(1))),
            Sent::Gid(t) => {
                let digits = v.as_str().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
                let n = digits.map_or_else(|| (h % 10_000_000_000).to_string(), str::to_string);
                json!(format!("gid://shopify/{t}/{n}"))
            }
            Sent::Date | Sent::DateTime => {
                let at = chrono::DateTime::from_timestamp(946_684_800 + (h % (40 * 365 * 86_400)) as i64, 0).unwrap_or_default();
                json!(if matches!(self, Sent::Date) { at.format("%Y-%m-%d").to_string() } else { at.format("%Y-%m-%dT%H:%M:%SZ").to_string() })
            }
        }
    }
}

fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3))
}

/// A decimal as Shopify writes one: "12.5", "10.0".
fn decimal(x: f64) -> String {
    if !x.is_finite() {
        return "0.0".into();
    }
    let s = format!("{x}");
    if s.contains(['.', 'e', 'E']) { s } else { format!("{s}.0") }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 60 { format!("{}…", s.chars().take(60).collect::<String>()) } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"
schema { query: Input mutation: MutationRoot }
directive @scaleLimits(rate: Float!) on FIELD_DEFINITION
directive @oneOf on INPUT_OBJECT
scalar Decimal
scalar Void
type Input { cart: Cart! discount: Discount! }
type Cart { lines: [CartLine!]! @scaleLimits(rate: 0.005) buyerIdentity: BuyerIdentity }
type BuyerIdentity { email: String }
type CartLine { id: ID! quantity: Int! cost: CartLineCost! merchandise: Merchandise! }
type CartLineCost { subtotalAmount: MoneyV2! }
type MoneyV2 { amount: Decimal! currencyCode: CurrencyCode! }
enum CurrencyCode { USD EUR }
union Merchandise = ProductVariant | CustomProduct
type ProductVariant { id: ID! product: Product! }
type Product { handle: String! hasAnyTag(tags: [String!]! = []): Boolean! }
type CustomProduct { title: String! }
type Discount { discountClasses: [DiscountClass!]! metafield(key: String!): Metafield }
type Metafield { value: String! jsonValue: JSON! }
scalar JSON
enum DiscountClass { PRODUCT ORDER SHIPPING }
type MutationRoot { cartLinesDiscountsGenerateRun(result: CartLinesDiscountsGenerateRunResult!): Void! }
input CartLinesDiscountsGenerateRunResult { operations: [CartOperation!]! }
input CartOperation @oneOf { productDiscountsAdd: ProductDiscountsAddOperation orderDiscountsAdd: OrderDiscountsAddOperation }
input ProductDiscountsAddOperation { candidates: [ProductDiscountCandidate!]! selectionStrategy: ProductDiscountSelectionStrategy! }
input OrderDiscountsAddOperation { message: String }
input ProductDiscountCandidate { targets: [CartLineTarget!]! value: ProductDiscountCandidateValue! message: String }
input CartLineTarget { id: ID! quantity: Int }
input ProductDiscountCandidateValue @oneOf { percentage: Percentage fixedAmount: FixedAmount }
input Percentage { value: Decimal! }
input FixedAmount { amount: Decimal! appliesToEachItem: Boolean = false }
enum ProductDiscountSelectionStrategy { FIRST MAXIMUM ALL }
"#;

    const QUERY: &str = r#"
query Input {
  cart {
    lines {
      id
      qty: quantity
      cost { subtotalAmount { amount currencyCode } }
      merchandise {
        __typename
        ... on ProductVariant { id product { handle vip: hasAnyTag(tags: ["vip"]) } }
      }
    }
    buyerIdentity { email }
  }
  discount { discountClasses config: metafield(key: "config") { value } }
}
"#;

    fn model() -> Model {
        Model::new(
            SCHEMA,
            &[TargetSource {
                target: "cart.lines.discounts.generate.run",
                export: "cart_lines_discounts_generate_run",
                query: QUERY,
                query_name: "run.graphql",
            }],
        )
        .unwrap()
    }

    #[test]
    fn names_become_kebab_case() {
        assert_eq!(kebab("subtotalAmount"), "subtotal-amount");
        assert_eq!(kebab("address1"), "address1");
        assert_eq!(kebab("__typename"), "typename");
        assert_eq!(kebab("FIRST_LINE"), "first-line");
        assert_eq!(kebab("URLPath"), "url-path");
        assert_eq!(kebab("countryCodeV2"), "country-code-v2");
        assert_eq!(kebab("cart_lines_discounts_generate_run"), "cart-lines-discounts-generate-run");
    }

    #[test]
    fn the_wit_parses_and_has_one_export_per_target() {
        let m = model();
        let wit = m.wit();
        let mut resolve = wit_parser::Resolve::new();
        resolve.push_str("shopify.wit", &wit).unwrap_or_else(|e| panic!("{e:#}\n{wit}"));
        assert!(wit.contains("export %cart-lines-discounts-generate-run: func(input: %input) -> %cart-lines-discounts-generate-run-result;"), "{wit}");
        // Selected fields only, under their response keys.
        assert!(wit.contains("%qty: s32"), "{wit}");
        assert!(!wit.contains("%quantity: s32"), "{wit}");
        assert!(wit.contains("variant %merchandise"), "{wit}");
        assert!(wit.contains("variant %cart-operation"), "{wit}");
    }

    #[test]
    fn input_encodes_as_shopify_sends_it() {
        let m = model();
        let t = &m.targets[0];
        let wit = json!({
            "cart": {
                "lines": [{
                    "id": "gid://shopify/CartLine/1",
                    "qty": 2,
                    "cost": {"subtotal-amount": {"amount": 12.0, "currency-code": "usd"}},
                    "merchandise": {"product-variant": {"id": "gid://shopify/ProductVariant/7", "product": {"handle": "hat", "vip": true}}}
                }, {
                    "id": "gid://shopify/CartLine/2",
                    "qty": 1,
                    "cost": {"subtotal-amount": {"amount": 3.25, "currency-code": "eur"}},
                    "merchandise": {"custom-product": {"present": true}}
                }],
                "buyer-identity": {"some": {"email": null}}
            },
            "discount": {"discount-classes": ["product"], "config": {"some": {"value": "{\"percent\":10}"}}}
        });
        let shopify = m.encode(&wit, &t.input);
        assert_eq!(
            shopify,
            json!({
                "cart": {
                    "lines": [{
                        "id": "gid://shopify/CartLine/1",
                        "qty": 2,
                        "cost": {"subtotalAmount": {"amount": "12.0", "currencyCode": "USD"}},
                        "merchandise": {"__typename": "ProductVariant", "id": "gid://shopify/ProductVariant/7", "product": {"handle": "hat", "vip": true}}
                    }, {
                        "id": "gid://shopify/CartLine/2",
                        "qty": 1,
                        "cost": {"subtotalAmount": {"amount": "3.25", "currencyCode": "EUR"}},
                        "merchandise": {"__typename": "CustomProduct"}
                    }],
                    "buyerIdentity": {"email": null}
                },
                "discount": {"discountClasses": ["PRODUCT"], "config": {"value": "{\"percent\":10}"}}
            })
        );
        assert_eq!(m.scale(&wit, &t.input), 1.0);
    }

    #[test]
    fn inputs_shopify_never_sends_are_named_and_repaired() {
        let m = model();
        let t = &m.targets[0];
        let line = |id: &str, qty: i64, amount: f64, variant: &str| {
            json!({
                "id": id,
                "qty": qty,
                "cost": {"subtotal-amount": {"amount": amount, "currency-code": "usd"}},
                "merchandise": {"product-variant": {"id": variant, "product": {"handle": "hat", "vip": false}}}
            })
        };
        let mut wit = json!({
            "cart": {"lines": [line("7", 0, -12.5, "abc"), line("gid://shopify/CartLine/2", 3, 4.0, "abc")], "buyer-identity": null},
            "discount": {"discount-classes": [], "config": null}
        });
        let bad: Vec<String> = m.unsendable(&wit, &t.input).into_iter().map(|(p, _, _)| p).collect();
        assert_eq!(
            bad,
            [
                "cart.lines[0].id",
                "cart.lines[0].qty",
                "cart.lines[0].cost.subtotalAmount.amount",
                "cart.lines[0].merchandise.id",
                "cart.lines[1].merchandise.id"
            ]
        );
        m.conform(&mut wit, &t.input);
        assert!(m.unsendable(&wit, &t.input).is_empty(), "{wit}");
        let lines = &wit["cart"]["lines"];
        assert_eq!(lines[0]["id"], "gid://shopify/CartLine/7");
        assert_eq!(lines[0]["qty"], 1);
        assert_eq!(lines[0]["cost"]["subtotal-amount"]["amount"], 12.5);
        // The same id is repaired the same way: lines still share a variant.
        let variant = &lines[0]["merchandise"]["product-variant"]["id"];
        assert!(variant.as_str().unwrap().starts_with("gid://shopify/ProductVariant/"), "{variant}");
        assert_eq!(*variant, lines[1]["merchandise"]["product-variant"]["id"]);
    }

    #[test]
    fn output_is_checked_like_shopify_checks_it() {
        let m = model();
        let t = &m.targets[0];
        let good = json!({"operations": [{"productDiscountsAdd": {
            "candidates": [{"targets": [{"id": "gid://shopify/CartLine/1"}], "value": {"percentage": {"value": "10.0"}}}],
            "selectionStrategy": "FIRST"
        }}]});
        let v = m.decode(&good, &t.output).unwrap();
        assert_eq!(v["operations"][0]["product-discounts-add"]["selection-strategy"], json!("first"));
        assert_eq!(v["operations"][0]["product-discounts-add"]["candidates"][0]["value"], json!({"percentage": {"value": 10.0}}));

        let bad = json!({"operations": [{"productDiscountsAdd": {
            "candidates": [{"targets": [{"id": "gid://shopify/CartLine/1"}], "value": {"percentage": {"value": "ten"}, "fixedAmount": {"amount": 1}}}],
            "selectionStrategy": "BEST",
            "extra": 1
        }}]});
        let problems = m.decode(&bad, &t.output).unwrap_err();
        let text = problems.join("\n");
        assert!(text.contains("takes exactly one field"), "{text}");
        assert!(text.contains("$.operations[0].productDiscountsAdd.selectionStrategy: expected one of FIRST, MAXIMUM, ALL"), "{text}");
        assert!(text.contains("has no field extra"), "{text}");
        let missing = m.decode(&json!({}), &t.output).unwrap_err();
        assert_eq!(missing, vec!["$.operations: missing; CartLinesDiscountsGenerateRunResult requires it".to_string()]);
    }

    #[test]
    fn limits_scale_with_the_rated_list() {
        let m = model();
        let t = &m.targets[0];
        let line = json!({"id": "x", "qty": 1, "cost": {"subtotal-amount": {"amount": 1.0, "currency-code": "usd"}}, "merchandise": {"custom-product": {"present": true}}});
        let lines: Vec<Value> = (0..400).map(|_| line.clone()).collect();
        let wit = json!({"cart": {"lines": lines, "buyer-identity": null}, "discount": {"discount-classes": [], "config": null}});
        assert_eq!(m.scale(&wit, &t.input), 2.0);
    }
}
