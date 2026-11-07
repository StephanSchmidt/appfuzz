//! Streams and futures in the answers of async platform imports.
//!
//! appfuzz generates, plans and records a `stream<T>` as `list<T>` and a
//! `future<T>` as `T`, so rows in a stream scale, shrink and carry labels
//! like rows in a list. The app needs a real stream, and wasmtime builds a
//! host stream only from a static Rust type. So each payload type a
//! platform streams has a mirror here: Spin's key-value keys, its sqlite,
//! postgres and mysql rows, and the `result<_, error>` futures that end
//! them. A payload without a mirror is an error that names its type.

use anyhow::{Context, Result, bail};
use wasmtime::AsContextMut;
use wasmtime::component::{ComponentType, FutureReader, Lift, Lower, StreamReader, Type, Val};

/// A Rust type that stands for a WIT type: it says which WIT type it is,
/// and converts a dynamic value of that type.
trait Mirror: Sized + ComponentType + Lower + Lift + Send + Sync + Unpin + 'static {
    fn matches(ty: &Type) -> bool;
    fn from_val(v: &Val) -> Result<Self>;
}

macro_rules! primitive {
    ($($t:ty => $wit:ident),* $(,)?) => {$(
        impl Mirror for $t {
            fn matches(ty: &Type) -> bool {
                matches!(ty, Type::$wit)
            }
            fn from_val(v: &Val) -> Result<Self> {
                match v {
                    Val::$wit(x) => Ok(x.clone()),
                    other => bail!("expected {}, got {other:?}", stringify!($wit)),
                }
            }
        }
    )*};
}

primitive!(bool => Bool, i8 => S8, u8 => U8, i16 => S16, u16 => U16, i32 => S32, u32 => U32, i64 => S64, u64 => U64, f32 => Float32, f64 => Float64, String => String);

impl<T: Mirror> Mirror for Vec<T> {
    fn matches(ty: &Type) -> bool {
        matches!(ty, Type::List(l) if T::matches(&l.ty()))
    }
    fn from_val(v: &Val) -> Result<Self> {
        match v {
            Val::List(xs) => xs.iter().map(T::from_val).collect(),
            other => bail!("expected a list, got {other:?}"),
        }
    }
}

impl<T: Mirror> Mirror for Option<T> {
    fn matches(ty: &Type) -> bool {
        matches!(ty, Type::Option(o) if T::matches(&o.ty()))
    }
    fn from_val(v: &Val) -> Result<Self> {
        match v {
            Val::Option(x) => x.as_deref().map(T::from_val).transpose(),
            other => bail!("expected an option, got {other:?}"),
        }
    }
}

/// `result<_, E>`, how a stream says it ended well or not.
impl<E: Mirror> Mirror for Result<(), E> {
    fn matches(ty: &Type) -> bool {
        matches!(ty, Type::Result(r) if r.ok().is_none() && r.err().is_some_and(|e| E::matches(&e)))
    }
    fn from_val(v: &Val) -> Result<Self> {
        match v {
            Val::Result(Ok(_)) => Ok(Ok(())),
            Val::Result(Err(Some(e))) => Ok(Err(E::from_val(e)?)),
            other => bail!("expected an error value, got {other:?}"),
        }
    }
}

macro_rules! tuple {
    ($(($($t:ident),+)),* $(,)?) => {$(
        impl<$($t: Mirror),+> Mirror for ($($t,)+) {
            fn matches(ty: &Type) -> bool {
                let Type::Tuple(t) = ty else { return false };
                let types: Vec<Type> = t.types().collect();
                let want: &[fn(&Type) -> bool] = &[$($t::matches),+];
                types.len() == want.len() && types.iter().zip(want).all(|(t, m)| m(t))
            }
            fn from_val(v: &Val) -> Result<Self> {
                let Val::Tuple(xs) = v else { bail!("expected a tuple, got {v:?}") };
                let mut xs = xs.iter();
                Ok(($($t::from_val(xs.next().context("a tuple too short")?)?,)+))
            }
        }
    )*};
}

tuple!((A, B), (A, B, C), (A, B, C, D), (A, B, C, D, E, F, G));

macro_rules! record {
    ($name:ident { $($field:ident: $ty:ty = $wit:tt),* $(,)? }) => {
        #[derive(ComponentType, Lower, Lift)]
        #[component(record)]
        #[allow(dead_code)]
        struct $name { $(#[component(name = $wit)] $field: $ty),* }

        impl Mirror for $name {
            fn matches(ty: &Type) -> bool {
                let Type::Record(r) = ty else { return false };
                let fields: Vec<_> = r.fields().collect();
                let want: &[(&str, fn(&Type) -> bool)] = &[$(($wit, <$ty as Mirror>::matches)),*];
                fields.len() == want.len() && fields.iter().zip(want).all(|(f, (n, m))| f.name == *n && m(&f.ty))
            }
            fn from_val(v: &Val) -> Result<Self> {
                let Val::Record(fs) = v else { bail!("expected a record, got {v:?}") };
                let get = |n: &str| fs.iter().find(|(k, _)| k == n).map(|(_, v)| v).with_context(|| format!("no field {n}"));
                Ok(Self { $($field: <$ty as Mirror>::from_val(get($wit)?)?),* })
            }
        }
    };
}

macro_rules! variant {
    ($name:ident { $($case:ident $(($ty:ty))? = $wit:tt),* $(,)? }) => {
        #[derive(ComponentType, Lower, Lift)]
        #[component(variant)]
        #[allow(dead_code)]
        enum $name { $(#[component(name = $wit)] $case $(($ty))?),* }

        impl Mirror for $name {
            fn matches(ty: &Type) -> bool {
                let Type::Variant(v) = ty else { return false };
                let cases: Vec<_> = v.cases().collect();
                let want: &[(&str, Option<fn(&Type) -> bool>)] = &[$(($wit, variant!(@matches $($ty)?))),*];
                cases.len() == want.len()
                    && cases.iter().zip(want).all(|(c, (n, m))| {
                        c.name == *n
                            && match (&c.ty, m) {
                                (None, None) => true,
                                (Some(t), Some(m)) => m(t),
                                _ => false,
                            }
                    })
            }
            #[allow(unused_variables)]
            fn from_val(v: &Val) -> Result<Self> {
                let Val::Variant(case, payload) = v else { bail!("expected a variant, got {v:?}") };
                $(if case == $wit {
                    return Ok(Self::$case $((<$ty as Mirror>::from_val(payload.as_deref().context("a case without its value")?)?))?);
                })*
                bail!("unknown case {case}")
            }
        }
    };
    (@matches) => { None };
    (@matches $ty:ty) => { Some(<$ty as Mirror>::matches as fn(&Type) -> bool) };
}

macro_rules! enumeration {
    ($name:ident { $($case:ident = $wit:tt),* $(,)? }) => {
        #[derive(ComponentType, Lower, Lift, Clone, Copy)]
        #[component(enum)]
        #[repr(u8)]
        #[allow(dead_code)]
        enum $name { $(#[component(name = $wit)] $case),* }

        impl Mirror for $name {
            fn matches(ty: &Type) -> bool {
                let Type::Enum(e) = ty else { return false };
                e.names().eq([$($wit),*])
            }
            fn from_val(v: &Val) -> Result<Self> {
                let Val::Enum(s) = v else { bail!("expected an enum, got {v:?}") };
                $(if s == $wit {
                    return Ok(Self::$case);
                })*
                bail!("unknown case {s}")
            }
        }
    };
}

// spin:key-value@3.0.0: `get-keys` streams strings.
variant!(KvError { StoreTableFull = "store-table-full", NoSuchStore = "no-such-store", AccessDenied = "access-denied", Other(String) = "other" });

// spin:sqlite@3.1.0: `execute-async` streams rows.
variant!(SqliteValue { Integer(i64) = "integer", Real(f64) = "real", Text(String) = "text", Blob(Vec<u8>) = "blob", Null = "null" });
record!(SqliteRow { values: Vec<SqliteValue> = "values" });
variant!(SqliteError {
    NoSuchDatabase = "no-such-database",
    AccessDenied = "access-denied",
    InvalidConnection = "invalid-connection",
    DatabaseFull = "database-full",
    Io(String) = "io",
});

// spin:mysql@3.0.0: `query` streams rows.
variant!(MysqlValue {
    Boolean(bool) = "boolean",
    Int8(i8) = "int8",
    Int16(i16) = "int16",
    Int32(i32) = "int32",
    Int64(i64) = "int64",
    Uint8(u8) = "uint8",
    Uint16(u16) = "uint16",
    Uint32(u32) = "uint32",
    Uint64(u64) = "uint64",
    Floating32(f32) = "floating32",
    Floating64(f64) = "floating64",
    Str(String) = "str",
    Binary(Vec<u8>) = "binary",
    DbNull = "db-null",
    Unsupported = "unsupported",
});
variant!(MysqlError {
    ConnectionFailed(String) = "connection-failed",
    BadParameter(String) = "bad-parameter",
    QueryFailed(String) = "query-failed",
    ValueConversionFailed(String) = "value-conversion-failed",
    Other(String) = "other",
});

// spin:postgres@4.2.0: `query-async` streams rows.
enumeration!(RangeBoundKind { Inclusive = "inclusive", Exclusive = "exclusive" });
record!(Interval { micros: i64 = "micros", days: i32 = "days", months: i32 = "months" });
type Bound<T> = Option<(T, RangeBoundKind)>;
variant!(PgValue {
    Boolean(bool) = "boolean",
    Int8(i8) = "int8",
    Int16(i16) = "int16",
    Int32(i32) = "int32",
    Int64(i64) = "int64",
    Floating32(f32) = "floating32",
    Floating64(f64) = "floating64",
    Str(String) = "str",
    Binary(Vec<u8>) = "binary",
    Date((i32, u8, u8)) = "date",
    Time((u8, u8, u8, u32)) = "time",
    Datetime((i32, u8, u8, u8, u8, u8, u32)) = "datetime",
    Timestamp(i64) = "timestamp",
    Uuid(String) = "uuid",
    Jsonb(Vec<u8>) = "jsonb",
    Decimal(String) = "decimal",
    RangeInt32((Bound<i32>, Bound<i32>)) = "range-int32",
    RangeInt64((Bound<i64>, Bound<i64>)) = "range-int64",
    RangeDecimal((Bound<String>, Bound<String>)) = "range-decimal",
    ArrayInt32(Vec<Option<i32>>) = "array-int32",
    ArrayInt64(Vec<Option<i64>>) = "array-int64",
    ArrayDecimal(Vec<Option<String>>) = "array-decimal",
    ArrayStr(Vec<Option<String>>) = "array-str",
    Interval(Interval) = "interval",
    DbNull = "db-null",
    Unsupported(Vec<u8>) = "unsupported",
});
record!(PgDbError {
    as_text: String = "as-text",
    severity: String = "severity",
    code: String = "code",
    message: String = "message",
    detail: Option<String> = "detail",
    extras: Vec<(String, String)> = "extras",
});
variant!(PgQueryError { Text(String) = "text", DbError(PgDbError) = "db-error" });
variant!(PgError {
    ConnectionFailed(String) = "connection-failed",
    BadParameter(String) = "bad-parameter",
    QueryFailed(PgQueryError) = "query-failed",
    ValueConversionFailed(String) = "value-conversion-failed",
    Other(String) = "other",
});

/// Tries each mirror in turn; the first whose WIT type is `$ty` builds it.
macro_rules! first_match {
    ($ty:expr, |$t:ident| $body:expr; $($mirror:ty),* $(,)?) => {{
        $(if <$mirror as Mirror>::matches($ty) {
            type $t = $mirror;
            return $body;
        })*
    }};
}

/// The stream the app reads: `items` one after the other, then its end.
pub fn stream(mut store: impl AsContextMut, payload: Option<Type>, items: &[Val]) -> Result<Val> {
    let ty = payload.context("appfuzz can't simulate a stream without values")?;
    first_match!(&ty, |T| {
        let items = items.iter().map(T::from_val).collect::<Result<Vec<T>>>()?;
        Ok(Val::Stream(StreamReader::new(&mut store, items)?.try_into_stream_any(&mut store)?))
    }; String, SqliteRow, Vec<MysqlValue>, Vec<PgValue>);
    bail!("appfuzz can't simulate stream<{}> yet", crate::wit::type_str(&ty))
}

/// The future the app awaits, already resolved to `value`.
pub fn future(mut store: impl AsContextMut, payload: Option<Type>, value: &Val) -> Result<Val> {
    let ty = payload.context("appfuzz can't simulate a future without a value")?;
    first_match!(&ty, |T| {
        let value = T::from_val(value)?;
        let ready = std::future::ready(Ok::<_, wasmtime::Error>(value));
        Ok(Val::Future(FutureReader::new(&mut store, ready)?.try_into_future_any(&mut store)?))
    }; Result<(), KvError>, Result<(), SqliteError>, Result<(), MysqlError>, Result<(), PgError>);
    bail!("appfuzz can't simulate future<{}> yet", crate::wit::type_str(&ty))
}
