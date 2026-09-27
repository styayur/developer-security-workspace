//! Streaming SARIF staging. JSON member order is irrelevant; raw secrets never reach staging.
use crate::error::{AppError, AppResult};
use crate::secret_redaction::SecretRedactor;
use rusqlite::{params, Connection};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use serde_json::{Map, Value};
use std::cell::Cell;
use std::collections::HashSet;
use std::fmt;
use std::io::{BufReader, Read};
use std::path::Path;
use std::rc::Rc;
use tokio_util::sync::CancellationToken;

pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_VALUE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProgress {
    pub import_id: String,
    pub phase: String,
    pub processed: usize,
    pub total: Option<usize>,
}

pub fn check_cancel(cancel: &CancellationToken) -> AppResult<()> {
    if cancel.is_cancelled() {
        Err(AppError::Cancelled)
    } else {
        Ok(())
    }
}

pub struct Staged {
    pub(crate) connection: Connection,
    pub(crate) directory: tempfile::TempDir,
    pub header: Value,
    pub count: usize,
    pub runs: usize,
}
impl Staged {
    pub fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("stage.db")
    }
}

struct BudgetReader<R> {
    inner: R,
    count: Rc<Cell<usize>>,
    end: Rc<Cell<usize>>,
    cancel: CancellationToken,
}
impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(std::io::Error::other("Import cancelled"));
        }
        let remaining = self.end.get().saturating_sub(self.count.get());
        if remaining == 0 {
            return Err(std::io::Error::other(
                "SARIF value exceeds the 2 MiB budget",
            ));
        }
        let length = output.len().min(remaining);
        let n = self.inner.read(&mut output[..length])?;
        let count = self.count.get() + n;
        if count as u64 > MAX_FILE_BYTES {
            return Err(std::io::Error::other("SARIF exceeds 1 GiB"));
        }
        self.count.set(count);
        Ok(n)
    }
}
struct Context<'a> {
    db: &'a Connection,
    count: Rc<Cell<usize>>,
    end: Rc<Cell<usize>>,
    metadata: Cell<usize>,
    results: Cell<usize>,
    runs: Cell<usize>,
    progress: &'a dyn Fn(usize),
}
impl Context<'_> {
    fn reset(&self) {
        self.end.set(self.count.get() + MAX_VALUE_BYTES);
    }
    fn metadata<E: Error>(&self, value: &Value) -> Result<(), E> {
        let size = serde_json::to_vec(value).map_err(E::custom)?.len();
        let total = self.metadata.get() + size;
        if total > MAX_METADATA_BYTES {
            return Err(E::custom("SARIF metadata exceeds 8 MiB"));
        }
        self.metadata.set(total);
        Ok(())
    }
}
struct Root<'a>(&'a Context<'a>);
struct Runs<'a>(&'a Context<'a>);
struct Run<'a>(&'a Context<'a>, usize);
struct Results<'a>(&'a Context<'a>, usize);
macro_rules! seed {
    ($name:ident, $method:ident, $value:ty) => {
        impl<'de> DeserializeSeed<'de> for $name<'_> {
            type Value = $value;
            fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                d.$method(self)
            }
        }
    };
}
seed!(Root, deserialize_map, Map<String, Value>);
seed!(Runs, deserialize_seq, ());
seed!(Run, deserialize_map, ());
seed!(Results, deserialize_seq, ());
impl<'de> Visitor<'de> for Root<'_> {
    type Value = Map<String, Value>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SARIF object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut header = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.0.metadata::<A::Error>(&Value::String(key.clone()))?;
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom("Duplicate SARIF member"));
            }
            self.0.reset();
            if key == "runs" {
                map.next_value_seed(Runs(self.0))?;
            } else {
                let value: Value = map.next_value()?;
                self.0.metadata::<A::Error>(&value)?;
                header.insert(key, SecretRedactor::redact_json(&value));
            }
            self.0.reset();
        }
        if header.get("version").and_then(Value::as_str) != Some("2.1.0") {
            return Err(A::Error::custom(
                "Unsupported SARIF version; expected 2.1.0",
            ));
        }
        if self.0.runs.get() == 0 {
            return Err(A::Error::custom("SARIF does not contain any runs"));
        }
        Ok(header)
    }
}
impl<'de> Visitor<'de> for Runs<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SARIF runs array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            self.0.reset();
            let index = self.0.runs.get();
            if seq.next_element_seed(Run(self.0, index))?.is_none() {
                break;
            }
            self.0.runs.set(index + 1);
            if index >= 4096 {
                return Err(A::Error::custom("Too many SARIF runs"));
            }
        }
        Ok(())
    }
}
impl<'de> Visitor<'de> for Run<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SARIF run object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut header = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.0.metadata::<A::Error>(&Value::String(key.clone()))?;
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom("Duplicate run member"));
            }
            self.0.reset();
            if key == "results" {
                map.next_value_seed(Results(self.0, self.1))?;
            } else {
                let value: Value = map.next_value()?;
                self.0.metadata::<A::Error>(&value)?;
                header.insert(key, SecretRedactor::redact_json(&value));
            }
            self.0.reset();
        }
        header.insert("results".into(), Value::Array(Vec::new()));
        let value = Value::Object(header);
        serde_json::from_value::<super::model::SarifRun>(value.clone())
            .map_err(A::Error::custom)?;
        self.0
            .db
            .execute(
                "INSERT INTO runs VALUES(?1,?2)",
                params![self.1, value.to_string()],
            )
            .map_err(A::Error::custom)?;
        Ok(())
    }
}
impl<'de> Visitor<'de> for Results<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SARIF results array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut index = 0usize;
        loop {
            self.0.reset();
            let Some(value) = seq.next_element::<Value>()? else {
                break;
            };
            if !value.is_object() {
                return Err(A::Error::custom("SARIF result must be an object"));
            }
            let result: super::model::SarifResult =
                serde_json::from_value(value.clone()).map_err(A::Error::custom)?;
            let native = super::normalize::native_fingerprint(&result);
            let redacted = SecretRedactor::redact_json(&value);
            self.0
                .db
                .prepare_cached("INSERT INTO results(run,idx,raw,native) VALUES(?1,?2,?3,?4)")
                .map_err(A::Error::custom)?
                .execute(params![self.1, index, redacted.to_string(), native])
                .map_err(A::Error::custom)?;
            index += 1;
            self.0.results.set(self.0.results.get() + 1);
            if self.0.results.get() > 1_000_000 {
                return Err(A::Error::custom("Too many SARIF results"));
            }
            if self.0.results.get().is_multiple_of(256) {
                (self.0.progress)(self.0.results.get());
            }
        }
        Ok(())
    }
}

pub fn stage(
    path: &Path,
    cancel: &CancellationToken,
    progress: &dyn Fn(usize),
) -> AppResult<Staged> {
    check_cancel(cancel)?;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_BYTES {
        return Err(AppError::Sarif(
            "SARIF exceeds the 1 GiB streaming limit".into(),
        ));
    }
    let directory = tempfile::Builder::new().prefix("dsw-import-").tempdir()?;
    let mut connection = Connection::open(directory.path().join("stage.db"))?;
    connection.execute_batch("PRAGMA cache_size=-8192; PRAGMA temp_store=FILE;
        CREATE TABLE runs(idx INTEGER PRIMARY KEY,header TEXT NOT NULL);
        CREATE TABLE results(run INTEGER,idx INTEGER,raw TEXT NOT NULL,native TEXT,PRIMARY KEY(run,idx));
        CREATE TABLE normalized(seq INTEGER PRIMARY KEY,id TEXT UNIQUE,finding TEXT,candidate TEXT);")?;
    let tx = connection.transaction()?;
    let count = Rc::new(Cell::new(0));
    let end = Rc::new(Cell::new(MAX_VALUE_BYTES));
    let context = Context {
        db: &tx,
        count: count.clone(),
        end: end.clone(),
        metadata: Cell::new(0),
        results: Cell::new(0),
        runs: Cell::new(0),
        progress,
    };
    let reader = BudgetReader {
        inner: BufReader::new(file),
        count,
        end,
        cancel: cancel.clone(),
    };
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let parsed = Root(&context)
        .deserialize(&mut deserializer)
        .and_then(|header| {
            deserializer.end()?;
            Ok(header)
        });
    check_cancel(cancel)?;
    let mut header = parsed.map_err(|e| AppError::Sarif(e.to_string()))?;
    let runs = {
        let mut stmt = tx.prepare("SELECT header FROM runs ORDER BY idx")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|r| serde_json::from_str::<Value>(&r))
            .collect::<Result<Vec<_>, _>>()?
    };
    header.insert("runs".into(), Value::Array(runs));
    let count = context.results.get();
    let runs = context.runs.get();
    tx.commit()?;
    Ok(Staged {
        connection,
        directory,
        header: Value::Object(header),
        count,
        runs,
    })
}
