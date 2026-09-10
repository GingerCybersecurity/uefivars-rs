//! JSON varstore format.
//!
//! Two on-the-wire shapes are accepted:
//!
//! * **v1** — bare array of variable objects.
//! * **v2** — `{"version": 2, "variables": [...]}`.
//!
//! Output always uses v2.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, Result, UefiVar, UefiVarStore};

const CURRENT_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
struct JsonVar {
    name: String,
    data: String,
    guid: Uuid,
    attr: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
}

#[derive(Deserialize)]
struct JsonStoreV2 {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    variables: Vec<JsonVar>,
}

fn default_version() -> u32 {
    CURRENT_VERSION
}

#[derive(Serialize)]
struct JsonStoreOut<'a> {
    version: u32,
    variables: &'a [JsonVar],
}

/// Parse a JSON varstore.
pub fn parse(data: &[u8]) -> Result<UefiVarStore> {
    let value: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| Error::invalid("json", format!("malformed JSON: {e}")))?;

    let raw_vars: Vec<JsonVar> = match value {
        serde_json::Value::Array(_) => serde_json::from_value(value)
            .map_err(|e| Error::invalid("json", format!("v1 array shape: {e}")))?,
        serde_json::Value::Object(_) => {
            let outer: JsonStoreV2 = serde_json::from_value(value)
                .map_err(|e| Error::invalid("json", format!("v2 object shape: {e}")))?;
            if outer.version > CURRENT_VERSION {
                return Err(Error::invalid(
                    "json",
                    format!(
                        "unsupported version {} (max supported: {CURRENT_VERSION})",
                        outer.version
                    ),
                ));
            }
            outer.variables
        }
        _ => {
            return Err(Error::invalid(
                "json",
                "expected object or array at top level",
            ));
        }
    };

    let mut store = UefiVarStore::new();
    for jv in raw_vars {
        store.vars.push(jvar_to_var(jv)?);
    }
    Ok(store)
}

/// Serialize a varstore to JSON (v2, 4-space indent).
pub fn serialize(store: &UefiVarStore) -> Result<Vec<u8>> {
    let encoded: Vec<JsonVar> = store.vars.iter().map(var_to_jvar).collect();
    let out = JsonStoreOut {
        version: CURRENT_VERSION,
        variables: &encoded,
    };

    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    out.serialize(&mut ser)
        .map_err(|e| Error::invalid("json", format!("serialize: {e}")))?;
    Ok(buf)
}

fn jvar_to_var(j: JsonVar) -> Result<UefiVar> {
    let data = hex::decode(&j.data)
        .map_err(|e| Error::invalid("json", format!("variable {:?}: data hex: {e}", j.name)))?;

    let timestamp = j
        .timestamp
        .as_deref()
        .map(|s| {
            let bytes = hex::decode(s).map_err(|e| {
                Error::invalid("json", format!("variable {:?}: timestamp hex: {e}", j.name))
            })?;
            <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| {
                Error::invalid(
                    "json",
                    format!("variable {:?}: timestamp must be 16 bytes", j.name),
                )
            })
        })
        .transpose()?;

    let digest = j
        .digest
        .as_deref()
        .map(|s| {
            hex::decode(s).map_err(|e| {
                Error::invalid("json", format!("variable {:?}: digest hex: {e}", j.name))
            })
        })
        .transpose()?;

    Ok(UefiVar {
        name: j.name,
        data,
        guid: j.guid,
        attr: j.attr,
        timestamp,
        digest,
    })
}

fn var_to_jvar(v: &UefiVar) -> JsonVar {
    JsonVar {
        name: v.name.clone(),
        data: hex::encode(&v.data),
        guid: v.guid,
        attr: v.attr,
        timestamp: v.timestamp.as_ref().map(hex::encode),
        digest: v.digest.as_ref().map(hex::encode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guid;

    fn t02() -> &'static [u8] {
        include_bytes!("../testdata/t02.json")
    }

    fn t01() -> &'static [u8] {
        include_bytes!("../testdata/t01.json")
    }

    #[test]
    fn parses_v2_object_form() {
        let store = parse(t02()).unwrap();
        assert!(!store.vars.is_empty(), "should parse some variables");
        let names: Vec<&str> = store.vars.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"BootOrder"));
        assert!(names.contains(&"MemoryTypeInformation"));
    }

    #[test]
    fn parses_v1_bare_array() {
        let v1 = br#"[
            {"name": "BootOrder",
             "data": "00000100",
             "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c",
             "attr": 7}
        ]"#;
        let store = parse(v1).unwrap();
        assert_eq!(store.vars.len(), 1);
        assert_eq!(store.vars[0].name, "BootOrder");
        assert_eq!(store.vars[0].guid, guid::GLOBAL_VARIABLE);
        assert_eq!(store.vars[0].attr, 7);
        assert_eq!(store.vars[0].data, vec![0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn round_trips_t02() {
        let original = parse(t02()).unwrap();
        let bytes = serialize(&original).unwrap();
        let reparsed = parse(&bytes).unwrap();
        assert_eq!(original, reparsed);
    }

    #[test]
    fn round_trips_t01() {
        let original = parse(t01()).unwrap();
        let bytes = serialize(&original).unwrap();
        let reparsed = parse(&bytes).unwrap();
        assert_eq!(original, reparsed);
    }

    #[test]
    fn round_trips_authenticated_var() {
        let mut store = UefiVarStore::new();
        let mut var = UefiVar::new(
            "PK",
            vec![0xde, 0xad, 0xbe, 0xef],
            guid::GLOBAL_VARIABLE,
            crate::attr::DEFAULT_AUTH,
        );
        var.timestamp = Some([0x11; 16]);
        var.digest = Some(vec![0xaa; 32]);
        store.vars.push(var);

        let bytes = serialize(&store).unwrap();
        let reparsed = parse(&bytes).unwrap();
        assert_eq!(store, reparsed);
    }

    #[test]
    fn rejects_future_version() {
        let bad = br#"{"version": 99, "variables": []}"#;
        let err = parse(bad).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("99"), "error should mention version: {msg}");
    }

    #[test]
    fn rejects_malformed_data_hex() {
        let bad = br#"{"version": 2, "variables": [
            {"name": "x", "data": "zz", "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c", "attr": 0}
        ]}"#;
        assert!(parse(bad).is_err());
    }

    #[test]
    fn rejects_short_timestamp() {
        let bad = br#"{"version": 2, "variables": [
            {"name": "x", "data": "", "guid": "8be4df61-93ca-11d2-aa0d-00e098032b8c",
             "attr": 0, "timestamp": "1122"}
        ]}"#;
        assert!(parse(bad).is_err());
    }
}
