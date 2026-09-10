use uuid::Uuid;

/// UEFI variable attribute flags. See UEFI spec §8.2.
pub mod attr {
    pub const NON_VOLATILE: u32 = 0x0000_0001;
    pub const BOOTSERVICE_ACCESS: u32 = 0x0000_0002;
    pub const RUNTIME_ACCESS: u32 = 0x0000_0004;
    pub const HARDWARE_ERROR_RECORD: u32 = 0x0000_0008;
    /// Deprecated by the UEFI spec; kept for round-tripping legacy stores.
    pub const AUTHENTICATED_WRITE_ACCESS: u32 = 0x0000_0010;
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x0000_0020;
    pub const APPEND_WRITE: u32 = 0x0000_0040;
    pub const ENHANCED_AUTHENTICATED_ACCESS: u32 = 0x0000_0080;

    /// NV + BS + RT + time-based auth — typical for Secure Boot variables.
    pub const DEFAULT_AUTH: u32 =
        NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
}

/// Well-known UEFI variable GUIDs.
pub mod guid {
    use uuid::{uuid, Uuid};

    /// `EFI_GLOBAL_VARIABLE_GUID` — owns `PK`, `KEK`, `BootOrder`, etc.
    pub const GLOBAL_VARIABLE: Uuid = uuid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");

    /// `EFI_IMAGE_SECURITY_DATABASE_GUID` — owns `db`, `dbx`, `dbt`, `dbr`.
    pub const IMAGE_SECURITY_DATABASE: Uuid = uuid!("d719b2cb-3d3a-4596-a3bc-dad00e67656f");

    /// EDK2-internal certificate database GUID; identifies the synthetic
    /// `certdb` variable that pairs authenticated variables with their
    /// public-key digests.
    pub const EDK2_CERT_DB: Uuid = uuid!("d9bee56e-75dc-49d9-b4d7-b534210f637a");

    /// Firmware Volume GUID for the OVMF NVRAM filesystem.
    pub const EDK2_NVFS: Uuid = uuid!("fff12b8d-7696-4c8b-a985-2747075b4f50");

    /// EDK2 variable store GUID.
    pub const EDK2_VARSTORE: Uuid = uuid!("aaf32c78-947b-439a-a180-2e144ec37792");
}

/// A single UEFI variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UefiVar {
    pub name: String,
    pub data: Vec<u8>,
    pub guid: Uuid,
    pub attr: u32,
    /// Auth-write timestamp (16 bytes, UEFI `EFI_TIME`). Only set when
    /// `attr` includes `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`.
    pub timestamp: Option<[u8; 16]>,
    /// Public-key digest associated with the authenticated write that last
    /// updated this variable. EDK2 stores this out-of-band in a synthetic
    /// `certdb` variable; preserved here to round-trip across formats.
    pub digest: Option<Vec<u8>>,
}

impl UefiVar {
    pub fn new(name: impl Into<String>, data: impl Into<Vec<u8>>, guid: Uuid, attr: u32) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
            guid,
            attr,
            timestamp: None,
            digest: None,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.attr & attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0
    }
}

/// A collection of UEFI variables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UefiVarStore {
    pub vars: Vec<UefiVar>,
}

impl UefiVarStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find the index of a variable by `(name, guid)`.
    pub fn find(&self, name: &str, guid: Uuid) -> Option<usize> {
        self.vars
            .iter()
            .position(|v| v.name == name && v.guid == guid)
    }

    /// Replace the variable with the same `(name, guid)` if present, otherwise
    /// append. Returns the resulting index.
    pub fn replace_or_insert(&mut self, var: UefiVar) -> usize {
        match self.find(&var.name, var.guid) {
            Some(idx) => {
                self.vars[idx] = var;
                idx
            }
            None => {
                self.vars.push(var);
                self.vars.len() - 1
            }
        }
    }

    /// Replace `PK` with the given EFI Signature List bytes, creating the
    /// variable with default Secure Boot attributes if missing.
    pub fn enroll_pk(&mut self, esl: impl Into<Vec<u8>>) {
        self.replace_or_insert(UefiVar::new(
            "PK",
            esl,
            guid::GLOBAL_VARIABLE,
            attr::DEFAULT_AUTH,
        ));
    }

    /// Replace `KEK` with the given EFI Signature List bytes.
    pub fn enroll_kek(&mut self, esl: impl Into<Vec<u8>>) {
        self.replace_or_insert(UefiVar::new(
            "KEK",
            esl,
            guid::GLOBAL_VARIABLE,
            attr::DEFAULT_AUTH,
        ));
    }

    /// Replace `db` with the given EFI Signature List bytes.
    pub fn enroll_db(&mut self, esl: impl Into<Vec<u8>>) {
        self.replace_or_insert(UefiVar::new(
            "db",
            esl,
            guid::IMAGE_SECURITY_DATABASE,
            attr::DEFAULT_AUTH,
        ));
    }

    /// Replace `dbx` with the given EFI Signature List bytes.
    pub fn enroll_dbx(&mut self, esl: impl Into<Vec<u8>>) {
        self.replace_or_insert(UefiVar::new(
            "dbx",
            esl,
            guid::IMAGE_SECURITY_DATABASE,
            attr::DEFAULT_AUTH,
        ));
    }

    /// Append the given EFI Signature List bytes to `db`, creating it with
    /// default Secure Boot attributes if not present. Useful for composing
    /// multiple ESLs (e.g. one cert plus one hash).
    pub fn append_to_db(&mut self, esl: &[u8]) {
        self.append_to_secdb("db", guid::IMAGE_SECURITY_DATABASE, esl);
    }

    /// Like `append_to_db` but for `dbx`.
    pub fn append_to_dbx(&mut self, esl: &[u8]) {
        self.append_to_secdb("dbx", guid::IMAGE_SECURITY_DATABASE, esl);
    }

    fn append_to_secdb(&mut self, name: &str, guid: Uuid, esl: &[u8]) {
        match self.find(name, guid) {
            Some(idx) => self.vars[idx].data.extend_from_slice(esl),
            None => self.vars.push(UefiVar::new(
                name.to_string(),
                esl.to_vec(),
                guid,
                attr::DEFAULT_AUTH,
            )),
        }
    }

    /// Generate an ephemeral RSA-2048 self-signed cert and install it as PK.
    /// The private key is destroyed inside the call — see
    /// [`crate::secboot::generate_ephemeral_cert_der`]. Returns an audit
    /// report (cert SHA-256 + owner GUID).
    pub fn enroll_ephemeral_pk(&mut self) -> crate::Result<EphemeralReport> {
        self.enroll_ephemeral("PK", guid::GLOBAL_VARIABLE)
    }

    /// Like `enroll_ephemeral_pk` but for KEK.
    pub fn enroll_ephemeral_kek(&mut self) -> crate::Result<EphemeralReport> {
        self.enroll_ephemeral("KEK", guid::GLOBAL_VARIABLE)
    }

    fn enroll_ephemeral(&mut self, name: &str, guid: Uuid) -> crate::Result<EphemeralReport> {
        use sha2::Digest;
        let subject = format!("uefivars ephemeral {name}");
        let cert_der = crate::secboot::generate_ephemeral_cert_der(&subject)?;
        let cert_sha256: [u8; 32] = sha2::Sha256::digest(&cert_der).into();
        let owner = Uuid::new_v4();
        let esl = crate::secboot::cert_esl_x509(&cert_der, owner);
        self.replace_or_insert(UefiVar::new(name, esl, guid, attr::DEFAULT_AUTH));
        Ok(EphemeralReport { cert_sha256, owner })
    }
}

/// Audit information returned by `enroll_ephemeral_pk` / `enroll_ephemeral_kek`.
#[derive(Debug, Clone)]
pub struct EphemeralReport {
    /// SHA-256 of the ephemeral certificate's DER encoding.
    pub cert_sha256: [u8; 32],
    /// The random owner GUID embedded in the ESL.
    pub owner: Uuid,
}
