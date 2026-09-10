//! Secure Boot helpers: Authenticode PE hashing and EFI Signature List
//! construction.
//!
//! The Authenticode hash is the SHA-256 that UEFI firmware compares against
//! entries in `db`/`dbx` when validating a PE image. It is *not* a plain
//! SHA-256 of the file — the PE checksum field, the cert-table data-directory
//! entry, and the appended certificate table itself are excluded, per the
//! Microsoft Authenticode specification.

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use sha2::{Digest, Sha256};
use uuid::{uuid, Uuid};

use crate::{Error, Result};

/// `EFI_CERT_SHA256_GUID` — signature type for SHA-256 image-hash entries.
pub const SIG_TYPE_SHA256: Uuid = uuid!("c1c41626-504c-4092-aca9-41f936934328");

/// `EFI_CERT_X509_GUID` — signature type for DER-encoded X.509 cert entries.
pub const SIG_TYPE_X509: Uuid = uuid!("a5c059a1-94e4-4aa7-87b5-ab155c2bf072");

/// Compute the SHA-256 Authenticode digest of a PE/COFF image.
pub fn authenticode_sha256(pe: &[u8]) -> Result<[u8; 32]> {
    let layout = PeLayout::parse(pe)?;

    let mut hasher = Sha256::new();
    // Hash header in three runs, skipping the 4-byte CheckSum field and the
    // 8-byte Certificate Table data-directory entry. Stop at SizeOfHeaders.
    hasher.update(&pe[..layout.checksum_off]);
    hasher.update(&pe[layout.checksum_off + 4..layout.cert_dir_off]);
    hasher.update(&pe[layout.cert_dir_off + 8..layout.size_of_headers]);

    // Hash sections in ascending PointerToRawData order.
    let mut sections = layout.sections.clone();
    sections.sort_by_key(|s| s.ptr_to_raw);
    let mut sum_of_bytes_hashed = layout.size_of_headers;
    for s in sections {
        let end = s
            .ptr_to_raw
            .checked_add(s.size_of_raw)
            .ok_or_else(|| Error::invalid("authenticode", "section size overflow"))?;
        if end > pe.len() {
            return Err(Error::invalid(
                "authenticode",
                format!(
                    "section [{}..{end}] exceeds file size {}",
                    s.ptr_to_raw,
                    pe.len()
                ),
            ));
        }
        hasher.update(&pe[s.ptr_to_raw..end]);
        sum_of_bytes_hashed = sum_of_bytes_hashed
            .checked_add(s.size_of_raw)
            .ok_or_else(|| Error::invalid("authenticode", "sum_of_bytes_hashed overflow"))?;
    }

    // Hash any tail bytes that weren't part of a section, excluding the
    // certificate table (if present).
    if pe.len() > sum_of_bytes_hashed {
        let tail_len = pe
            .len()
            .checked_sub(layout.cert_table_size)
            .and_then(|e| e.checked_sub(sum_of_bytes_hashed))
            .ok_or_else(|| Error::invalid("authenticode", "negative tail length"))?;
        if tail_len > 0 {
            hasher.update(&pe[sum_of_bytes_hashed..sum_of_bytes_hashed + tail_len]);
        }
    }

    Ok(hasher.finalize().into())
}

/// Generate an ephemeral RSA-2048 self-signed certificate suitable for use as
/// a PK or KEK trust anchor.
///
/// The keypair is created, used to sign the cert, then **dropped before this
/// function returns** — only the DER certificate is returned to the caller.
/// That is the whole point of the "ephemeral" model: no one ever holds the
/// private key, so no one can ever sign authenticated-variable updates after
/// enrollment, making the resulting varstore effectively immutable.
///
/// `subject_cn` is the Subject CommonName on the cert (cosmetic). The cert is
/// valid 2020-01-01 → 2030-01-01; UEFI firmware does not typically enforce
/// certificate dates, but a `NotBefore` in the past defends against firmwares
/// that boot with the clock at epoch.
pub fn generate_ephemeral_cert_der(subject_cn: &str) -> Result<Vec<u8>> {
    let key = KeyPair::generate_for(&PKCS_RSA_SHA256)
        .map_err(|e| Error::invalid("secboot", format!("RSA keygen: {e}")))?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, subject_cn);
    params.distinguished_name = dn;
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2120, 1, 1);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];

    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::invalid("secboot", format!("self-sign: {e}")))?;
    let der = cert.der().to_vec();
    drop(key); // explicit: the private key is gone now
    Ok(der)
}

/// Build an EFI Signature List containing a single DER-encoded X.509
/// certificate.
pub fn cert_esl_x509(cert_der: &[u8], owner: Uuid) -> Vec<u8> {
    const ESL_HEADER_LEN: u32 = 16 + 4 + 4 + 4;
    const OWNER_LEN: u32 = 16;
    let sig_size: u32 = OWNER_LEN + cert_der.len() as u32;
    let list_size: u32 = ESL_HEADER_LEN + sig_size;

    let mut out = Vec::with_capacity(list_size as usize);
    out.extend_from_slice(SIG_TYPE_X509.to_bytes_le().as_ref());
    out.extend_from_slice(&list_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
    out.extend_from_slice(&sig_size.to_le_bytes());
    out.extend_from_slice(owner.to_bytes_le().as_ref());
    out.extend_from_slice(cert_der);
    out
}

/// Build an EFI Signature List containing a single SHA-256 image hash.
///
/// The result is suitable for appending to `db` / `dbx`, or for setting them
/// outright when no other entries are needed.
pub fn hash_esl_sha256(hash: [u8; 32], owner: Uuid) -> Vec<u8> {
    const ESL_HEADER_LEN: u32 = 16 + 4 + 4 + 4; // SigType + 3 u32 fields
    const OWNER_LEN: u32 = 16;
    const HASH_LEN: u32 = 32;
    const SIG_SIZE: u32 = OWNER_LEN + HASH_LEN;
    const LIST_SIZE: u32 = ESL_HEADER_LEN + SIG_SIZE;

    let mut out = Vec::with_capacity(LIST_SIZE as usize);
    out.extend_from_slice(SIG_TYPE_SHA256.to_bytes_le().as_ref());
    out.extend_from_slice(&LIST_SIZE.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
    out.extend_from_slice(&SIG_SIZE.to_le_bytes());
    out.extend_from_slice(owner.to_bytes_le().as_ref());
    out.extend_from_slice(&hash);
    out
}

#[derive(Clone, Copy)]
struct SectionInfo {
    ptr_to_raw: usize,
    size_of_raw: usize,
}

struct PeLayout {
    checksum_off: usize,
    cert_dir_off: usize,
    size_of_headers: usize,
    cert_table_size: usize,
    sections: Vec<SectionInfo>,
}

impl PeLayout {
    fn parse(pe: &[u8]) -> Result<Self> {
        if pe.len() < 64 {
            return Err(Error::invalid(
                "authenticode",
                format!("file shorter than DOS header ({} bytes)", pe.len()),
            ));
        }
        if &pe[0..2] != b"MZ" {
            return Err(Error::invalid("authenticode", "missing MZ magic"));
        }

        let e_lfanew = i32::from_le_bytes(pe[60..64].try_into().expect("len checked"));
        if e_lfanew < 0 {
            return Err(Error::invalid("authenticode", "negative e_lfanew"));
        }
        let pe_sig = e_lfanew as usize;
        if pe_sig + 24 > pe.len() {
            return Err(Error::invalid("authenticode", "PE header out of bounds"));
        }
        if &pe[pe_sig..pe_sig + 4] != b"PE\0\0" {
            return Err(Error::invalid("authenticode", "missing PE signature"));
        }

        let coff = pe_sig + 4;
        let num_sections =
            u16::from_le_bytes(pe[coff + 2..coff + 4].try_into().expect("len checked")) as usize;
        let size_of_optional =
            u16::from_le_bytes(pe[coff + 16..coff + 18].try_into().expect("len checked")) as usize;
        let opt = coff + 20;
        if opt + size_of_optional > pe.len() || size_of_optional < 68 {
            return Err(Error::invalid(
                "authenticode",
                "optional header out of bounds",
            ));
        }

        let magic = u16::from_le_bytes(pe[opt..opt + 2].try_into().expect("len checked"));
        let is_pe32_plus = match magic {
            0x10b => false,
            0x20b => true,
            _ => {
                return Err(Error::invalid(
                    "authenticode",
                    format!("unknown optional header magic {magic:#x}"),
                ))
            }
        };

        // SizeOfHeaders and CheckSum offsets are the same in PE32 and PE32+:
        //   PE32+ removes BaseOfData (4 bytes) but widens ImageBase by 4 bytes.
        let size_of_headers =
            u32::from_le_bytes(pe[opt + 60..opt + 64].try_into().expect("len checked")) as usize;
        let checksum_off = opt + 64;

        let cert_dir_off = if is_pe32_plus { opt + 144 } else { opt + 128 };
        if cert_dir_off + 8 > opt + size_of_optional {
            return Err(Error::invalid(
                "authenticode",
                "cert table data directory entry out of bounds",
            ));
        }
        let cert_table_size = u32::from_le_bytes(
            pe[cert_dir_off + 4..cert_dir_off + 8]
                .try_into()
                .expect("len checked"),
        ) as usize;

        if size_of_headers > pe.len() {
            return Err(Error::invalid(
                "authenticode",
                format!(
                    "SizeOfHeaders {size_of_headers} exceeds file size {}",
                    pe.len()
                ),
            ));
        }

        let sections_off = opt + size_of_optional;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let sh = sections_off + i * 40;
            if sh + 40 > pe.len() {
                return Err(Error::invalid(
                    "authenticode",
                    "section header out of bounds",
                ));
            }
            let size_of_raw =
                u32::from_le_bytes(pe[sh + 16..sh + 20].try_into().expect("len checked")) as usize;
            let ptr_to_raw =
                u32::from_le_bytes(pe[sh + 20..sh + 24].try_into().expect("len checked")) as usize;
            sections.push(SectionInfo {
                ptr_to_raw,
                size_of_raw,
            });
        }

        Ok(PeLayout {
            checksum_off,
            cert_dir_off,
            size_of_headers,
            cert_table_size,
            sections,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a minimal PE32+ binary with one section. The contents are
    /// arbitrary but the structure is valid enough for our parser.
    fn build_minimal_pe() -> Vec<u8> {
        let mut pe = Vec::with_capacity(0x400);

        // DOS header: MZ + zeros, with e_lfanew at offset 60.
        pe.extend_from_slice(b"MZ");
        pe.resize(60, 0);
        const PE_SIG_OFF: u32 = 0x80;
        pe.extend_from_slice(&PE_SIG_OFF.to_le_bytes());
        pe.resize(PE_SIG_OFF as usize, 0);

        // PE signature
        pe.extend_from_slice(b"PE\0\0");

        // COFF header (20 bytes)
        pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine = x86_64
        pe.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        pe.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        pe.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        const SIZE_OF_OPT: u16 = 0xF0; // 240 bytes (PE32+, all 16 data dirs)
        pe.extend_from_slice(&SIZE_OF_OPT.to_le_bytes());
        pe.extend_from_slice(&0u16.to_le_bytes()); // Characteristics

        let opt_start = pe.len();
        // Optional header (PE32+)
        pe.extend_from_slice(&0x20bu16.to_le_bytes()); // Magic
        pe.push(0); // MajorLinkerVersion
        pe.push(0); // MinorLinkerVersion
        pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfCode
        pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        pe.extend_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
        pe.extend_from_slice(&0u32.to_le_bytes()); // BaseOfCode
                                                   // (PE32+ has no BaseOfData)
        pe.extend_from_slice(&0u64.to_le_bytes()); // ImageBase (8 bytes)
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // SectionAlignment
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        pe.extend_from_slice(&[0u8; 12]); // OS/Image/Subsystem version fields
        pe.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfImage
        const SIZE_OF_HEADERS: u32 = 0x200;
        pe.extend_from_slice(&SIZE_OF_HEADERS.to_le_bytes()); // SizeOfHeaders
        pe.extend_from_slice(&0u32.to_le_bytes()); // CheckSum (will be skipped)
        pe.extend_from_slice(&0u16.to_le_bytes()); // Subsystem
        pe.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
        pe.extend_from_slice(&0u64.to_le_bytes()); // SizeOfStackReserve
        pe.extend_from_slice(&0u64.to_le_bytes()); // SizeOfStackCommit
        pe.extend_from_slice(&0u64.to_le_bytes()); // SizeOfHeapReserve
        pe.extend_from_slice(&0u64.to_le_bytes()); // SizeOfHeapCommit
        pe.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        pe.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        for _ in 0..16 {
            pe.extend_from_slice(&0u32.to_le_bytes()); // VA
            pe.extend_from_slice(&0u32.to_le_bytes()); // Size
        }
        let opt_end = pe.len();
        assert_eq!(opt_end - opt_start, SIZE_OF_OPT as usize);

        // One section header (40 bytes)
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".text");
        pe.extend_from_slice(&name);
        pe.extend_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // VirtualAddress
        pe.extend_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        pe.extend_from_slice(&[0u8; 16]); // relocs/lineno + counts
        pe.extend_from_slice(&0u32.to_le_bytes()); // Characteristics

        // Pad to SizeOfHeaders
        pe.resize(SIZE_OF_HEADERS as usize, 0);

        // Section data (0x100 bytes of distinguishable content)
        for i in 0..0x100u32 {
            pe.push(i as u8);
        }

        pe
    }

    #[test]
    fn esl_layout_is_correct() {
        let owner = uuid!("11111111-2222-3333-4444-555555555555");
        let hash = [0xAA; 32];
        let esl = hash_esl_sha256(hash, owner);

        assert_eq!(esl.len(), 76);
        // SignatureType (16 bytes, bytes_le of EFI_CERT_SHA256_GUID)
        assert_eq!(&esl[0..16], SIG_TYPE_SHA256.to_bytes_le().as_ref());
        // SignatureListSize = 76
        assert_eq!(u32::from_le_bytes(esl[16..20].try_into().unwrap()), 76);
        // SignatureHeaderSize = 0
        assert_eq!(u32::from_le_bytes(esl[20..24].try_into().unwrap()), 0);
        // SignatureSize = 48
        assert_eq!(u32::from_le_bytes(esl[24..28].try_into().unwrap()), 48);
        // SignatureOwner
        assert_eq!(&esl[28..44], owner.to_bytes_le().as_ref());
        // SignatureData = hash
        assert_eq!(&esl[44..76], &hash);
    }

    #[test]
    fn authenticode_hash_is_stable() {
        let pe = build_minimal_pe();
        let h1 = authenticode_sha256(&pe).unwrap();
        let h2 = authenticode_sha256(&pe).unwrap();
        assert_eq!(h1, h2, "hashing must be deterministic");
    }

    #[test]
    fn authenticode_hash_ignores_checksum_field() {
        // The 4-byte CheckSum field at opt+64 must not influence the hash.
        let mut pe = build_minimal_pe();
        let h1 = authenticode_sha256(&pe).unwrap();
        // Locate the CheckSum: pe_sig at 0x80, COFF at 0x84, opt at 0x98, +64 = 0xD8
        let checksum_off = 0x80 + 4 + 20 + 64;
        pe[checksum_off..checksum_off + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let h2 = authenticode_sha256(&pe).unwrap();
        assert_eq!(h1, h2, "CheckSum must not contribute to the hash");
    }

    #[test]
    fn authenticode_hash_changes_when_section_changes() {
        let mut pe = build_minimal_pe();
        let h1 = authenticode_sha256(&pe).unwrap();
        // Mutate one byte in the section data (starts at PointerToRawData = 0x200).
        pe[0x200] ^= 0x01;
        let h2 = authenticode_sha256(&pe).unwrap();
        assert_ne!(h1, h2, "section data must contribute to the hash");
    }

    #[test]
    fn rejects_non_pe() {
        assert!(authenticode_sha256(b"not a PE file").is_err());
    }

    #[test]
    fn ephemeral_cert_is_a_valid_der_sequence() {
        let der = generate_ephemeral_cert_der("test").unwrap();
        // DER X.509 certificates start with a SEQUENCE tag (0x30) and a
        // length field; this is the cheapest structural sanity check.
        assert_eq!(der[0], 0x30, "DER cert must start with a SEQUENCE tag");
        assert!(
            der.len() > 200,
            "RSA-2048 cert should be several hundred bytes, got {}",
            der.len()
        );
    }

    #[test]
    fn ephemeral_certs_are_unique() {
        let a = generate_ephemeral_cert_der("test").unwrap();
        let b = generate_ephemeral_cert_der("test").unwrap();
        assert_ne!(a, b, "each call must produce a fresh keypair and cert");
    }

    #[test]
    fn cert_esl_layout_is_correct() {
        let owner = uuid!("99999999-8888-7777-6666-555544443333");
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // dummy 4-byte "cert"
        let esl = cert_esl_x509(&cert_der, owner);

        let expected_sig_size = 16 + cert_der.len() as u32;
        let expected_list_size = 28 + expected_sig_size;

        assert_eq!(esl.len(), expected_list_size as usize);
        assert_eq!(&esl[0..16], SIG_TYPE_X509.to_bytes_le().as_ref());
        assert_eq!(
            u32::from_le_bytes(esl[16..20].try_into().unwrap()),
            expected_list_size
        );
        assert_eq!(u32::from_le_bytes(esl[20..24].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(esl[24..28].try_into().unwrap()),
            expected_sig_size
        );
        assert_eq!(&esl[28..44], owner.to_bytes_le().as_ref());
        assert_eq!(&esl[44..], &cert_der[..]);
    }
}
