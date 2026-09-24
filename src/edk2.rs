//! EDK2 / OVMF flash variable store format.
//!
//! Layout:
//!
//! 1. **Zero vector** (16 bytes of `0x00`)
//! 2. **Firmware Volume header** — file system GUID, total length, signature
//!    `_FVH`, attributes, header length, 16-bit checksum, ext-header offset,
//!    reserved, revision, blockmap.
//! 3. **Variable store header** — varstore GUID, varstore size, status sentinel.
//! 4. **Variable records** — each prefixed with `0x55aa`, 4-byte aligned.
//! 5. **Fault tolerant write (FTW) area** — in the second half of the flash: an
//!    event log block, the FTW working block (with its header), and the spare
//!    area. Everything not written is `0xFF`, erased flash.
//!
//! The firmware treats bytes that are not `0xFF` as data, so free space left
//! as `0x00` has to be reclaimed, and a missing FTW header rebuilt, before it
//! can boot. Under SMM with a secure pflash that takes minutes.
//!
//! Authenticated variables carry a public-key digest in a synthetic `certdb`
//! variable. The digest is round-tripped via `UefiVar::digest`.

use uuid::Uuid;

use crate::guid;
use crate::{Error, Result, UefiVar, UefiVarStore};

const ZERO_VECTOR: [u8; 16] = [0u8; 16];
const FVH_SIGNATURE: &[u8; 4] = b"_FVH";
const FVH_REVISION: u8 = 0x02;
const VARSTORE_STATUS: [u8; 8] = [0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const STATE_SETTLED: u8 = 0x3f;
const VAR_START_MARKER: u16 = 0x55aa;

const OVMF_BLOCK_SIZE: u64 = 0x1000;

/// The value of erased flash, and so of every byte the store does not use.
const ERASED: u8 = 0xff;

/// The FTW working block: one block, ending where the second half of the flash begins.
const FTW_WORKING_BLOCK_SIZE: u64 = OVMF_BLOCK_SIZE;
/// `EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER`: signature, CRC, state, reserved, queue size.
const FTW_HEADER_SIZE: u64 = 32;
/// The state byte once the header is valid: `WorkingBlockValid` (bit 0) cleared, since flash
/// bits can only be cleared, and `WorkingBlockInvalid` (bit 1) still set.
const FTW_STATE_VALID: u8 = 0xfe;

/// Default total flash size used by OVMF / AAVMF (528 KiB).
pub const DEFAULT_LENGTH: u64 = 540_672;

/// Default FVH attributes — matches OVMF's typical configuration.
const DEFAULT_FVH_ATTRS: u32 = 0x0004_FEFF;

/// Options controlling EDK2 serialization.
#[derive(Debug, Clone)]
pub struct Edk2Options {
    /// Total flash size in bytes. Must be large enough to contain the variables
    /// plus the FV/varstore headers.
    pub length: u64,
}

impl Default for Edk2Options {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
        }
    }
}

/// Parse an EDK2 / OVMF flash image into a variable store.
pub fn parse(data: &[u8]) -> Result<UefiVarStore> {
    let mut r = Reader::new(data);

    if r.read_array::<16>()? != ZERO_VECTOR {
        return Err(Error::invalid("edk2", "missing zero vector at offset 0"));
    }

    let fs_guid = r.read_guid()?;
    if fs_guid != guid::EDK2_NVFS {
        return Err(Error::invalid(
            "edk2",
            format!("unexpected NVFS GUID {fs_guid}"),
        ));
    }

    let length = r.read_u64()?;
    if length as usize > data.len() {
        return Err(Error::invalid(
            "edk2",
            format!("declared length {length} exceeds input size {}", data.len()),
        ));
    }

    let sig = r.read_array::<4>()?;
    if &sig != FVH_SIGNATURE {
        return Err(Error::invalid(
            "edk2",
            format!("invalid FVH signature {sig:?}"),
        ));
    }

    let _attrs = r.read_u32()?;
    let hlength = r.read_u16()?;
    let _csum = r.read_u16()?;

    if hlength as usize > data.len() {
        return Err(Error::invalid("edk2", "header length exceeds input"));
    }
    if csum16(&data[..hlength as usize]) != 0 {
        return Err(Error::invalid("edk2", "FVH checksum mismatch"));
    }

    let ext_hdr_offset = r.read_u16()?;
    if ext_hdr_offset != 0 {
        return Err(Error::invalid("edk2", "extension header not supported"));
    }

    let reserved = r.read_u8()?;
    if reserved != 0 {
        return Err(Error::invalid("edk2", "FVH reserved byte must be zero"));
    }

    let rev = r.read_u8()?;
    if rev != FVH_REVISION {
        return Err(Error::invalid("edk2", format!("FVH revision {rev:#x}")));
    }

    let mut total_blockmap_bytes: u64 = 0;
    loop {
        let count = r.read_u32()? as u64;
        let bytes = r.read_u32()? as u64;
        if count == 0 && bytes == 0 {
            break;
        }
        total_blockmap_bytes += count * bytes;
    }
    if total_blockmap_bytes != length {
        return Err(Error::invalid(
            "edk2",
            format!("blockmap totals {total_blockmap_bytes}, declared length {length}"),
        ));
    }

    if r.pos != hlength as usize {
        return Err(Error::invalid(
            "edk2",
            format!(
                "header length {hlength} does not match parser position {}",
                r.pos
            ),
        ));
    }

    let vs_guid = r.read_guid()?;
    if vs_guid != guid::EDK2_VARSTORE {
        return Err(Error::invalid(
            "edk2",
            format!("unexpected varstore GUID {vs_guid}"),
        ));
    }
    let _varsize = r.read_u32()?;
    let status = r.read_array::<8>()?;
    if status != VARSTORE_STATUS {
        return Err(Error::invalid(
            "edk2",
            "unexpected varstore status sentinel",
        ));
    }

    let mut store = UefiVarStore::new();
    let mut certdb: Vec<CertDbEntry> = Vec::new();

    while r.has_remaining() {
        if r.peek_u16().ok() != Some(VAR_START_MARKER) {
            break;
        }
        r.advance(2);

        let state = r.read_u8()?;
        let _reserved = r.read_u8()?;
        let attr = r.read_u32()?;
        let _monotonic = r.read_u64()?;
        let timestamp = r.read_array::<16>()?;
        let _pubkey_idx = r.read_u32()?;
        let name_len = r.read_u32()? as usize;
        let data_len = r.read_u32()? as usize;
        let var_guid = r.read_guid()?;
        let name_bytes = r.read_slice(name_len)?;
        let value = r.read_slice(data_len)?.to_vec();

        if state == STATE_SETTLED {
            let name = decode_utf16le_string(name_bytes, "edk2 variable name")?;
            let timestamp = if timestamp == [0u8; 16] {
                None
            } else {
                Some(timestamp)
            };

            if name == "certdb" && var_guid == guid::EDK2_CERT_DB {
                certdb = parse_certdb(&value)?;
            } else {
                store.vars.push(UefiVar {
                    name,
                    data: value,
                    guid: var_guid,
                    attr,
                    timestamp,
                    digest: None,
                });
            }
        }

        r.align_to(4);
    }

    for entry in certdb {
        if let Some(idx) = store.find(&entry.name, entry.guid) {
            store.vars[idx].digest = Some(entry.digest);
        }
    }

    Ok(store)
}

/// Serialize with default options.
pub fn serialize(store: &UefiVarStore) -> Result<Vec<u8>> {
    serialize_with(store, &Edk2Options::default())
}

/// Serialize a varstore as an EDK2/OVMF flash image.
pub fn serialize_with(store: &UefiVarStore, opts: &Edk2Options) -> Result<Vec<u8>> {
    let length = opts.length;
    if length < 0x1000 {
        return Err(Error::invalid(
            "edk2",
            format!("length {length} too small for any header"),
        ));
    }

    let blockmap = vec![(length / OVMF_BLOCK_SIZE, OVMF_BLOCK_SIZE)];
    if blockmap[0].0 * blockmap[0].1 != length {
        return Err(Error::invalid(
            "edk2",
            format!("length {length} is not a multiple of {OVMF_BLOCK_SIZE}"),
        ));
    }
    let varsize = (length / 2).saturating_sub(8264) as u32;

    let mut buf: Vec<u8> = Vec::with_capacity(length as usize);

    buf.extend_from_slice(&ZERO_VECTOR);
    buf.extend_from_slice(guid::EDK2_NVFS.to_bytes_le().as_ref());
    buf.extend_from_slice(&length.to_le_bytes());
    buf.extend_from_slice(FVH_SIGNATURE);
    buf.extend_from_slice(&DEFAULT_FVH_ATTRS.to_le_bytes());

    let hlength_pos = buf.len();
    buf.extend_from_slice(&[0u8; 2]);
    let csum_pos = buf.len();
    buf.extend_from_slice(&[0u8; 2]);
    buf.extend_from_slice(&[0u8; 3]);
    buf.push(FVH_REVISION);

    for (count, bytes) in &blockmap {
        buf.extend_from_slice(&(*count as u32).to_le_bytes());
        buf.extend_from_slice(&(*bytes as u32).to_le_bytes());
    }
    buf.extend_from_slice(&[0u8; 8]);

    let hlength = buf.len();
    buf[hlength_pos..hlength_pos + 2].copy_from_slice(&(hlength as u16).to_le_bytes());

    let csum = csum16(&buf[..hlength]);
    let csum_fix = (0x1_0000u32.wrapping_sub(csum as u32) & 0xffff) as u16;
    buf[csum_pos..csum_pos + 2].copy_from_slice(&csum_fix.to_le_bytes());

    buf.extend_from_slice(guid::EDK2_VARSTORE.to_bytes_le().as_ref());
    buf.extend_from_slice(&varsize.to_le_bytes());
    buf.extend_from_slice(&VARSTORE_STATUS);

    let certdb = build_certdb_var(&store.vars);
    write_var(&mut buf, &certdb);
    for (idx, var) in store
        .vars
        .iter()
        .enumerate()
        .filter(|(_, v)| v.digest.is_some())
    {
        write_var_with_pubkey_idx(&mut buf, var, idx as u32);
    }
    for var in store.vars.iter().filter(|v| v.digest.is_none()) {
        write_var(&mut buf, var);
    }

    if buf.len() > length as usize {
        return Err(Error::invalid(
            "edk2",
            format!(
                "variables ({} bytes) do not fit into flash size {length}",
                buf.len()
            ),
        ));
    }
    buf.resize(length as usize, ERASED);
    let working_block = (length / 2 - FTW_WORKING_BLOCK_SIZE) as usize;
    buf[working_block..working_block + FTW_HEADER_SIZE as usize]
        .copy_from_slice(&ftw_working_block_header());
    Ok(buf)
}

/// The header OVMF writes when it formats an empty FTW working block. The CRC covers the whole
/// header with the CRC field and the state byte still erased; the valid state is set afterwards.
fn ftw_working_block_header() -> [u8; FTW_HEADER_SIZE as usize] {
    let mut header = [ERASED; FTW_HEADER_SIZE as usize];
    header[..16].copy_from_slice(guid::EDK2_FTW_WORKING_BLOCK.to_bytes_le().as_ref());
    let write_queue_size = FTW_WORKING_BLOCK_SIZE - FTW_HEADER_SIZE;
    header[24..32].copy_from_slice(&write_queue_size.to_le_bytes());
    let crc = crc32(&header);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    header[20] = FTW_STATE_VALID;
    header
}

/// CRC-32 (IEEE 802.3), as EDK2's `CalculateCrc32` computes it.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

fn write_var(buf: &mut Vec<u8>, var: &UefiVar) {
    write_var_with_pubkey_idx(buf, var, 0);
}

fn write_var_with_pubkey_idx(buf: &mut Vec<u8>, var: &UefiVar, pubkey_idx: u32) {
    let name_utf16: Vec<u8> = var
        .name
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    buf.extend_from_slice(&VAR_START_MARKER.to_le_bytes());
    buf.push(STATE_SETTLED);
    buf.push(0);
    buf.extend_from_slice(&var.attr.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&var.timestamp.unwrap_or([0u8; 16]));
    buf.extend_from_slice(&pubkey_idx.to_le_bytes());
    buf.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(var.data.len() as u32).to_le_bytes());
    buf.extend_from_slice(var.guid.to_bytes_le().as_ref());
    buf.extend_from_slice(&name_utf16);
    buf.extend_from_slice(&var.data);

    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

struct CertDbEntry {
    name: String,
    guid: Uuid,
    digest: Vec<u8>,
}

fn parse_certdb(data: &[u8]) -> Result<Vec<CertDbEntry>> {
    let mut r = Reader::new(data);
    let total = r.read_u32()? as usize;
    if total != data.len() {
        return Err(Error::invalid(
            "edk2",
            format!("certdb declared size {total} != actual {}", data.len()),
        ));
    }

    let mut out = Vec::new();
    while r.has_remaining() {
        let guid = r.read_guid()?;
        let _node_size = r.read_u32()?;
        let name_chars = r.read_u32()? as usize;
        let digest_size = r.read_u32()? as usize;
        let name_bytes = r.read_slice(name_chars * 2)?;
        let digest = r.read_slice(digest_size)?.to_vec();
        let name = decode_utf16le_string(name_bytes, "certdb name")?;
        out.push(CertDbEntry { name, guid, digest });
    }
    Ok(out)
}

fn build_certdb_var(vars: &[UefiVar]) -> UefiVar {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0u8; 4]); // size placeholder

    for var in vars.iter().filter(|v| v.digest.is_some()) {
        let digest = var.digest.as_ref().expect("filtered above");
        let name_chars = (var.name.encode_utf16().count() + 1) as u32;
        let name_size_bytes = name_chars as usize * 2;
        let digest_size = digest.len() as u32;
        let entry_size = (16 + 4 + 4 + 4 + name_size_bytes + digest.len()) as u32;

        body.extend_from_slice(var.guid.to_bytes_le().as_ref());
        body.extend_from_slice(&entry_size.to_le_bytes());
        body.extend_from_slice(&name_chars.to_le_bytes());
        body.extend_from_slice(&digest_size.to_le_bytes());
        for c in var.name.encode_utf16().chain(std::iter::once(0u16)) {
            body.extend_from_slice(&c.to_le_bytes());
        }
        body.extend_from_slice(digest);
    }

    let total = body.len() as u32;
    body[..4].copy_from_slice(&total.to_le_bytes());

    UefiVar {
        name: "certdb".into(),
        data: body,
        guid: guid::EDK2_CERT_DB,
        attr: 0x07, // NV | BS | RT
        timestamp: None,
        digest: None,
    }
}

fn csum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum = sum.wrapping_add(u16::from_le_bytes([c[0], c[1]]) as u32);
    }
    if let &[odd] = chunks.remainder() {
        sum = sum.wrapping_add(odd as u32);
    }
    (sum & 0xffff) as u16
}

fn decode_utf16le_string(bytes: &[u8], context: &'static str) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::invalid(
            "edk2",
            format!("{context}: odd byte count {}", bytes.len()),
        ));
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16(&words)
        .map_err(|e| Error::invalid("edk2", format!("{context}: invalid UTF-16: {e}")))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn ensure(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(Error::invalid(
                "edk2",
                format!(
                    "unexpected EOF at offset {} (need {n} bytes, have {})",
                    self.pos,
                    self.buf.len() - self.pos
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        self.ensure(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.read_slice(N)?;
        Ok(s.try_into().expect("slice length checked"))
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    fn peek_u16(&self) -> Result<u16> {
        if self.pos + 2 > self.buf.len() {
            return Err(Error::invalid("edk2", "peek past end"));
        }
        Ok(u16::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
        ]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_guid(&mut self) -> Result<Uuid> {
        Ok(Uuid::from_bytes_le(self.read_array::<16>()?))
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn align_to(&mut self, align: usize) {
        self.pos = (self.pos + align - 1) & !(align - 1);
        if self.pos > self.buf.len() {
            self.pos = self.buf.len();
        }
    }

    fn has_remaining(&self) -> bool {
        self.pos < self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn t02_edk2() -> &'static [u8] {
        include_bytes!("../testdata/t02.edk2")
    }

    fn t02_json() -> &'static [u8] {
        include_bytes!("../testdata/t02.json")
    }

    #[test]
    fn parses_t02_edk2() {
        let store = parse(t02_edk2()).unwrap();
        assert!(!store.vars.is_empty());
        let names: Vec<&str> = store.vars.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"BootOrder"));
        assert!(names.contains(&"MemoryTypeInformation"));
    }

    #[test]
    fn edk2_matches_json_oracle() {
        let from_edk2 = parse(t02_edk2()).unwrap();
        let from_json = json::parse(t02_json()).unwrap();
        assert_eq!(
            from_edk2.vars.len(),
            from_json.vars.len(),
            "variable count diverged"
        );
        for (a, b) in from_edk2.vars.iter().zip(from_json.vars.iter()) {
            assert_eq!(a.name, b.name, "names diverged");
            assert_eq!(a.guid, b.guid, "guids diverged for {}", a.name);
            assert_eq!(a.attr, b.attr, "attrs diverged for {}", a.name);
            assert_eq!(a.data, b.data, "data diverged for {}", a.name);
        }
    }

    #[test]
    fn round_trips_t02_edk2() {
        let original = parse(t02_edk2()).unwrap();
        let bytes = serialize(&original).unwrap();
        let reparsed = parse(&bytes).unwrap();
        assert_eq!(original, reparsed);
    }

    #[test]
    fn round_trips_authenticated_var_with_digest() {
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
    fn free_space_is_erased_flash() {
        let bytes = serialize(&parse(t02_edk2()).unwrap()).unwrap();
        let working_block = (DEFAULT_LENGTH / 2 - FTW_WORKING_BLOCK_SIZE) as usize;
        let header_end = working_block + FTW_HEADER_SIZE as usize;
        // the last variable ends well before the event log that precedes the working block
        assert!(bytes[working_block - 0x1000..working_block]
            .iter()
            .all(|&b| b == ERASED));
        assert!(bytes[header_end..].iter().all(|&b| b == ERASED));
    }

    #[test]
    fn ftw_header_matches_ovmf() {
        // the working block header of Debian and Ubuntu's OVMF_VARS_4M.fd, at 0x41000
        let expected =
            hex::decode("2b29589e687c7d49a0ce6500fd9f1b952caf2c64feffffffe00f000000000000")
                .unwrap();
        let bytes = serialize(&UefiVarStore::new()).unwrap();
        assert_eq!(&bytes[0x41000..0x41020], expected.as_slice());
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn rejects_too_small_length() {
        let store = UefiVarStore::new();
        let err = serialize_with(&store, &Edk2Options { length: 16 }).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn fvh_checksum_verifies() {
        let store = UefiVarStore::new();
        let bytes = serialize(&store).unwrap();
        let hlength = u16::from_le_bytes([bytes[48], bytes[49]]) as usize;
        assert_eq!(csum16(&bytes[..hlength]), 0);
    }
}
