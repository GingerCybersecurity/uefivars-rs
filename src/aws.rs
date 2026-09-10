//! AWS UEFI variable blob format.
//!
//! Wire format (after base64 decode):
//!
//! ```text
//! +--------+---------+----------+--------------------+
//! | u64 LE | u32 LE  | u32 LE   |  zlib-compressed   |
//! | magic  | crc32c  | version  |  variable stream   |
//! +--------+---------+----------+--------------------+
//! ```
//!
//! * `magic` = `0x494645554e5a4d41` ("AMZNUEFI" interpreted as little-endian).
//! * `crc32c` covers the version field plus the zlib-compressed bytes.
//! * Zlib stream (with header), using a fixed preset dictionary
//!   (see `aws_v0_dict.bin`).
//!
//! Decompressed entries:
//!
//! ```text
//! u64 LE  nr_entries
//! per entry:
//!   u64 LE size + bytes  : name (UTF-8)
//!   u64 LE size + bytes  : data
//!   16 bytes             : guid (mixed-endian, like Microsoft GUIDs)
//!   u32 LE               : attr
//!   if attr & TIME_BASED_AUTHENTICATED_WRITE_ACCESS:
//!     16 bytes           : timestamp (zero == "no timestamp")
//!     u64 LE size + bytes: digest    (32 zero bytes == "no digest")
//! ```

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use flate2::Compression;
use uuid::Uuid;

use crate::attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
use crate::{Error, Result, UefiVar, UefiVarStore};

const MAGIC: u64 = 0x4946_4555_4e5a_4d41; // "AMZNUEFI" little-endian
const VERSION: u32 = 0;
const EMPTY_TIMESTAMP: [u8; 16] = [0u8; 16];
const EMPTY_DIGEST_LEN: usize = 32;

/// Preset dictionary used by the v0 AWS varstore zlib stream.
///
/// Sourced from python-uefivars (`pyuefivars/aws_v0.py`).
const ZLIB_DICT: &[u8] = include_bytes!("aws_v0_dict.bin");

/// Parse an AWS varstore (base64-encoded blob).
pub fn parse(b64: &[u8]) -> Result<UefiVarStore> {
    let raw = BASE64
        .decode(strip_ascii_whitespace(b64))
        .map_err(|e| Error::invalid("aws", format!("base64 decode: {e}")))?;

    if raw.len() < 16 {
        return Err(Error::invalid(
            "aws",
            format!("blob too short: {} bytes", raw.len()),
        ));
    }

    let magic = u64::from_le_bytes(raw[0..8].try_into().expect("len checked"));
    if magic != MAGIC {
        return Err(Error::invalid(
            "aws",
            format!("expected magic AMZNUEFI, got {magic:#x}"),
        ));
    }
    let crc = u32::from_le_bytes(raw[8..12].try_into().expect("len checked"));

    let actual_crc = crc32c::crc32c(&raw[12..]);
    if actual_crc != crc {
        return Err(Error::invalid(
            "aws",
            format!("crc32c mismatch: header {crc:#x}, computed {actual_crc:#x}"),
        ));
    }

    let version = u32::from_le_bytes(raw[12..16].try_into().expect("len checked"));
    if version != VERSION {
        return Err(Error::invalid(
            "aws",
            format!("unsupported version {version}"),
        ));
    }

    let decompressed = decompress_with_dict(&raw[16..])?;

    let mut r = ByteReader::new(&decompressed);
    let nr_entries = r.read_u64()?;

    let mut store = UefiVarStore::new();
    for _ in 0..nr_entries {
        let name_bytes = r.read_data()?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|e| Error::invalid("aws", format!("variable name UTF-8: {e}")))?
            .to_string();
        let data = r.read_data()?.to_vec();
        let guid = Uuid::from_bytes_le(r.read_array::<16>()?);
        let attr = r.read_u32()?;

        let mut var = UefiVar {
            name,
            data,
            guid,
            attr,
            timestamp: None,
            digest: None,
        };

        if attr & TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
            let ts = r.read_array::<16>()?;
            if ts != EMPTY_TIMESTAMP {
                var.timestamp = Some(ts);
            }
            let digest = r.read_data()?;
            if !is_empty_digest(digest) {
                var.digest = Some(digest.to_vec());
            }
        }

        store.vars.push(var);
    }

    Ok(store)
}

/// Serialize a varstore as an AWS base64 blob.
pub fn serialize(store: &UefiVarStore) -> Result<Vec<u8>> {
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(&(store.vars.len() as u64).to_le_bytes());

    for var in &store.vars {
        write_data(&mut payload, var.name.as_bytes());
        write_data(&mut payload, &var.data);
        payload.extend_from_slice(var.guid.to_bytes_le().as_ref());
        payload.extend_from_slice(&var.attr.to_le_bytes());

        if var.attr & TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
            payload.extend_from_slice(&var.timestamp.unwrap_or(EMPTY_TIMESTAMP));
            let empty_digest = vec![0u8; EMPTY_DIGEST_LEN];
            let digest = var.digest.as_deref().unwrap_or(&empty_digest);
            write_data(&mut payload, digest);
        }
    }

    let zdata = compress_with_dict(&payload)?;

    let mut crc_input = Vec::with_capacity(4 + zdata.len());
    crc_input.extend_from_slice(&VERSION.to_le_bytes());
    crc_input.extend_from_slice(&zdata);
    let crc = crc32c::crc32c(&crc_input);

    let mut out = Vec::with_capacity(16 + zdata.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&zdata);

    Ok(BASE64.encode(out).into_bytes())
}

/// Decompress a zlib stream that uses our preset dictionary.
///
/// We parse the zlib header manually (so we can validate the FDICT bit and
/// dict ID) and then hand the raw DEFLATE body to flate2. That avoids the
/// libz `Z_NEED_DICT` round-trip, which flate2's `Status` enum does not
/// surface.
fn decompress_with_dict(zdata: &[u8]) -> Result<Vec<u8>> {
    // 2-byte zlib header + 4-byte dict ID + raw deflate + 4-byte adler32.
    if zdata.len() < 10 {
        return Err(Error::invalid("aws", "zlib stream too short"));
    }
    let cmf = zdata[0];
    let flg = zdata[1];
    if cmf & 0x0f != 8 {
        return Err(Error::invalid(
            "aws",
            format!("unexpected zlib compression method {:#x}", cmf & 0x0f),
        ));
    }
    if flg & 0x20 == 0 {
        return Err(Error::invalid("aws", "expected FDICT bit in zlib header"));
    }
    if !u16::from_be_bytes([cmf, flg]).is_multiple_of(31) {
        return Err(Error::invalid("aws", "zlib header FCHECK invalid"));
    }

    let dict_id_bytes: [u8; 4] = zdata[2..6].try_into().expect("len checked");
    let dict_id = u32::from_be_bytes(dict_id_bytes);
    let expected_dict_id = adler32(ZLIB_DICT);
    if dict_id != expected_dict_id {
        return Err(Error::invalid(
            "aws",
            format!("dict id {dict_id:#x} != expected {expected_dict_id:#x}"),
        ));
    }

    let body = &zdata[6..zdata.len() - 4];
    let trailer: [u8; 4] = zdata[zdata.len() - 4..].try_into().expect("len checked");
    let expected_payload_adler = u32::from_be_bytes(trailer);

    let mut decompress = flate2::Decompress::new(false);
    decompress
        .set_dictionary(ZLIB_DICT)
        .map_err(|e| Error::invalid("aws", format!("zlib set_dictionary: {e}")))?;
    let mut out: Vec<u8> = Vec::with_capacity(body.len() * 4);
    let mut input_pos: usize = 0;
    loop {
        let prev_total_in = decompress.total_in();
        let prev_total_out = decompress.total_out();
        let status = decompress
            .decompress_vec(
                &body[input_pos..],
                &mut out,
                flate2::FlushDecompress::Finish,
            )
            .map_err(|e| Error::invalid("aws", format!("deflate decompress: {e}")))?;
        input_pos += (decompress.total_in() - prev_total_in) as usize;
        let produced = decompress.total_out() - prev_total_out;
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError => {
                if produced == 0 && input_pos == body.len() {
                    return Err(Error::invalid("aws", "deflate stream truncated"));
                }
                if out.len() == out.capacity() {
                    out.reserve(out.capacity());
                }
            }
        }
    }

    let actual_adler = adler32(&out);
    if actual_adler != expected_payload_adler {
        return Err(Error::invalid(
            "aws",
            format!(
                "decompressed adler32 {actual_adler:#x} != trailer {expected_payload_adler:#x}"
            ),
        ));
    }
    Ok(out)
}

/// Compress with the preset dictionary, emitting a complete zlib stream.
fn compress_with_dict(payload: &[u8]) -> Result<Vec<u8>> {
    let mut compress = flate2::Compress::new(Compression::best(), false);
    compress
        .set_dictionary(ZLIB_DICT)
        .map_err(|e| Error::invalid("aws", format!("zlib set_dictionary: {e}")))?;

    // Upper bound on raw DEFLATE output for `payload.len()` bytes:
    //   payload + 5 bytes per 16 KiB block + a small fixed overhead.
    let mut raw_deflate = Vec::with_capacity(payload.len() + payload.len() / 16384 + 64);
    let status = compress
        .compress_vec(payload, &mut raw_deflate, flate2::FlushCompress::Finish)
        .map_err(|e| Error::invalid("aws", format!("deflate compress: {e}")))?;
    if status != flate2::Status::StreamEnd {
        return Err(Error::invalid(
            "aws",
            format!("deflate did not finish (status {status:?})"),
        ));
    }

    // Zlib header: CMF=0x78 (deflate, 32K window), FLG with FDICT(0x20) and
    // FLEVEL=3 (best, 0xC0). FCHECK chosen so that (CMF<<8 | FLG) % 31 == 0.
    const CMF: u8 = 0x78;
    const FLG_BASE: u8 = 0xE0; // FDICT | FLEVEL=3
    let mut fcheck: u8 = 0;
    while !((u16::from(CMF) << 8) | u16::from(FLG_BASE | fcheck)).is_multiple_of(31) {
        fcheck += 1;
        debug_assert!(fcheck < 32);
    }
    let flg = FLG_BASE | fcheck;

    let dict_id = adler32(ZLIB_DICT);
    let payload_adler = adler32(payload);

    let mut out = Vec::with_capacity(2 + 4 + raw_deflate.len() + 4);
    out.push(CMF);
    out.push(flg);
    out.extend_from_slice(&dict_id.to_be_bytes());
    out.extend_from_slice(&raw_deflate);
    out.extend_from_slice(&payload_adler.to_be_bytes());
    Ok(out)
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn write_data(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
}

fn is_empty_digest(digest: &[u8]) -> bool {
    digest.len() == EMPTY_DIGEST_LEN && digest.iter().all(|&b| b == 0)
}

fn strip_ascii_whitespace(b: &[u8]) -> Vec<u8> {
    b.iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn ensure(&self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            Err(Error::invalid(
                "aws",
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

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.ensure(N)?;
        let s = &self.buf[self.pos..self.pos + N];
        self.pos += N;
        Ok(s.try_into().expect("len checked"))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_data(&mut self) -> Result<&'a [u8]> {
        let n = self.read_u64()? as usize;
        self.ensure(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{guid, json};

    fn t02_aws() -> &'static [u8] {
        include_bytes!("../testdata/t02.aws")
    }

    fn t02_json() -> &'static [u8] {
        include_bytes!("../testdata/t02.json")
    }

    #[test]
    fn parses_t02_aws() {
        let store = parse(t02_aws()).unwrap();
        assert!(!store.vars.is_empty());
    }

    #[test]
    fn aws_matches_json_oracle() {
        let from_aws = parse(t02_aws()).unwrap();
        let from_json = json::parse(t02_json()).unwrap();
        assert_eq!(from_aws, from_json, "AWS and JSON parses diverged");
    }

    #[test]
    fn round_trips_t02_aws() {
        let original = parse(t02_aws()).unwrap();
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
    fn round_trips_unauthenticated_var() {
        let mut store = UefiVarStore::new();
        store.vars.push(UefiVar::new(
            "BootOrder",
            vec![0x00, 0x00, 0x01, 0x00],
            guid::GLOBAL_VARIABLE,
            0x07,
        ));
        let bytes = serialize(&store).unwrap();
        let reparsed = parse(&bytes).unwrap();
        assert_eq!(store, reparsed);
    }

    #[test]
    fn rejects_bad_magic() {
        let bogus = BASE64.encode(b"NOTAMZNUEFI....").into_bytes();
        assert!(parse(&bogus).is_err());
    }

    #[test]
    fn rejects_bad_crc() {
        let mut bytes = BASE64
            .decode(
                t02_aws()
                    .iter()
                    .copied()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        bytes[8] ^= 0x01;
        let mangled = BASE64.encode(bytes).into_bytes();
        let err = parse(&mangled).unwrap_err();
        assert!(err.to_string().contains("crc32c"));
    }
}
