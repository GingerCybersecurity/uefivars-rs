# uefivars

Read, write, and convert UEFI variable stores between the AWS, EDK2/OVMF, and
JSON formats, as a Rust library and a single self-contained CLI binary.

## Acknowledgements

This project exists because of
[python-uefivars](https://github.com/awslabs/python-uefivars) by Amazon Web
Services. That library did the hard part: working out the on-disk layouts,
the AWS blob framing, the EDK2 firmware-volume structure, and the awkward
details in between. This code is a direct result of that work. The formats,
the CLI flag set, and the test vectors all follow it closely, and where the
two disagree, python-uefivars is the reference implementation.

I wrote this because I wanted an implementation in Rust, and a single binary I
could drop onto a machine without carrying a Python interpreter and its
dependency tree along with it.

python-uefivars is MIT-licensed, Copyright Amazon.com, Inc. or its affiliates.
The AWS v0 zlib preset dictionary in [`src/aws_v0_dict.bin`](src/aws_v0_dict.bin)
is taken verbatim from it (see below), as are the test vectors in
[`testdata/`](testdata/).

## Install

```bash
cargo install uefivars
```

Or build from a checkout:

```bash
cargo build --release
```

The binary lands at `target/release/uefivars`. The only runtime requirement is
libc. Everything else, including the compression dictionary, is compiled in.

## Usage

Formats are named `aws`, `edk2`, and `json`. Input may also be `none`, which
starts from an empty varstore.

```bash
uefivars -i <format> -o <format> [-I infile] [-O outfile] [options]
```

Input defaults to stdin and output to stdout, so it pipes:

```bash
aws ec2 get-instance-uefi-data --instance-id i-0123456789abcdef0 \
  --query UefiData --output text | uefivars -i aws -o json
```

### Converting

```bash
# AWS blob to JSON, for inspection or scripting
uefivars -i aws -I varstore.aws -o json -O varstore.json

# JSON to EDK2/OVMF flash image
uefivars -i json -I varstore.json -o edk2 -O OVMF_VARS.fd

# EDK2 to AWS blob, ready to pass to ec2 register-image
uefivars -i edk2 -I OVMF_VARS.fd -o aws -O varstore.b64
```

The `edk2` output format accepts a `filesize` option, in KB, to set the total
image size. It defaults to 528 KB (540,672 bytes), matching OVMF's usual
`OVMF_VARS.fd`:

```bash
uefivars -i json -I varstore.json -o edk2,filesize=1024 -O OVMF_VARS.fd
```

### Enrolling Secure Boot keys

PK, KEK, db, and dbx are enrolled from EFI Signature List (`.esl`) files:

```bash
uefivars -i none -o aws -O varstore.b64 \
  -P PK.esl -K KEK.esl -b db.esl -x dbx.esl
```

You can also append the Authenticode SHA-256 of a PE/COFF binary directly to
db or dbx, which is how you authorize (or revoke) one specific EFI image
without issuing a certificate for it:

```bash
uefivars -i aws -I varstore.aws -o aws -O out.b64 \
  --db-hash bootx64.efi \
  --hash-owner 11111111-2222-3333-4444-555555555555
```

`--hash-owner` sets the owner GUID recorded in the synthesized signature list.
It defaults to a fresh random v4 GUID; pass an explicit value when you need
reproducible output.

Note that this is the *Authenticode* hash, not a plain SHA-256 of the file.
The PE checksum field, the certificate-table data-directory entry, and any
appended certificate table are excluded from the digest, per the Microsoft
Authenticode specification. That is the digest UEFI firmware actually compares
against db and dbx.

### Immutable varstores: `--auto-pk` and `--auto-kek`

Secure Boot will not engage without a Platform Key, but for many workloads you
never want to *update* the varstore afterward. You want the exact db and dbx
you shipped, permanently.

`--auto-pk` generates an RSA-2048 self-signed certificate, installs it as PK,
and destroys the private key before the program exits. It is never written to
disk and never leaves the process. `--auto-kek` does the same for KEK.

```bash
uefivars -i none -o aws -O varstore.b64 --auto-pk --auto-kek -b db.esl -x dbx.esl
```

The result is a varstore that is in User Mode, with Secure Boot enforcing and
db and dbx honored, but whose authenticated variables can never be updated by
anyone, because the key needed to sign an update no longer exists. This is a
feature when the varstore is baked into an immutable image, and a footgun if
you later need to rotate db or dbx. In that case, keep a real PK and re-run the
tool to produce a new varstore.

Each ephemeral enrollment prints the certificate's SHA-256 and its owner GUID
to stderr so the run can be audited after the fact:

```
auto-pk: enrolled ephemeral PK (cert sha256 d7dea80c..., owner cdc1c4eb-...)
```

## Library

```toml
[dependencies]
uefivars = { version = "0.1", default-features = false }
```

`default-features = false` drops the CLI dependencies (`clap`, `anyhow`).

```rust
use uefivars::{aws, json};

let mut store = aws::parse(&std::fs::read("varstore.aws")?)?;

for var in &store.vars {
    println!("{} ({}): {} bytes", var.name, var.guid, var.data.len());
}

store.enroll_db(std::fs::read("db.esl")?);
std::fs::write("varstore.json", json::serialize(&store)?)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The core type is [`UefiVarStore`](src/var.rs), a `Vec<UefiVar>` with helpers for
enrollment. Each format lives in its own module, [`aws`](src/aws.rs),
[`edk2`](src/edk2.rs), and [`json`](src/json.rs), with matching `parse` and
`serialize` functions. [`secboot`](src/secboot.rs) holds the Authenticode
hashing and EFI Signature List construction.

## Formats

**`aws`** is the base64-encoded blob returned by
`aws ec2 get-instance-uefi-data`: an `AMZNUEFI` magic, a CRC32C, a version
word, and a zlib stream carrying the variables. The zlib stream uses a fixed
*preset dictionary*, so the blob cannot be decompressed without it. The
dictionary is embedded at [`src/aws_v0_dict.bin`](src/aws_v0_dict.bin),
byte-identical to the `dict` array in python-uefivars's `pyuefivars/aws_v0.py`
(sha256 `b6c4f52acbb0ab9aa415290e6c223af871eaa3d430c96b8116899d994681535b`).
Running `strings` on it turns up fragments of Microsoft and Red Hat Secure Boot
*certificates*. That is expected, and harmless: a compression dictionary is
trained on representative sample data, and representative UEFI variable stores
are mostly Secure Boot payloads. Those certificates are public by design and no
private key material is involved.

**`edk2`** is the OVMF/EDK2 NVRAM flash image (`OVMF_VARS.fd`): firmware volume
header, variable store header, and the packed variable list. Authenticated
variables carry their public-key digests in EDK2's synthetic `certdb` variable,
which this tool unpacks on read and rebuilds on write so digests survive a
round trip through the other formats.

**`json`** is a plain text form for inspection, diffing, and scripting. Both
shapes python-uefivars emits are accepted on input: v1, a bare array of
variable objects, and v2, `{"version": 2, "variables": [...]}`. Output is
always v2.

## Tests

```bash
cargo test
```

29 unit tests covering format round trips, EDK2 header and checksum handling,
Authenticode hashing, and Secure Boot signature-list construction. The vectors
in [`testdata/`](testdata/) come from python-uefivars. `t02.aws`, `t02.edk2`,
and `t02.json` are the same 23 variables in all three formats, which is what
makes cross-format round-trip testing possible. See
[`testdata/NOTICE`](testdata/NOTICE).

## License

MIT. See [LICENSE](LICENSE).

Portions derived from python-uefivars, Copyright Amazon.com, Inc. or its
affiliates, also MIT.
