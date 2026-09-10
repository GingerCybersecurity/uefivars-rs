//! CLI for converting UEFI variable stores between formats and enrolling
//! Secure Boot keys. Mirrors python-uefivars's flag set.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use uuid::Uuid;

use uefivars::{aws, edk2, json, secboot, UefiVarStore};

#[derive(Parser, Debug)]
#[command(
    name = "uefivars",
    about = "Convert UEFI variable stores between AWS, EDK2/OVMF, and JSON formats."
)]
struct Cli {
    /// Input format: "aws", "edk2", "json", or "none".
    #[arg(short, long)]
    input: String,

    /// Output format: "aws", "edk2", "json" (with optional ",filesize=<KB>").
    #[arg(short, long)]
    output: String,

    /// Input file (stdin if omitted).
    #[arg(short = 'I', long = "inputfile")]
    inputfile: Option<PathBuf>,

    /// Output file (stdout if omitted).
    #[arg(short = 'O', long = "outputfile")]
    outputfile: Option<PathBuf>,

    /// Insert PK from given file (usually PK.esl).
    #[arg(short = 'P', long = "PK", value_name = "FILE")]
    pk: Option<PathBuf>,

    /// Insert KEK from given file (usually KEK.esl).
    #[arg(short = 'K', long = "KEK", value_name = "FILE")]
    kek: Option<PathBuf>,

    /// Insert db from given file (usually db.esl).
    #[arg(short = 'b', long = "db", value_name = "FILE")]
    db: Option<PathBuf>,

    /// Insert dbx from given file (usually dbx.esl).
    #[arg(short = 'x', long = "dbx", value_name = "FILE")]
    dbx: Option<PathBuf>,

    /// Generate an ephemeral RSA-2048 self-signed certificate and install it
    /// as PK. The private key is destroyed inside the program — see the
    /// "immutable varstore" note in the README.
    #[arg(long = "auto-pk", conflicts_with = "pk")]
    auto_pk: bool,

    /// Same as --auto-pk but for KEK.
    #[arg(long = "auto-kek", conflicts_with = "kek")]
    auto_kek: bool,

    /// Append the Authenticode SHA-256 hash of an EFI binary to db.
    /// Can be combined with --db (cert ESL appended first, then the hash).
    #[arg(long = "db-hash", value_name = "EFI_FILE")]
    db_hash: Option<PathBuf>,

    /// Append the Authenticode SHA-256 hash of an EFI binary to dbx.
    #[arg(long = "dbx-hash", value_name = "EFI_FILE")]
    dbx_hash: Option<PathBuf>,

    /// Owner GUID used for synthesized hash ESL entries. Defaults to a
    /// fresh random v4 GUID; pass an explicit value for reproducible output.
    #[arg(long = "hash-owner", value_name = "UUID")]
    hash_owner: Option<Uuid>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let (out_format, out_options) = parse_output_spec(&cli.output)?;

    let mut store = read_input(&cli.input, cli.inputfile.as_deref())?;
    eprintln!("Read {} variables", store.vars.len());

    if cli.auto_pk {
        let report = store.enroll_ephemeral_pk()?;
        eprintln!(
            "auto-pk: enrolled ephemeral PK (cert sha256 {}, owner {})",
            hex::encode(report.cert_sha256),
            report.owner
        );
    } else if let Some(path) = &cli.pk {
        store.enroll_pk(read_esl(path, "PK")?);
    } else if !store.vars.iter().any(is_pk) {
        eprintln!("warning: no PK set; SecureBoot will not be enabled without one");
    }
    if cli.auto_kek {
        let report = store.enroll_ephemeral_kek()?;
        eprintln!(
            "auto-kek: enrolled ephemeral KEK (cert sha256 {}, owner {})",
            hex::encode(report.cert_sha256),
            report.owner
        );
    } else if let Some(path) = &cli.kek {
        store.enroll_kek(read_esl(path, "KEK")?);
    }
    if let Some(path) = &cli.db {
        store.enroll_db(read_esl(path, "db")?);
    }
    if let Some(path) = &cli.dbx {
        store.enroll_dbx(read_esl(path, "dbx")?);
    }
    if let Some(path) = &cli.db_hash {
        let esl = build_hash_esl_for_pe(path, "db-hash", cli.hash_owner)?;
        store.append_to_db(&esl);
    }
    if let Some(path) = &cli.dbx_hash {
        let esl = build_hash_esl_for_pe(path, "dbx-hash", cli.hash_owner)?;
        store.append_to_dbx(&esl);
    }

    let bytes = serialize(&store, out_format, &out_options)?;
    write_output(cli.outputfile.as_deref(), &bytes)?;
    eprintln!("Wrote {} variables", store.vars.len());
    Ok(())
}

fn read_input(format: &str, path: Option<&std::path::Path>) -> Result<UefiVarStore> {
    if format == "none" {
        return Ok(UefiVarStore::new());
    }
    let data = match path {
        Some(p) => fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => {
            eprintln!("Reading uefivars from stdin");
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).context("reading stdin")?;
            buf
        }
    };
    parse(&data, format)
}

fn parse(data: &[u8], format: &str) -> Result<UefiVarStore> {
    match format {
        "aws" => Ok(aws::parse(data)?),
        "edk2" => Ok(edk2::parse(data)?),
        "json" => Ok(json::parse(data)?),
        other => {
            bail!(r#"unknown input format "{other}" (expected "aws", "edk2", "json", or "none")"#)
        }
    }
}

#[derive(Default)]
struct OutputOptions {
    edk2_filesize_kb: Option<u64>,
}

fn parse_output_spec(spec: &str) -> Result<(&str, OutputOptions)> {
    let mut parts = spec.split(',').map(str::trim);
    let format = parts.next().ok_or_else(|| anyhow!("empty output spec"))?;

    let mut opts = OutputOptions::default();
    for opt in parts {
        let (k, v) = opt
            .split_once('=')
            .ok_or_else(|| anyhow!("output option {opt:?} missing '='"))?;
        match k.trim() {
            "filesize" => {
                let kb: u64 = v
                    .trim()
                    .parse()
                    .with_context(|| format!("filesize value {v:?} not a number"))?;
                opts.edk2_filesize_kb = Some(kb);
            }
            other => bail!("unknown output option {other:?}"),
        }
    }
    Ok((format, opts))
}

fn serialize(store: &UefiVarStore, format: &str, opts: &OutputOptions) -> Result<Vec<u8>> {
    match format {
        "aws" => Ok(aws::serialize(store)?),
        "json" => Ok(json::serialize(store)?),
        "edk2" => {
            let mut edk2_opts = edk2::Edk2Options::default();
            if let Some(kb) = opts.edk2_filesize_kb {
                edk2_opts.length = kb
                    .checked_mul(1024)
                    .ok_or_else(|| anyhow!("filesize {kb} KB overflows"))?;
            }
            Ok(edk2::serialize_with(store, &edk2_opts)?)
        }
        other => bail!(r#"unknown output format "{other}" (expected "aws", "edk2", or "json")"#),
    }
}

fn write_output(path: Option<&std::path::Path>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) => fs::write(p, data).with_context(|| format!("writing {}", p.display())),
        None => io::stdout().write_all(data).context("writing stdout"),
    }
}

fn read_esl(path: &std::path::Path, name: &str) -> Result<Vec<u8>> {
    let data =
        fs::read(path).with_context(|| format!("reading {} ESL {}", name, path.display()))?;
    if data.is_empty() {
        bail!("{name} ESL file {} is empty", path.display());
    }
    Ok(data)
}

fn is_pk(v: &uefivars::UefiVar) -> bool {
    v.name == "PK" && v.guid == uefivars::guid::GLOBAL_VARIABLE
}

fn build_hash_esl_for_pe(
    path: &std::path::Path,
    flag: &'static str,
    owner: Option<Uuid>,
) -> Result<Vec<u8>> {
    let bytes =
        fs::read(path).with_context(|| format!("reading --{flag} input {}", path.display()))?;
    let hash = secboot::authenticode_sha256(&bytes)
        .with_context(|| format!("computing Authenticode SHA-256 of {}", path.display()))?;
    let owner = owner.unwrap_or_else(Uuid::new_v4);
    eprintln!(
        "{flag}: {} -> sha256 {} (owner {owner})",
        path.display(),
        hex::encode(hash)
    );
    Ok(secboot::hash_esl_sha256(hash, owner))
}
