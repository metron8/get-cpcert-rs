// The CLI uses clap/rpassword, which are not available on wasm.  On wasm
// targets we compile a stub `main` that does nothing — the WASM consumer
// is the `get-cpcert-wasm` crate, not this binary.
#![cfg(not(target_family = "wasm"))]

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "get-cpcert",
    version,
    about = "Extract certificate + private key from a CryptoPro 4/5 container or .pfx",
    long_about = "\
Reads either:
  * a CryptoPro container directory (e.g. /path/to/MyKey.000), or
  * a PKCS#12 / .pfx file exported by CryptoPro CSP
       (PBES2 + PBKDF2-HMAC-Streebog256 + GOST 28147-89 CFB)

and writes a PEM bundle (CERTIFICATE + PRIVATE KEY) to stdout, suitable
for use with GOST-enabled OpenSSL 1.1.1 or later.

Supports GOST R 34.10-2001, -2012/256 and -2012/512 containers."
)]
struct Cli {
    /// Path to the container directory (e.g. /path/to/MyKey.000) or to a
    /// `.pfx` / `.p12` file.  Auto-detected by inspecting the path:
    /// directory → CryptoPro container, file → PKCS#12.
    container: PathBuf,

    /// Password. If omitted, the program prompts on the TTY.
    /// (Passing on the CLI exposes it in shell history & process list.)
    #[arg(short, long)]
    password: Option<String>,

    /// Read password from this file instead of prompting.
    #[arg(long, conflicts_with = "password")]
    password_file: Option<PathBuf>,

    /// Write output to this file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// External X.509 certificate (DER or PEM), overriding the container's
    /// embedded certificate. Only valid for a container directory.
    #[arg(long, value_name = "FILE", conflicts_with = "inspect")]
    cert: Option<PathBuf>,

    /// Diagnostic mode: print a structural report of the .pfx file
    /// (OIDs, PBE schemes, salt/iter, bag types, MAC) and exit.
    /// Does NOT decrypt anything and does not require a password.
    /// Only valid when the input is a PFX file (not a container).
    #[arg(long)]
    inspect: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.inspect {
        return run_inspect(&cli.container);
    }

    if cli.cert.is_some() && !cli.container.is_dir() {
        eprintln!("error: --cert only works with a container directory");
        return ExitCode::from(2);
    }

    let certificate = match cli.cert.as_ref().map(std::fs::read).transpose() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error reading --cert file: {e}");
            return ExitCode::from(3);
        }
    };

    let password = match resolve_password(&cli) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let result = if cli.container.is_dir() {
        match certificate {
            Some(bytes) => get_cpcert::extract_with_certificate(&cli.container, &password, &bytes),
            None => get_cpcert::extract(&cli.container, &password),
        }
    } else if cli.container.is_file() {
        match std::fs::read(&cli.container) {
            Ok(bytes) => get_cpcert::extract_from_pfx(&bytes, &password),
            Err(e) => {
                eprintln!("error reading {}: {}", cli.container.display(), e);
                return ExitCode::from(3);
            }
        }
    } else {
        eprintln!(
            "error: {} is neither a directory nor a file",
            cli.container.display()
        );
        return ExitCode::from(2);
    };

    match result {
        Ok(pem) => {
            if let Some(path) = cli.output {
                if let Err(e) = std::fs::write(&path, pem) {
                    eprintln!("error writing {}: {}", path.display(), e);
                    return ExitCode::from(3);
                }
            } else {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                if let Err(e) = handle.write_all(pem.as_bytes()) {
                    eprintln!("error: {e}");
                    return ExitCode::from(3);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

/// `--inspect` handler: read the file, run [`pfx::inspect_pfx`], print to stdout.
/// Returns appropriate exit code.
fn run_inspect(path: &PathBuf) -> ExitCode {
    if !path.is_file() {
        eprintln!(
            "error: --inspect only works on PFX/.p12 files (got {})",
            path.display()
        );
        return ExitCode::from(2);
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error reading {}: {}", path.display(), e);
            return ExitCode::from(3);
        }
    };
    match get_cpcert::pfx::inspect_pfx(&bytes) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("inspect error: {e}");
            ExitCode::from(1)
        }
    }
}

fn resolve_password(cli: &Cli) -> anyhow::Result<String> {
    if let Some(p) = &cli.password {
        return Ok(p.clone());
    }
    if let Some(path) = &cli.password_file {
        let raw = std::fs::read_to_string(path)?;
        // Strip trailing newline, leave everything else (passwords may
        // legitimately contain spaces/quotes).
        return Ok(raw.trim_end_matches(['\r', '\n']).to_string());
    }
    Ok(rpassword::prompt_password("Container password: ")?)
}
