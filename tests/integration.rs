//! Integration tests against real CryptoPro containers.
//!
//! Layout — drop into `tests/samples/<name>/`:
//!
//!   header.key       (binary, from the container)
//!   primary.key      (binary, from the container)
//!   masks.key        (binary, from the container)
//!   password         (text — exactly the password, no trailing newline;
//!                     empty file means empty password)
//!   expected.pem     (text — the reference PEM produced by the original
//!                     `get-cpcert` C utility)
//!
//! The test prints a friendly skip-message when there are no samples; this
//! way `cargo test` stays green in environments without test data (e.g.
//! sandboxed CI without network access to the upstream release tarball).
//!
//! When samples *are* present, each one becomes a sub-test; the whole
//! suite must produce a byte-for-byte match against `expected.pem`.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use get_cpcert::extract;

#[path = "integration/external_certificate.rs"]
mod external_certificate;

fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("samples")
}

fn list_samples() -> Vec<PathBuf> {
    let root = samples_dir();
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    let entries = match fs::read_dir(&root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if !path.is_dir() {
            continue;
        }
        // A directory counts as a sample if it has header.key plus
        // either primary*.key and masks*.key (we support both unsuffixed
        // and the "2" variant).
        let has_primary = path.join("primary.key").is_file() || path.join("primary2.key").is_file();
        let has_masks = path.join("masks.key").is_file() || path.join("masks2.key").is_file();
        if path.join("header.key").is_file() && has_primary && has_masks {
            out.push(path);
        }
    }
    out.sort();
    out
}

fn read_password(dir: &Path) -> String {
    let pwd_path = dir.join("password");
    match fs::read_to_string(pwd_path) {
        Ok(s) => s.trim_end_matches(['\r', '\n']).to_string(),
        // Default = empty password if file is missing.
        Err(_) => String::new(),
    }
}

fn label(dir: &Path) -> String {
    dir.file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("<unknown>")
        .to_string()
}

#[test]
fn samples_extract_correctly() {
    let samples = list_samples();
    if samples.is_empty() {
        eprintln!(
            "\n  [SKIP] No samples found in tests/samples/.\n  \
             To run end-to-end checks, fetch get-cpcert-bin.tar.gz from the\n  \
             original release page and place each sample container as\n  \
             tests/samples/<name>/{{header.key, primary.key, masks.key, \
             password, expected.pem}}.\n"
        );
        return;
    }

    let mut failures = Vec::new();

    for sample in &samples {
        let name = label(sample);
        let password = read_password(sample);
        let expected_path = sample.join("expected.pem");

        let actual = match extract(sample, &password) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("[{name}] extract failed: {e}"));
                continue;
            }
        };

        // If there's no expected.pem we just smoke-test that extraction
        // didn't blow up.  Print the output so the user can save it as
        // the reference once they're satisfied it's correct.
        let expected = match fs::read_to_string(&expected_path) {
            Ok(s) => s,
            Err(_) => {
                eprintln!(
                    "[{name}] no expected.pem — extracted successfully \
                     ({} bytes); save the printed PEM as expected.pem \
                     to pin it.",
                    actual.len()
                );
                continue;
            }
        };

        // Normalize line endings before comparison — original utility
        // emits LF on Linux.
        let normalize = |s: &str| s.replace("\r\n", "\n");
        if normalize(&actual) != normalize(&expected) {
            failures.push(format!(
                "[{name}] PEM mismatch:\n--- expected (first 200 bytes) ---\n{}\n\
                 --- actual (first 200 bytes) ---\n{}\n",
                expected.chars().take(200).collect::<String>(),
                actual.chars().take(200).collect::<String>(),
            ));
        } else {
            eprintln!("[{name}] OK ({} bytes)", actual.len());
        }
    }

    if !failures.is_empty() {
        for f in &failures {
            eprintln!("{f}");
        }
        panic!("{} sample(s) failed", failures.len());
    }
}

#[test]
fn samples_directory_layout_helper() {
    // Sanity check that the test scaffolding compiles and the samples
    // directory either is absent or contains only sample-shaped folders.
    let samples = list_samples();
    for s in &samples {
        assert!(
            s.join("header.key").is_file(),
            "{} missing header.key",
            s.display()
        );
        assert!(
            s.join("primary.key").is_file() || s.join("primary2.key").is_file(),
            "{} missing primary[2].key",
            s.display()
        );
        assert!(
            s.join("masks.key").is_file() || s.join("masks2.key").is_file(),
            "{} missing masks[2].key",
            s.display()
        );
    }
}
