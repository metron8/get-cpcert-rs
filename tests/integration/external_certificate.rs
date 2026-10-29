use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn extracts_nonexportable_container_with_external_certificate() -> anyhow::Result<()> {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/nonexportable_g2012256");

    let output = Command::new(env!("CARGO_BIN_EXE_get-cpcert"))
        .arg(sample.join("container.000"))
        .arg("--cert")
        .arg(sample.join("certificate.cer"))
        .arg("--password-file")
        .arg(sample.join("password"))
        .output()?;

    assert!(
        output.status.success(),
        "get-cpcert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout)?;
    let expected = fs::read_to_string(sample.join("expected.pem"))?;
    assert_eq!(actual.replace("\r\n", "\n"), expected.replace("\r\n", "\n"));
    Ok(())
}
