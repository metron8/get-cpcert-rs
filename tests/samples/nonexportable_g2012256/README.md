# Non-exportable GOST-2012-256 key with an external certificate

Disposable test key generated with CryptoPro CSP, provider type 80:

```text
CSP (Type:80) v5.0.10014 KC1 Release Ver:5.0.13700 OS:Linux CPU:AMD64
Container name: cpcert-nonexport-test
Key type: exchange
```

The `container.000/` files and `certificate.cer` are the original supplied
artifacts, without modification. `password` contains the test password
`test123`, without a trailing newline.

## Provider verification

The fixture contributor reported successful header, container, signing,
private/public key signature verification and import checks:

```text
[ErrorCode: 0x00000000]
```

Copying through CryptoPro failed while exporting the private key:

```text
CopyPrivateKey!ExportKey(PRIVATEKEYBLOB, NULL) (:343)
../../../../CSPbuild/CSP/samples/csptest/keycopy.c:331:CopyPrivateKey(AT_KEYEXCHANGE)
Error 0x8009000b: Key not valid for use in specified state.
[ErrorCode: 0x8009000b]
```

These provider checks were run by the contributor, not by the Rust test suite.

## Extraction

From the repository root:

```bash
./target/release/get-cpcert \
  tests/samples/nonexportable_g2012256/container.000 \
  --cert tests/samples/nonexportable_g2012256/certificate.cer \
  --password-file tests/samples/nonexportable_g2012256/password \
  -o /tmp/nonexportable-bundle.pem
```

Extraction with the external certificate succeeded, including verification
of its full public key against the recovered private key. No independently
generated reference private-key PEM is available.

`expected.pem` pins the Rust CLI output after successful verification against
the supplied certificate. It is a regression baseline, not an independent
CryptoPro private-key export.

The container is nested because the generic `tests/integration.rs` discovery
only supports samples with embedded certificates. One dedicated CLI integration
test covers this fixture and compares the complete PEM bundle byte for byte:

```bash
cargo test --test integration extracts_nonexportable_container_with_external_certificate
```
