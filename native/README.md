[English](README.md) | [简体中文](README.zh-CN.md)

# SkyLicense Rust native client

For a working license-verification release, follow the [Basic edition guide](../README.md).
It provides TLS/v4 verification without a native library.

This directory preserves the source formerly stored in `MagicLicense-Client`.
It is now a member of the root Cargo workspace, with one root `Cargo.lock`.
The server, Java SDK and Vue console are maintained in this same repository.

## Compatibility boundary

- `src/lib.rs` currently opens a plain `TcpStream` and sends protocol version 2.
- The current server requires TLS 1.3 and protocol 4, including release identity, challenges and loading ACK.
- The imported source has no matching v4 signed-release workflow or manifests.
- Compiling this crate or passing its unit tests does not prove server compatibility.

Do **not** replace the current SDK's DLL/SO with an artifact from this directory.
The production SDK packaging checks remain enabled. Restoring a matching v4 implementation and
validating Windows/Linux release hardening are separate work; this directory consolidation does not implement them.

## Development

From the repository root, with a Rust toolchain supporting edition 2024:

```sh
cargo test --workspace --locked
cargo check --workspace --locked
```

An optional build of this legacy crate is `cargo build --release --locked`; it is not the supported Basic edition.
Outputs are under root `target/`. GNU Windows linker maps are written to `SkyLicense.map` and ignored by Git.
The release profile is preserved from the original project. No binaries, caches, credentials or nested Git repository are imported.
The original Rust source has been restored from the pre-consolidation backup. The attempted v4 upgrade has been cancelled.
The original tests share global XOR-key state and can interfere when run in parallel; this legacy behavior is also preserved.

The Java Basic package is built independently with `gradlew basicReleaseZip` (Windows: `gradlew.bat`).
See the root [source layout and console instructions](../README.md#source-layout-and-console-development).

Original project attribution: Client of MagicLicense, by pi_ka.
