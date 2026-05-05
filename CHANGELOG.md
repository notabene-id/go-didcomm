## Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-05-05

### Added
- JWS JSON serialization is now produced by default by `PackSigned` and by the inner JWS of `PackAuthcrypt`, matching JWE behavior (#TBD).
- `Unpack` and `cli.DetectContentType` now recognize JWS JSON serialization (both flattened and general forms) in addition to compact serialization.

### Changed
- `signMessage` calls `jws.WithJSON()` by default. Existing compact-serialized JWS envelopes produced elsewhere continue to verify and unpack — only the pack-side default has changed.
- `cmd/didcomm` CLI version bumped to `0.4.0`.

## [0.3.0] - 2026-03-25

### Added
- `did resolve` CLI command and support for string references in DID documents.
- Pre-push checklist in `CLAUDE.md`.

### Changed
- JWE pack output now defaults to JSON serialization (required for multi-recipient, preferred for consistency).
- HTTP error logging improved on `--send`.

## [0.2.0] - 2026-03-01

### Added
- Exported `cli/` package so external tools (e.g. `tap-go`) can reuse the CLI utilities.

### Removed
- Unused wrappers flagged by the linter.

## [0.1.0] - 2026-02-27

### Added
- Initial DIDComm v2 messaging library: `PackSigned` (JWS), `PackAnoncrypt` (JWE), `PackAuthcrypt` (sign-then-encrypt), and `Unpack` with auto-detection.
- `did:key` and `did:web` generation and resolution; `MultiResolver` and `DefaultResolver()`.
- `cmd/didcomm` CLI with `did generate-key`, `did generate-web`, `pack`, `unpack`, and `send` commands; `--send` flag resolves the recipient's `DIDCommMessaging` service endpoint.
- `SecretsResolver` interface and in-memory implementation.
- GitHub Actions CI with linting and tests.

[Unreleased]: https://github.com/Notabene-id/go-didcomm/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Notabene-id/go-didcomm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Notabene-id/go-didcomm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Notabene-id/go-didcomm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Notabene-id/go-didcomm/releases/tag/v0.1.0
