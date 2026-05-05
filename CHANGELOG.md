## Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-05-05

### Fixed
- **JWS serialization now conforms to DIDComm v2.** The spec ([signature.md](https://github.com/decentralized-identity/didcomm-messaging/blob/master/docs/spec-files/signature.md)) states: "When transmitted in a normal JWM fashion, the JSON Serialization MUST be used … Message recipients MUST be able to process both [general and flattened] forms." Pre-v0.4.0 emitted JWS in compact serialization (non-conforming) and refused JSON-serialized JWS on `Unpack` (also non-conforming).
- `cli.DetectContentType` no longer mislabels compact JWS/JWE as `application/didcomm-*+json`. The `+json` suffix per RFC 6839 §3.1 specifically signals JSON serialization, so compact data now returns `application/jose` (the RFC 7515/7516 media type for compact JOSE). DIDComm v2 mandates JSON serialization for transmission, so this only affects users feeding compact JOSE through the CLI's `--send` flag.

### Added
- `cli.ContentTypeJOSE = "application/jose"` constant for compact JOSE.
- `Unpack` and `DetectContentType` recognize JWS JSON serialization in both flattened (`payload`+`signature`) and general (`payload`+`signatures[]`) forms.

### Changed
- `PackSigned` and the inner JWS of `PackAuthcrypt` now emit JSON serialization by default (jwx flattened form for the single-signer case, valid per spec). Compact-serialized JWS produced by other implementations continues to verify on the unpack side — only the pack-side default changed.
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
