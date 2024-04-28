# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2024-04-28

### Added
- Re-export `secrecy::ExposeSecret` in the `config` module.

### Changed
- `key_config::KeyConfig` has been moved to `config::Config` & is no longer exposed through `lib.rs`. You'll have to use the full path to reach it.
- The encryption strategy is no longer configured on the `EncryptedMessage` itself, but rather inside its `Config` type.

### Removed
- Removed the `utilities::key_decoder` module, as it's out of scope for this library.
- Removed the `utilities::key_generation` module, as it's out of scope for this library.
- Removed the `with_new_payload` & `with_new_payload_and_key_config` methods, as they add no value.

## [0.2.0] - 2024-04-23

First official release.

[Unreleased]: https://github.com/RigoOnRails/encrypted-message/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/RigoOnRails/encrypted-message/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/RigoOnRails/encrypted-message/releases/tag/v0.2.0
