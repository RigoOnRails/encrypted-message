# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Re-export `secrecy::ExposeSecret` in the `key_config` module.

### Changed

### Removed
- Removed the `utilities::key_decoder` module, as it's out of scope for this library.
- Removed the `with_new_payload` & `with_new_payload_and_key_config` methods as they add no value.

## [0.2.0] - 2024-04-23

First official release.

[Unreleased]: https://github.com/RigoOnRails/encrypted-message/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/RigoOnRails/encrypted-message/releases/tag/v0.2.0
