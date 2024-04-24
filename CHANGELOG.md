# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Breaking: Implement the `KeyDecoder` trait for the `HexKeyDecoder` & `Base64KeyDecoder` structs.
  Using the key decoders now requires importing the `KeyDecoder` trait.

## [0.2.0] - 2024-04-23

First official release.

[Unreleased]: https://github.com/RigoOnRails/encrypted-message/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/RigoOnRails/encrypted-message/releases/tag/v0.2.0
