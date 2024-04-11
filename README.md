# encrypted-message
[![crates.io](https://img.shields.io/crates/v/encrypted-message.svg)](https://crates.io/crates/encrypted-message)
[!["Lint & run tests" workflow](https://github.com/RigoOnRails/encrypted-message/actions/workflows/development.yml/badge.svg)](https://github.com/RigoOnRails/encrypted-message/actions/workflows/development.yml)

## Generate your keys
You should use 32-byte strings for the `Deterministic` key, `Randomized` key, & the key derivation salt.

Run the following to generate them (you'll need OpenSSL installed):
```bash
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | cut -c -32
```
