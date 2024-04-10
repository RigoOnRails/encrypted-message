# sql-encrypt
[![crates.io](https://img.shields.io/crates/v/sql-encrypt.svg)](https://crates.io/crates/sql-encrypt)
[!["Lint & run tests" workflow](https://github.com/RigoOnRails/sql-encrypt/actions/workflows/development.yml/badge.svg)](https://github.com/RigoOnRails/sql-encrypt/actions/workflows/development.yml)

## Generate your keys
You should use 32-byte strings for the primary key, deterministic key, & the key derivation salt.

Run the following to generate them (you'll need OpenSSL installed):
```bash
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | cut -c -32
```
