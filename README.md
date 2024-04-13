# `encrypted-message`
[![crates.io](https://img.shields.io/crates/v/encrypted-message?logo=rust)](https://crates.io/crates/encrypted-message)
[![docs.rs](https://img.shields.io/docsrs/encrypted-message?logo=docs.rs)](https://docs.rs/encrypted-message)
[!["Lint & run tests" workflow](https://img.shields.io/github/actions/workflow/status/RigoOnRails/encrypted-message/development.yml?logo=github)](https://github.com/RigoOnRails/encrypted-message/actions/workflows/development.yml)

## Generate your keys
You should use 32-byte strings for your keys & the key derivation salt.

You can generate them with the following:
```bash
openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | cut -c -32
```
