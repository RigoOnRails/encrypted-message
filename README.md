# `encrypted-message`
[![crates.io](https://img.shields.io/crates/v/encrypted-message?logo=rust)](https://crates.io/crates/encrypted-message)
[![docs.rs](https://img.shields.io/docsrs/encrypted-message?logo=docs.rs)](https://docs.rs/encrypted-message)
[!["Lint & run tests" workflow](https://img.shields.io/github/actions/workflow/status/RigoOnRails/encrypted-message/development.yml?logo=github)](https://github.com/RigoOnRails/encrypted-message/actions/workflows/development.yml)
[![License](https://img.shields.io/crates/l/encrypted-message)](./LICENSE)

Safely encrypt & store serializable data using XChaCha20Poly1305.

## Install

```toml
[dependencies]
encrypted-message = "0.3.0"
```

## Integration with Diesel

`EncryptedMessage` implements [`FromSql`](https://docs.diesel.rs/2.1.x/diesel/deserialize/trait.FromSql.html) & [`ToSql`](https://docs.diesel.rs/2.1.x/diesel/serialize/trait.ToSql.html), allowing you to use `EncryptedMessage` as a field type in your models.

- **MySQL**: Enable the `diesel` & `diesel-mysql` features. Supports the [`Json`][diesel-json] type.
- **PostgreSQL**: Enable the `diesel` & `diesel-postgres` features. Supports the [`Json`][diesel-json] & [`Jsonb`][diesel-jsonb] types.

```toml
[dependencies]
encrypted-message = { version = "0.3.0", features = ["diesel", "diesel-<mysql|postgres>"] }
```

## Examples

- [`examples/basic.rs`](./examples/basic.rs), a basic example of how to use `encrypted-message`.
- [`examples/config_with_external_data.rs`](./examples/config_with_external_data.rs), an example of a `Config` that depends on external data, like a user-provided key or password.

## Security

This crate uses trusted, pure-Rust encryption using the [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) crate
from the [Rust Crypto][rust-crypto] organization.

Keys are handled safely using the [`secrecy`](https://crates.io/crates/secrecy) crate,
which internally uses the [`zeroize`](https://crates.io/crates/zeroize) crate (also from [Rust Crypto][rust-crypto])
to zero-out the keys in memory when no longer used.

[diesel-json]: https://docs.diesel.rs/2.1.x/diesel/sql_types/struct.Json.html
[diesel-jsonb]: https://docs.diesel.rs/2.1.x/diesel/sql_types/struct.Jsonb.html

[rust-crypto]: https://github.com/RustCrypto
