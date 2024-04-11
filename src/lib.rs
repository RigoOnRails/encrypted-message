mod integrations;

pub mod encryption_type;
use encryption_type::EncryptionType;

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// The JSON format of an encrypted column.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Json))]
#[cfg_attr(all(feature = "diesel", feature = "diesel-postgres"), diesel(sql_type = diesel::sql_types::Jsonb))]
pub struct EncryptedMessage<T: EncryptionType> {
    /// The base64-encoded & encrypted payload.
    p: String,

    /// The headers stored with the encrypted payload.
    h: EncryptedMessageHeaders,

    /// The encryption type used to encrypt the payload.
    _encryption_type: PhantomData<T>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct EncryptedMessageHeaders {
    /// The base64-encoded nonce used to encrypt the payload.
    iv: String,

    /// The base64-encoded auth tag used to verify the encrypted payload.
    at: String,
}
