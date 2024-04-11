use std::fmt::Debug;

use diesel::{
    deserialize::FromSql,
    serialize::ToSql,
    backend::Backend,
    sql_types,
};
use serde::Serialize;

use crate::{EncryptedMessage, encryption_type::EncryptionType};

macro_rules! impl_from_and_to_sql {
    ($sql_type:ty, $backend:ty) => {
        impl<P: Serialize + Debug, E: EncryptionType> FromSql<$sql_type, $backend> for EncryptedMessage<P, E> {
            fn from_sql(value: <$backend as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                let json: serde_json::Value = FromSql::<$sql_type, $backend>::from_sql(value)?;

                Ok(serde_json::from_value(json)?)
            }
        }

        impl<P: Serialize + Debug, E: EncryptionType> ToSql<$sql_type, $backend> for EncryptedMessage<P, E> {
            fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, $backend>) -> diesel::serialize::Result {
                let json = serde_json::to_value(self)?;

                ToSql::<$sql_type, $backend>::to_sql(&json, &mut out.reborrow())
            }
        }
    };
}

#[cfg(feature = "diesel-mysql")]
impl_from_and_to_sql!(sql_types::Json, diesel::mysql::Mysql);

#[cfg(feature = "diesel-postgres")]
impl_from_and_to_sql!(sql_types::Json, diesel::pg::Pg);

#[cfg(feature = "diesel-postgres")]
impl_from_and_to_sql!(sql_types::Jsonb, diesel::pg::Pg);
