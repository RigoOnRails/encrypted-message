use diesel::{
    deserialize::FromSql,
    serialize::ToSql,
    backend::Backend,
    sql_types,
};

use crate::message::EncryptedMessage;

macro_rules! impl_from_and_to_sql {
    ($sql_type:ty, $backend:ty) => {
        impl FromSql<$sql_type, $backend> for EncryptedMessage {
            fn from_sql(value: <$backend as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                let json: serde_json::Value = FromSql::<$sql_type, $backend>::from_sql(value)?;

                Ok(serde_json::from_value(json)?)
            }
        }

        impl ToSql<$sql_type, $backend> for EncryptedMessage {
            fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, $backend>) -> diesel::serialize::Result {
                let json = serde_json::to_value(self)?;

                ToSql::<$sql_type, $backend>::to_sql(&json, &mut out.reborrow())
            }
        }
    };
}

#[cfg(all(feature = "diesel", feature = "diesel-mysql"))]
impl_from_and_to_sql!(sql_types::Json, diesel::mysql::Mysql);

#[cfg(all(feature = "diesel", feature = "diesel-postgres"))]
impl_from_and_to_sql!(sql_types::Json, diesel::pg::Pg);

#[cfg(all(feature = "diesel", feature = "diesel-postgres"))]
impl_from_and_to_sql!(sql_types::Jsonb, diesel::pg::Pg);
