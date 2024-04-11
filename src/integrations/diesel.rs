use diesel::{
    deserialize::FromSql,
    serialize::ToSql,
    backend::Backend,
    sql_types,
};

use crate::{EncryptedMessage, encryption_type::{Deterministic, Randomized}};

macro_rules! impl_from_and_to_sql {
    ($sql_type:ty, $backend:ty, $encryption_type:ty) => {
        impl FromSql<$sql_type, $backend> for EncryptedMessage<$encryption_type> {
            fn from_sql(value: <$backend as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                let json: serde_json::Value = FromSql::<$sql_type, $backend>::from_sql(value)?;

                Ok(serde_json::from_value(json)?)
            }
        }

        impl ToSql<$sql_type, $backend> for EncryptedMessage<$encryption_type> {
            fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, $backend>) -> diesel::serialize::Result {
                let json = serde_json::to_value(self)?;

                ToSql::<$sql_type, $backend>::to_sql(&json, &mut out.reborrow())
            }
        }
    };
}

#[cfg(feature = "diesel-mysql")]
mod mysql {
    use super::*;

    impl_from_and_to_sql!(sql_types::Json, diesel::mysql::Mysql, Deterministic);
    impl_from_and_to_sql!(sql_types::Json, diesel::mysql::Mysql, Randomized);
}

#[cfg(feature = "diesel-postgres")]
mod postgres {
    use super::*;

    impl_from_and_to_sql!(sql_types::Json, diesel::pg::Pg, Deterministic);
    impl_from_and_to_sql!(sql_types::Json, diesel::pg::Pg, Randomized);

    impl_from_and_to_sql!(sql_types::Jsonb, diesel::pg::Pg, Deterministic);
    impl_from_and_to_sql!(sql_types::Jsonb, diesel::pg::Pg, Randomized);
}
