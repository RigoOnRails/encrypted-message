use std::fmt::Debug;

use diesel::{
    deserialize::FromSql,
    serialize::ToSql,
    backend::Backend,
    expression::AsExpression,
    internal::derives::as_expression::Bound,
    sql_types,
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{EncryptedMessage, config::Config};

macro_rules! impl_from_and_to_sql {
    ($($sql_type:ty, $backend:ty),+ $(,)?) => {
        $(
            impl<P: Debug + DeserializeOwned + Serialize, C: Config> FromSql<$sql_type, $backend> for EncryptedMessage<P, C> {
                fn from_sql(value: <$backend as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                    let json: serde_json::Value = FromSql::<$sql_type, $backend>::from_sql(value)?;

                    Ok(serde_json::from_value(json)?)
                }
            }

            impl<P: Debug + DeserializeOwned + Serialize, C: Config> ToSql<$sql_type, $backend> for EncryptedMessage<P, C> {
                fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, $backend>) -> diesel::serialize::Result {
                    let json = serde_json::to_value(self)?;

                    ToSql::<$sql_type, $backend>::to_sql(&json, &mut out.reborrow())
                }
            }
        )+
    };
}

macro_rules! impl_from_and_to_sql_text {
    ($($backend:ty),+ $(,)?) => {
        $(
            impl<P: Debug + DeserializeOwned + Serialize, C: Config> FromSql<sql_types::Text, $backend> for EncryptedMessage<P, C> {
                fn from_sql(value: <$backend as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                    let text: String = FromSql::<sql_types::Text, $backend>::from_sql(value)?;

                    Ok(serde_json::from_str(&text)?)
                }
            }

            impl<P: Debug + DeserializeOwned + Serialize, C: Config> ToSql<sql_types::Text, $backend> for EncryptedMessage<P, C> {
                fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, $backend>) -> diesel::serialize::Result {
                    let json = serde_json::to_string(self)?;

                    ToSql::<sql_types::Text, $backend>::to_sql(json.as_str(), &mut out.reborrow())
                }
            }
        )+
    };
}

// AsExpression impls allow EncryptedMessage to be used directly in Diesel query
// expressions (e.g. with Insertable, filter, etc.) for Text columns.
#[cfg(any(feature = "diesel-mysql", feature = "diesel-postgres", feature = "diesel-sqlite"))]
impl<P: Debug + DeserializeOwned + Serialize, C: Config> AsExpression<sql_types::Text> for EncryptedMessage<P, C> {
    type Expression = Bound<sql_types::Text, Self>;
    fn as_expression(self) -> Self::Expression { Bound::new(self) }
}

#[cfg(any(feature = "diesel-mysql", feature = "diesel-postgres", feature = "diesel-sqlite"))]
impl<P: Debug + DeserializeOwned + Serialize, C: Config> AsExpression<sql_types::Text> for &EncryptedMessage<P, C> {
    type Expression = Bound<sql_types::Text, Self>;
    fn as_expression(self) -> Self::Expression { Bound::new(self) }
}

#[cfg(any(feature = "diesel-mysql", feature = "diesel-postgres", feature = "diesel-sqlite"))]
impl<P: Debug + DeserializeOwned + Serialize, C: Config> AsExpression<sql_types::Nullable<sql_types::Text>> for EncryptedMessage<P, C> {
    type Expression = Bound<sql_types::Nullable<sql_types::Text>, Self>;
    fn as_expression(self) -> Self::Expression { Bound::new(self) }
}

#[cfg(any(feature = "diesel-mysql", feature = "diesel-postgres", feature = "diesel-sqlite"))]
impl<P: Debug + DeserializeOwned + Serialize, C: Config> AsExpression<sql_types::Nullable<sql_types::Text>> for &EncryptedMessage<P, C> {
    type Expression = Bound<sql_types::Nullable<sql_types::Text>, Self>;
    fn as_expression(self) -> Self::Expression { Bound::new(self) }
}

// ToSql<Nullable<Text>, DB> delegates to ToSql<Text, DB>, always writing IsNull::No.
// This is required for Bound<Nullable<Text>, EncryptedMessage> to work as a QueryFragment.
#[cfg(any(feature = "diesel-mysql", feature = "diesel-postgres", feature = "diesel-sqlite"))]
impl<P: Debug + DeserializeOwned + Serialize, C: Config, DB: Backend> ToSql<sql_types::Nullable<sql_types::Text>, DB> for EncryptedMessage<P, C>
where
    Self: ToSql<sql_types::Text, DB>,
{
    fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, DB>) -> diesel::serialize::Result {
        ToSql::<sql_types::Text, DB>::to_sql(self, out)
    }
}

#[cfg(feature = "diesel-mysql")]
impl_from_and_to_sql!(sql_types::Json, diesel::mysql::Mysql);

#[cfg(feature = "diesel-mysql")]
impl_from_and_to_sql_text!(diesel::mysql::Mysql);

#[cfg(feature = "diesel-postgres")]
impl_from_and_to_sql!(
    sql_types::Json, diesel::pg::Pg,
    sql_types::Jsonb, diesel::pg::Pg,
);

#[cfg(feature = "diesel-postgres")]
impl_from_and_to_sql_text!(diesel::pg::Pg);

#[cfg(feature = "diesel-sqlite")]
impl<P: Debug + DeserializeOwned + Serialize, C: Config> FromSql<sql_types::Text, diesel::sqlite::Sqlite> for EncryptedMessage<P, C> {
    fn from_sql(value: <diesel::sqlite::Sqlite as Backend>::RawValue<'_>) -> diesel::deserialize::Result<Self> {
        let text: String = FromSql::<sql_types::Text, diesel::sqlite::Sqlite>::from_sql(value)?;

        Ok(serde_json::from_str(&text)?)
    }
}

#[cfg(feature = "diesel-sqlite")]
impl<P: Debug + DeserializeOwned + Serialize, C: Config> ToSql<sql_types::Text, diesel::sqlite::Sqlite> for EncryptedMessage<P, C> {
    fn to_sql<'b>(&'b self, out: &mut diesel::serialize::Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
        let json = serde_json::to_string(self)?;
        out.set_value(json);
        Ok(diesel::serialize::IsNull::No)
    }
}
