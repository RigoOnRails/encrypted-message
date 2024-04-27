#![cfg(all(feature = "diesel", feature = "diesel-mysql"))]

mod schema;

use diesel::prelude::*;
use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    key_config::Secret,
};

#[derive(Debug, Default)]
struct KeyConfig;
impl encrypted_message::KeyConfig for KeyConfig {
    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct User {
    #[allow(dead_code)]
    id: String,
    json: Option<EncryptedMessage<String, Randomized, KeyConfig>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct UserInsertable {
    id: String,
    json: Option<EncryptedMessage<String, Randomized, KeyConfig>>,
}

#[derive(AsChangeset)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct UserChangeset {
    json: Option<Option<EncryptedMessage<String, Randomized, KeyConfig>>>,
}

#[test]
fn encrypted_message_works() {
    // Attempt to load environment variables from .env.test
    let _ = dotenvy::from_filename(".env.test");

    let database_url = dotenvy::var("MYSQL_DATABASE_URL").expect("MYSQL_DATABASE_URL must be set.");
    let mut connection = MysqlConnection::establish(&database_url).unwrap();

    // Create a new user.
    let id = uuid::Uuid::new_v4().to_string();
    diesel::insert_into(schema::users::table)
        .values(UserInsertable {
            id: id.clone(),
            json: Some(EncryptedMessage::encrypt("Very secret.".to_string()).unwrap()),
        })
        .execute(&mut connection)
        .unwrap();

    // Load the new user from the database.
    let user: User = schema::users::table.find(&id).first(&mut connection).unwrap();

    // Decrypt the user's secrets.
    assert_eq!(user.json.as_ref().unwrap().decrypt().unwrap(), "Very secret.");
}
