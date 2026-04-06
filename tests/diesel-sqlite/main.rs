#![cfg(all(feature = "diesel", feature = "diesel-sqlite"))]

mod schema;

use diesel::prelude::*;
use diesel::connection::SimpleConnection;
use encrypted_message::{
    EncryptedMessage,
    strategy::Randomized,
    config::{Config, Secret},
};

#[derive(Debug, Default)]
struct EncryptionConfig;
impl Config for EncryptionConfig {
    type Strategy = Randomized;

    fn keys(&self) -> Vec<Secret<[u8; 32]>> {
        vec![(*b"uuOxfpWgRgIEo3dIrdo0hnHJHF1hntvW").into()]
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct User {
    #[allow(dead_code)]
    id: i32,
    text: Option<EncryptedMessage<String, EncryptionConfig>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct UserInsertable {
    text: Option<EncryptedMessage<String, EncryptionConfig>>,
}

#[derive(AsChangeset)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct UserChangeset {
    text: Option<Option<EncryptedMessage<String, EncryptionConfig>>>,
}

fn setup_db() -> SqliteConnection {
    let mut connection = SqliteConnection::establish(":memory:").unwrap();
    connection.batch_execute("
        CREATE TABLE users (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            text TEXT
        )
    ").unwrap();
    connection
}

#[test]
fn encrypted_message_works() {
    let mut connection = setup_db();

    // Insert a new user.
    diesel::insert_into(schema::users::table)
        .values(UserInsertable {
            text: Some(EncryptedMessage::encrypt("Very secret, as text.".to_string()).unwrap()),
        })
        .execute(&mut connection)
        .unwrap();

    // Load the user from the database.
    let user: User = schema::users::table.first(&mut connection).unwrap();

    // Decrypt the user's secret.
    assert_eq!(user.text.as_ref().unwrap().decrypt().unwrap(), "Very secret, as text.");
}
