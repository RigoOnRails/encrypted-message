#![cfg(all(feature = "diesel", feature = "diesel-mysql"))]

mod schema;

use diesel::prelude::*;
use encrypted_message::{encryption_type::Randomized, EncryptedMessage};

#[derive(Debug)]
struct Config;
impl encrypted_message::Config for Config {
    fn raw_keys() -> Vec<secrecy::SecretVec<u8>> {
        vec![b"Fl1cANaYYRKWjmZPMDG2a3lhMnulSBqx".to_vec().into()]
    }

    fn key_derivation_salt() -> secrecy::SecretVec<u8> {
        b"ucTe1weWDJC0zz8Pl4pDMR4ydgnuUsZZ".to_vec().into()
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct User {
    #[allow(dead_code)]
    id: String,
    json: EncryptedMessage<String, Randomized, Config>,
    nullable_json: Option<EncryptedMessage<String, Randomized, Config>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct UserInsertable {
    id: String,
    json: EncryptedMessage<String, Randomized, Config>,
    nullable_json: Option<EncryptedMessage<String, Randomized, Config>>,
}

#[derive(AsChangeset)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
struct UserChangeset {
    json: Option<EncryptedMessage<String, Randomized, Config>>,
    nullable_json: Option<Option<EncryptedMessage<String, Randomized, Config>>>,
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
            json: EncryptedMessage::encrypt("Very secret.".to_string()).unwrap(),
            nullable_json: Some(EncryptedMessage::encrypt("Also very secret, but nullable.".to_string()).unwrap()),
        })
        .execute(&mut connection)
        .unwrap();

    // Load the new user from the database.
    let user: User = schema::users::table.find(&id).first(&mut connection).unwrap();

    // Decrypt the user's secrets.
    assert_eq!(user.json.decrypt().unwrap(), "Very secret.");
    assert_eq!(user.nullable_json.map(|s| s.decrypt().unwrap()), Some("Also very secret, but nullable.".to_string()));

    // Update the user's secrets.
    diesel::update(schema::users::table.find(&id))
        .set(UserChangeset {
            json: Some(user.json.with_new_payload("New secret.".to_string()).unwrap()),
            nullable_json: Some(None),
        })
        .execute(&mut connection)
        .unwrap();

    // Load the updated user from the database.
    let user: User = schema::users::table.find(&id).first(&mut connection).unwrap();

    // Decrypt the user's secrets.
    assert_eq!(user.json.decrypt().unwrap(), "New secret.");
    assert_eq!(user.nullable_json.map(|s| s.decrypt().unwrap()), None);
}
