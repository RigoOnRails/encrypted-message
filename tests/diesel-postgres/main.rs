#![cfg(all(feature = "diesel", feature = "diesel-postgres"))]

mod schema;

use diesel::prelude::*;
use encrypted_message::{encryption_type::{Randomized, Deterministic}, EncryptedMessage};

#[derive(Debug, Default)]
struct KeyConfig;
impl encrypted_message::KeyConfig for KeyConfig {
    fn raw_keys(&self) -> Vec<secrecy::SecretVec<u8>> {
        vec![b"Fl1cANaYYRKWjmZPMDG2a3lhMnulSBqx".to_vec().into()]
    }

    fn key_derivation_salt(&self) -> secrecy::SecretVec<u8> {
        b"ucTe1weWDJC0zz8Pl4pDMR4ydgnuUsZZ".to_vec().into()
    }
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct User {
    id: i32,
    json: Option<EncryptedMessage<String, Randomized, KeyConfig>>,
    jsonb: Option<EncryptedMessage<String, Deterministic, KeyConfig>>,
}

#[derive(Insertable)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct UserInsertable {
    json: Option<EncryptedMessage<String, Randomized, KeyConfig>>,
    jsonb: Option<EncryptedMessage<String, Deterministic, KeyConfig>>,
}

#[derive(AsChangeset)]
#[diesel(table_name = schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct UserChangeset {
    json: Option<Option<EncryptedMessage<String, Randomized, KeyConfig>>>,
    jsonb: Option<Option<EncryptedMessage<String, Deterministic, KeyConfig>>>,
}

#[test]
fn encrypted_message_works() {
    // Attempt to load environment variables from .env.test
    let _ = dotenvy::from_filename(".env.test");

    let database_url = dotenvy::var("POSTGRES_DATABASE_URL").expect("POSTGRES_DATABASE_URL must be set.");
    let mut connection = PgConnection::establish(&database_url).unwrap();

    // Create a new user.
    let user: User = diesel::insert_into(schema::users::table)
        .values(UserInsertable {
            json: Some(EncryptedMessage::encrypt("Very secret.".to_string()).unwrap()),
            jsonb: Some(EncryptedMessage::encrypt("Very secret, also binary.".to_string()).unwrap()),
        })
        .get_result(&mut connection)
        .unwrap();

    // Decrypt the user's secrets.
    assert_eq!(user.json.as_ref().unwrap().decrypt().unwrap(), "Very secret.");
    assert_eq!(user.jsonb.as_ref().unwrap().decrypt().unwrap(), "Very secret, also binary.");

    // Update the user's secrets.
    let user: User = diesel::update(schema::users::table.find(user.id))
        .set(UserChangeset {
            json: Some(Some(user.json.unwrap().with_new_payload("New secret.".to_string()).unwrap())),
            jsonb: Some(Some(user.jsonb.unwrap().with_new_payload("New secret, still very much binary.".to_string()).unwrap())),
        })
        .get_result(&mut connection)
        .unwrap();

    // Decrypt the user's secrets.
    assert_eq!(user.json.unwrap().decrypt().unwrap(), "New secret.");
    assert_eq!(user.jsonb.as_ref().unwrap().decrypt().unwrap(), "New secret, still very much binary.");
}
