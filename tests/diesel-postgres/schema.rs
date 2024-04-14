// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Int4,
        json -> Nullable<Json>,
        jsonb -> Nullable<Jsonb>,
    }
}
