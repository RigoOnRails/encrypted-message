// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        #[max_length = 36]
        id -> Char,
        json -> Nullable<Json>,
        text -> Nullable<Text>,
    }
}
