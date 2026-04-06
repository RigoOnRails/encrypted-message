diesel::table! {
    users (id) {
        id -> Integer,
        text -> Nullable<Text>,
    }
}
