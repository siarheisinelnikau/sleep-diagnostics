use std::{collections::BTreeMap, sync::OnceLock};

pub const LANGUAGES: [(&str, &str); 6] = [
    ("en", "English"),
    ("ru", "Русский"),
    ("fr", "Français"),
    ("de", "Deutsch"),
    ("es", "Español"),
    ("it", "Italiano"),
];
static CATALOGS: OnceLock<Vec<BTreeMap<String, String>>> = OnceLock::new();
pub fn catalogs() -> &'static [BTreeMap<String, String>] {
    CATALOGS.get_or_init(|| {
        [
            include_str!("../locales/en.json"),
            include_str!("../locales/ru.json"),
            include_str!("../locales/fr.json"),
            include_str!("../locales/de.json"),
            include_str!("../locales/es.json"),
            include_str!("../locales/it.json"),
        ]
        .iter()
        .map(|json| serde_json::from_str(json).expect("embedded translation catalog"))
        .collect()
    })
}
pub fn tr<'a>(language: &str, key: &'a str) -> &'a str {
    let index = LANGUAGES.iter().position(|l| l.0 == language).unwrap_or(0);
    catalogs()[index]
        .get(key)
        .or_else(|| catalogs()[0].get(key))
        .map(String::as_str)
        .unwrap_or(key)
}
