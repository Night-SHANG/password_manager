use std::collections::BTreeMap;
use std::io::Read;

use crate::import::{ImportParseResult, NormalizedImportItem};
use crate::security::sha256;
use crate::{AppError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LogicalField {
    Name,
    Url,
    Username,
    Password,
    Notes,
    Category,
    StableId,
}

const ALIASES: &[(LogicalField, &[&str])] = &[
    (
        LogicalField::Name,
        &["name", "title", "account", "display name", "item name"],
    ),
    (
        LogicalField::Url,
        &[
            "url",
            "website",
            "uri",
            "login uri",
            "login_uri",
            "web site",
        ],
    ),
    (
        LogicalField::Username,
        &[
            "username",
            "user name",
            "login username",
            "login_username",
            "login",
            "user",
        ],
    ),
    (
        LogicalField::Password,
        &["password", "login password", "login_password", "pwd", "passwd"],
    ),
    (
        LogicalField::Notes,
        &["notes", "note", "comment", "comments"],
    ),
    (
        LogicalField::Category,
        &["category", "folder", "group", "grouping"],
    ),
    (
        LogicalField::StableId,
        &["id", "uuid", "guid", "item id", "item_id"],
    ),
];

#[derive(Debug)]
struct Mapping {
    columns: BTreeMap<LogicalField, usize>,
}

impl Mapping {
    fn from_headers(headers: &csv::StringRecord) -> Self {
        let normalized: Vec<String> = headers.iter().map(normalize_header).collect();
        let mut columns = BTreeMap::new();
        let mut claimed = vec![false; normalized.len()];

        for (field, aliases) in ALIASES {
            for alias in *aliases {
                if let Some((index, _)) = normalized
                    .iter()
                    .enumerate()
                    .find(|(index, header)| !claimed[*index] && header.as_str() == normalize_header(alias))
                {
                    columns.insert(*field, index);
                    claimed[index] = true;
                    break;
                }
            }
        }

        Self { columns }
    }

    fn value<'a>(&self, row: &'a csv::StringRecord, field: LogicalField) -> &'a str {
        self.columns
            .get(&field)
            .and_then(|index| row.get(*index))
            .unwrap_or("")
            .trim()
    }

    fn looks_like_password_export(&self) -> bool {
        self.columns.contains_key(&LogicalField::Password)
            && (self.columns.contains_key(&LogicalField::Name)
                || self.columns.contains_key(&LogicalField::Url))
    }
}

fn normalize_header(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('﻿')
        .to_ascii_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn provider_from_headers(headers: &csv::StringRecord) -> &'static str {
    let fields: Vec<String> = headers.iter().map(normalize_header).collect();

    if fields.iter().any(|v| v == "login uri")
        && fields.iter().any(|v| v == "login password")
    {
        "bitwarden"
    } else if fields.iter().any(|v| v == "formactionorigin")
        || fields.iter().any(|v| v == "httprealm")
    {
        "firefox"
    } else if fields.iter().any(|v| v == "group")
        && fields.iter().any(|v| v == "title")
    {
        "keepass-compatible"
    } else {
        "chrome-compatible"
    }
}

fn host_fallback(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return host.to_string();
        }
    }

    url.split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(url)
        .to_string()
}

fn fingerprint(
    provider: &str,
    stable_id: &str,
    name: &str,
    url: &str,
    username: &str,
    password: &str,
    notes: &str,
    category: &str,
) -> [u8; 32] {
    let mut canonical = Vec::new();
    for value in [
        provider, stable_id, name, url, username, password, notes, category,
    ] {
        canonical.extend_from_slice(value.as_bytes());
        canonical.push(0x1f);
    }
    sha256(&canonical)
}

pub fn parse_reader<R: Read>(reader: R) -> Result<ImportParseResult> {
    let mut csv = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(reader);

    let headers = csv.headers()?.clone();
    let mapping = Mapping::from_headers(&headers);
    if !mapping.looks_like_password_export() {
        return Err(AppError::Input(format!(
            "无法识别为密码 CSV，表头：{}",
            headers.iter().collect::<Vec<_>>().join(", ")
        )));
    }

    let provider = provider_from_headers(&headers).to_string();
    let mut result = ImportParseResult::default();

    for row in csv.records() {
        let row = match row {
            Ok(row) => row,
            Err(_) => {
                result.invalid_rows += 1;
                continue;
            }
        };

        let url = mapping.value(&row, LogicalField::Url);
        let password = mapping.value(&row, LogicalField::Password);

        if password.is_empty() {
            result.invalid_rows += 1;
            continue;
        }

        let raw_name = mapping.value(&row, LogicalField::Name);
        let name = if raw_name.is_empty() {
            host_fallback(url)
        } else {
            raw_name.to_string()
        };

        if name.is_empty() && url.is_empty() {
            result.invalid_rows += 1;
            continue;
        }

        let username = mapping.value(&row, LogicalField::Username).to_string();
        let notes = mapping.value(&row, LogicalField::Notes).to_string();
        let category = mapping.value(&row, LogicalField::Category).to_string();
        let stable_id_raw = mapping.value(&row, LogicalField::StableId);
        let stable_id = (!stable_id_raw.is_empty()).then(|| stable_id_raw.to_string());

        let item_fingerprint = fingerprint(
            &provider,
            stable_id_raw,
            &name,
            url,
            &username,
            password,
            &notes,
            &category,
        );

        result.items.push(NormalizedImportItem {
            provider: provider.clone(),
            source_stable_id: stable_id,
            name,
            website: url.to_string(),
            username,
            password: password.to_string(),
            notes,
            category,
            fingerprint: item_fingerprint,
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv_maps_by_header_not_position() {
        let csv = "password,username,url,name,note\npw,ada,https://github.com,GitHub,hello\n";
        let parsed = parse_reader(csv.as_bytes()).unwrap();
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].name, "GitHub");
        assert_eq!(parsed.items[0].username, "ada");
        assert_eq!(parsed.items[0].password, "pw");
        assert_eq!(parsed.items[0].notes, "hello");
    }

    #[test]
    fn bom_header_is_supported() {
        let csv = "\u{feff}name,url,username,password\nX,https://x.example,u,p\n";
        let parsed = parse_reader(csv.as_bytes()).unwrap();
        assert_eq!(parsed.items.len(), 1);
    }

    #[test]
    fn malformed_or_empty_secret_rows_are_counted() {
        let csv = "name,url,username,password\nEmpty,https://x,u,\nReal,https://y,u,pw\n";
        let parsed = parse_reader(csv.as_bytes()).unwrap();
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.invalid_rows, 1);
    }

    #[test]
    fn same_record_has_same_fingerprint() {
        let csv = "name,url,username,password\nX,https://x,u,pw\n";
        let a = parse_reader(csv.as_bytes()).unwrap();
        let b = parse_reader(csv.as_bytes()).unwrap();
        assert_eq!(a.items[0].fingerprint, b.items[0].fingerprint);
    }
}
