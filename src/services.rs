use crate::domain::{EntryDraft, SecretPayload};
use crate::security::random_array;
use crate::{AppError, Result};

const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordGeneratorOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }
}

pub fn generate_password(options: PasswordGeneratorOptions) -> Result<String> {
    if !(8..=128).contains(&options.length) {
        return Err(AppError::Input(
            "密码长度必须在 8 到 128 之间".to_string(),
        ));
    }

    let mut groups: Vec<&[u8]> = Vec::new();
    if options.uppercase {
        groups.push(UPPER);
    }
    if options.lowercase {
        groups.push(LOWER);
    }
    if options.digits {
        groups.push(DIGITS);
    }
    if options.symbols {
        groups.push(SYMBOLS);
    }
    if groups.is_empty() {
        return Err(AppError::Input(
            "至少需要启用一种密码字符类型".to_string(),
        ));
    }
    if options.length < groups.len() {
        return Err(AppError::Input(
            "密码长度不足以覆盖已启用的字符类型".to_string(),
        ));
    }

    let alphabet: Vec<u8> = groups.iter().flat_map(|group| group.iter().copied()).collect();
    let mut output = Vec::with_capacity(options.length);

    for group in &groups {
        output.push(sample(group)?);
    }
    while output.len() < options.length {
        output.push(sample(&alphabet)?);
    }

    secure_shuffle(&mut output)?;
    String::from_utf8(output)
        .map_err(|_| AppError::Crypto("password generator produced invalid UTF-8"))
}

pub fn validate_entry_draft(draft: &EntryDraft) -> Result<()> {
    if draft.name.trim().is_empty() {
        return Err(AppError::Input("名称不能为空".to_string()));
    }
    if draft.secret.password.is_empty() {
        return Err(AppError::Input("密码不能为空".to_string()));
    }
    if !draft.website.trim().is_empty() {
        safe_web_url(&draft.website)?;
    }
    Ok(())
}

pub fn safe_web_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AppError::Input("网站地址为空".to_string()));
    }

    let url = match url::Url::parse(trimmed) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => url::Url::parse(&format!("https://{trimmed}"))
            .map_err(|_| AppError::Input("网站地址格式无效".to_string()))?,
        Err(_) => return Err(AppError::Input("网站地址格式无效".to_string())),
    };

    match url.scheme() {
        "http" | "https" => Ok(url.to_string()),
        _ => Err(AppError::Input(
            "只允许打开 http / https 网站".to_string(),
        )),
    }
}

pub fn draft(
    name: String,
    website: String,
    username: String,
    password: String,
    notes: String,
    category: String,
    favorite: bool,
) -> Result<EntryDraft> {
    let draft = EntryDraft {
        name,
        website,
        username,
        category: if category.trim().is_empty() {
            "其他".to_string()
        } else {
            category
        },
        favorite,
        secret: SecretPayload::new(password, notes),
        provenance: None,
    };
    validate_entry_draft(&draft)?;
    Ok(draft)
}

fn sample(alphabet: &[u8]) -> Result<u8> {
    let zone = u8::MAX - (u8::MAX % alphabet.len() as u8);
    loop {
        let byte = random_array::<1>()?[0];
        if byte < zone {
            return Ok(alphabet[(byte as usize) % alphabet.len()]);
        }
    }
}

fn secure_shuffle(values: &mut [u8]) -> Result<()> {
    for i in (1..values.len()).rev() {
        let bound = i + 1;
        let zone = u32::MAX - (u32::MAX % bound as u32);
        let index = loop {
            let bytes = random_array::<4>()?;
            let value = u32::from_le_bytes(bytes);
            if value < zone {
                break (value as usize) % bound;
            }
        };
        values.swap(i, index);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_uses_all_enabled_groups() {
        let value = generate_password(PasswordGeneratorOptions::default()).unwrap();
        assert_eq!(value.len(), 20);
        assert!(value.bytes().any(|c| UPPER.contains(&c)));
        assert!(value.bytes().any(|c| LOWER.contains(&c)));
        assert!(value.bytes().any(|c| DIGITS.contains(&c)));
        assert!(value.bytes().any(|c| SYMBOLS.contains(&c)));
    }

    #[test]
    fn unsafe_url_scheme_is_rejected() {
        assert!(safe_web_url("javascript:alert(1)").is_err());
        assert!(safe_web_url("file:///C:/Windows").is_err());
        assert!(safe_web_url("mailto:test@example.com").is_err());
        assert!(safe_web_url("https://example.com").is_ok());
        assert!(safe_web_url("example.com").is_ok());
    }
}
