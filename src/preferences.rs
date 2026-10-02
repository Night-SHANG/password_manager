//! Non-sensitive application safety preferences, kept separate from vault data.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MAX_SETTINGS_BYTES: u64 = 4096;
const FORMAT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Preferences {
    pub auto_lock_minutes: u16,
    pub clipboard_seconds: u16,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            clipboard_seconds: 30,
        }
    }
}

// Keep the disk schema explicit so additions to application state cannot
// accidentally serialize vault paths, secrets, or unrelated user data.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SettingsFile {
    version: u16,
    auto_lock_minutes: u16,
    clipboard_seconds: u16,
}

fn validate(preferences: &Preferences) -> Result<(), &'static str> {
    if ![1, 5, 10, 15, 30].contains(&preferences.auto_lock_minutes) {
        return Err("自动锁定设置无效：请选择 1、5、10、15 或 30 分钟");
    }
    if ![15, 30, 60].contains(&preferences.clipboard_seconds) {
        return Err("剪贴板清理设置无效：请选择 15、30 或 60 秒");
    }
    Ok(())
}

/// Read only this non-sensitive settings file, falling back without rewriting it.
pub fn load(path: &Path) -> (Preferences, Option<String>) {
    match read_settings(path) {
        Ok(Some(preferences)) => (preferences, None),
        Ok(None) => (Preferences::default(), None),
        Err(reason) => (
            Preferences::default(),
            Some(format!(
                "{reason}；已使用默认安全设置（5 分钟自动锁定、30 秒清理剪贴板）"
            )),
        ),
    }
}

fn read_settings(path: &Path) -> Result<Option<Preferences>, &'static str> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound && settings_path_is_missing(path) => {
            return Ok(None);
        }
        Err(_) => return Err("无法读取设置文件，请检查文件权限"),
    };
    let metadata = file.metadata().map_err(|_| "无法读取设置文件信息")?;
    if !metadata.is_file() {
        return Err("设置路径不是普通文件");
    }
    if metadata.len() > MAX_SETTINGS_BYTES {
        return Err("设置文件超过 4 KiB 大小限制");
    }
    let mut bytes = Vec::new();
    // Bound actual reads as well as checking metadata: a concurrent writer must
    // not cause an unbounded allocation. Never read more than four KiB.
    (&file)
        .take(MAX_SETTINGS_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| "无法读取设置文件，请检查文件权限")?;
    if file.metadata().map_err(|_| "无法读取设置文件信息")?.len() > MAX_SETTINGS_BYTES {
        return Err("设置文件超过 4 KiB 大小限制");
    }
    let settings: SettingsFile =
        serde_json::from_slice(&bytes).map_err(|_| "设置文件损坏或包含不支持的字段")?;
    if settings.version != FORMAT_VERSION {
        return Err("不支持此设置文件版本");
    }
    let preferences = Preferences {
        auto_lock_minutes: settings.auto_lock_minutes,
        clipboard_seconds: settings.clipboard_seconds,
    };
    validate(&preferences)?;
    Ok(Some(preferences))
}

fn settings_path_is_missing(path: &Path) -> bool {
    // Windows can report NotFound for a child of a regular file as well as a
    // missing path. Inspect the nearest existing entry without hiding dangling
    // symlinks or metadata errors, and require a usable parent directory.
    for (depth, candidate) in path.ancestors().enumerate() {
        let candidate = if candidate.as_os_str().is_empty() {
            Path::new(".")
        } else {
            candidate
        };
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                return depth > 0
                    && (metadata.is_dir()
                        || (metadata.is_symlink()
                            && fs::metadata(candidate).is_ok_and(|target| target.is_dir())));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return false,
        }
    }
    false
}

/// Commit valid preferences atomically. Callers should apply them only on success.
pub fn save(path: &Path, preferences: &Preferences) -> Result<(), String> {
    validate(preferences).map_err(str::to_owned)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "无法保存设置：缺少有效的设置目录".to_owned())?;
    let bytes = serde_json::to_vec_pretty(&SettingsFile {
        version: FORMAT_VERSION,
        auto_lock_minutes: preferences.auto_lock_minutes,
        clipboard_seconds: preferences.clipboard_seconds,
    })
    .map_err(|_| "无法编码设置，原设置未更改".to_owned())?;
    fs::create_dir_all(parent).map_err(|_| "无法创建设置目录，原设置未更改".to_owned())?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".settings-")
        .tempfile_in(parent)
        .map_err(|_| "无法创建临时设置文件，原设置未更改".to_owned())?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| "无法写入或同步设置文件，原设置未更改".to_owned())?;
    // A sibling temporary file stays on the same filesystem. persist replaces
    // atomically on Windows and Unix; on failure its temporary file is dropped.
    temporary
        .persist(path)
        .map_err(|_| "无法替换设置文件，原设置未更改".to_owned())?;
    Ok(())
}

pub fn default_path() -> Result<PathBuf, String> {
    default_path_from_vars(cfg!(windows), |key| std::env::var_os(key))
}

fn default_path_from_vars(
    windows: bool,
    get_env: impl Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, String> {
    let (base, suffix) = if windows {
        (get_env("LOCALAPPDATA"), "PasswordManager/settings.json")
    } else if let Some(base) = get_env("XDG_CONFIG_HOME") {
        (Some(base), "password-manager/settings.json")
    } else {
        (get_env("HOME"), ".config/password-manager/settings.json")
    };
    let base = base
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "无法确定设置目录：需要有效的绝对用户配置路径".to_owned())?;
    Ok(base.join(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn assert_safe_fallback(path: &Path) {
        let (preferences, warning) = load(path);
        assert_eq!(preferences, Preferences::default());
        let warning = warning.expect("invalid settings must show a warning");
        assert!(warning.contains("默认"));
        assert!(!warning.contains("synthetic-secret"));
        assert!(!warning.contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn defaults_are_five_minutes_and_thirty_seconds() {
        assert_eq!(
            Preferences::default(),
            Preferences {
                auto_lock_minutes: 5,
                clipboard_seconds: 30,
            }
        );
    }

    #[test]
    fn missing_file_uses_defaults_without_warning_or_writing() {
        let directory = tempfile::tempdir().unwrap();
        for relative in [
            "settings.json",
            "missing/settings.json",
            "missing/nested/settings.json",
        ] {
            let path = directory.path().join(relative);
            assert_eq!(load(&path), (Preferences::default(), None));
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn allowed_values_round_trip_in_a_strict_versioned_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preferences/settings.json");
        for auto_lock_minutes in [1, 5, 10, 15, 30] {
            for clipboard_seconds in [15, 30, 60] {
                let preferences = Preferences {
                    auto_lock_minutes,
                    clipboard_seconds,
                };
                save(&path, &preferences).unwrap();
                assert_eq!(load(&path), (preferences, None));
                let actual: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                assert_eq!(
                    actual,
                    serde_json::json!({
                        "version": 1,
                        "auto_lock_minutes": auto_lock_minutes,
                        "clipboard_seconds": clipboard_seconds,
                    })
                );
            }
        }
    }

    #[test]
    fn replacement_touches_only_settings_and_leaves_no_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let other = directory.path().join("unrelated.txt");
        fs::write(&other, "synthetic unrelated data").unwrap();
        save(&path, &Preferences::default()).unwrap();
        let updated = Preferences {
            auto_lock_minutes: 15,
            clipboard_seconds: 60,
        };
        save(&path, &updated).unwrap();
        assert_eq!(load(&path), (updated, None));
        assert_eq!(
            fs::read_to_string(other).unwrap(),
            "synthetic unrelated data"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn invalid_save_preserves_previous_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let old = br#"{"version":1,"auto_lock_minutes":5,"clipboard_seconds":30}"#;
        fs::write(&path, old).unwrap();
        for (auto_lock_minutes, clipboard_seconds) in [
            (0, 30),
            (2, 30),
            (31, 30),
            (u16::MAX, 30),
            (5, 0),
            (5, 16),
            (5, u16::MAX),
        ] {
            let error = save(
                &path,
                &Preferences {
                    auto_lock_minutes,
                    clipboard_seconds,
                },
            )
            .unwrap_err();
            assert!(error.contains("设置"));
            assert_eq!(fs::read(&path).unwrap(), old);
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn malformed_unknown_and_invalid_settings_use_safe_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        for input in [
            "synthetic-secret",
            r#"{"version":2,"auto_lock_minutes":5,"clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":5,"clipboard_seconds":30,"password":"synthetic-secret"}"#,
            r#"{"version":1,"auto_lock_minutes":5,"clipboard_seconds":30,"vault_path":"synthetic-secret"}"#,
            r#"{"version":1,"auto_lock_minutes":5,"clipboard_seconds":30,"theme":"dark"}"#,
            r#"{"version":1,"auto_lock_minutes":0,"clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":2,"clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":5,"clipboard_seconds":31}"#,
            r#"{"version":1,"auto_lock_minutes":-1,"clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":65536,"clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":"5","clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":5}"#,
            r#"{"auto_lock_minutes":5,"clipboard_seconds":30}"#,
            r#"{"version":1,"version":1,"auto_lock_minutes":5,"clipboard_seconds":30}"#,
            r#"{"version":1,"auto_lock_minutes":5,"clipboard_seconds":30} null"#,
        ] {
            fs::write(&path, input).unwrap();
            assert_safe_fallback(&path);
            assert_eq!(fs::read_to_string(&path).unwrap(), input);
        }
    }

    #[test]
    fn file_size_limit_is_four_kibibytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let mut bytes = br#"{"version":1,"auto_lock_minutes":10,"clipboard_seconds":15}"#.to_vec();
        bytes.resize(4096, b' ');
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            load(&path),
            (
                Preferences {
                    auto_lock_minutes: 10,
                    clipboard_seconds: 15,
                },
                None,
            )
        );
        bytes.push(b' ');
        fs::write(&path, &bytes).unwrap();
        assert_safe_fallback(&path);
        assert_eq!(fs::metadata(&path).unwrap().len(), 4097);
    }

    #[test]
    fn read_errors_use_defaults_and_a_visible_warning() {
        let directory = tempfile::tempdir().unwrap();
        assert_safe_fallback(directory.path());
        let blocker = directory.path().join("blocker");
        fs::write(&blocker, "synthetic-secret").unwrap();
        assert_safe_fallback(&blocker.join("settings.json"));
        assert_safe_fallback(&blocker.join("missing/nested/settings.json"));
        assert_eq!(fs::read_to_string(&blocker).unwrap(), "synthetic-secret");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_settings_symlink_uses_defaults_and_a_visible_warning() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("missing.json");
        let path = directory.path().join("settings.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_safe_fallback(&path);
        assert_eq!(fs::read_link(&path).unwrap(), target);
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_parent_symlink_uses_defaults_and_a_visible_warning() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("missing");
        let link = directory.path().join("config");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_safe_fallback(&link.join("nested/settings.json"));
        assert_eq!(fs::read_link(&link).unwrap(), target);
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_symlink_ancestor_uses_defaults_and_a_visible_warning() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("blocker");
        fs::write(&target, "synthetic-secret").unwrap();
        let link = directory.path().join("linked-file");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_safe_fallback(&link.join("missing/nested/settings.json"));
        assert_eq!(fs::read_link(&link).unwrap(), target);
        assert_eq!(fs::read_to_string(&target).unwrap(), "synthetic-secret");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn missing_settings_under_directory_symlink_do_not_warn_or_write() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("config");
        fs::create_dir(&target).unwrap();
        let link = directory.path().join("linked-config");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            load(&link.join("missing/nested/settings.json")),
            (Preferences::default(), None)
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    #[test]
    fn failed_replacement_preserves_existing_destination_and_cleans_tempfile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::create_dir(&path).unwrap();
        let old = path.join("previous-settings.json");
        fs::write(&old, "synthetic previous settings").unwrap();
        let error = save(&path, &Preferences::default()).unwrap_err();
        assert!(error.contains("设置"));
        assert_eq!(
            fs::read_to_string(old).unwrap(),
            "synthetic previous settings"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn invalid_values_do_not_even_create_a_settings_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-created/settings.json");
        assert!(
            save(
                &path,
                &Preferences {
                    auto_lock_minutes: 0,
                    clipboard_seconds: 30,
                }
            )
            .is_err()
        );
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn default_paths_use_only_absolute_platform_configuration_directories() {
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().as_os_str().to_os_string();
        for (windows, variable, suffix) in [
            (true, "LOCALAPPDATA", "PasswordManager/settings.json"),
            (false, "XDG_CONFIG_HOME", "password-manager/settings.json"),
            (false, "HOME", ".config/password-manager/settings.json"),
        ] {
            let path =
                default_path_from_vars(windows, |key| (key == variable).then(|| base.clone()))
                    .unwrap();
            assert_eq!(path, directory.path().join(suffix));
            assert!(!path.exists());
        }
        for windows in [false, true] {
            assert!(default_path_from_vars(windows, |_| None).is_err());
            assert!(default_path_from_vars(windows, |_| Some("relative".into())).is_err());
            assert!(default_path_from_vars(windows, |_| Some("".into())).is_err());
        }
        // An explicitly supplied relative XDG base is rejected, not resolved from cwd.
        assert!(
            default_path_from_vars(false, |key| match key {
                "XDG_CONFIG_HOME" => Some("relative".into()),
                "HOME" => Some(base.clone()),
                _ => None,
            })
            .is_err()
        );
    }
}
