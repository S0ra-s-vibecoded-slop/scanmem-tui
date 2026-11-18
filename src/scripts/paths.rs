//! Where scripts live, and who owns the files this program creates.
//!
//! Under `sudo` the environment talks about root (`HOME=/root`), but files
//! belong to the user who invoked us: the cache folder is derived from their
//! home and everything we create is chowned to them. An explicit
//! `--scripts-dir` is taken as-is, because the user chose that location.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// How much of a script the preview shows.
pub const PREVIEW_MAX_BYTES: usize = 1 << 20;
pub const PREVIEW_MAX_LINES: usize = 5000;

/// The user behind `sudo`, when there is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

/// The invoking user when we run elevated through sudo. `None` for a normal
/// run, a root login, or when `/etc/passwd` cannot tell us who it was.
pub fn invoking_user() -> Option<User> {
    if effective_uid()? != 0 {
        return None;
    }
    let name = env::var("SUDO_USER").ok()?;
    if name.is_empty() || name == "root" {
        return None;
    }
    let uid: u32 = env::var("SUDO_UID").ok()?.parse().ok()?;
    let (home, passwd_gid) = passwd_entry(&name, uid)?;
    let gid = env::var("SUDO_GID")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(passwd_gid);
    Some(User {
        name,
        uid,
        gid,
        home,
    })
}

/// Effective uid, read without unsafe code.
fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Home directory and primary gid from `/etc/passwd`, by name or uid.
fn passwd_entry(name: &str, uid: u32) -> Option<(PathBuf, u32)> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let matches = fields[0] == name || fields[2].parse::<u32>() == Ok(uid);
        if !matches {
            continue;
        }
        let home = PathBuf::from(fields[5]);
        let Ok(gid) = fields[3].parse::<u32>() else {
            continue;
        };
        return home.is_absolute().then_some((home, gid));
    }
    None
}

/// chown `path` to the invoking user; failures are not fatal (the file still
/// works for root, it would just keep root ownership).
pub fn give_to_user(path: &Path, user: Option<&User>) {
    if let Some(user) = user {
        let _ = std::os::unix::fs::chown(path, Some(user.uid), Some(user.gid));
    }
}

/// The scripts folder, and whether the user picked it explicitly.
#[derive(Clone)]
pub struct ScriptsRoot {
    pub dir: PathBuf,
    pub explicit: bool,
    /// Set only when running under sudo; used for chown and the editor drop.
    pub user: Option<User>,
}

impl ScriptsRoot {
    pub fn from_arg(dir: Option<&Path>) -> ScriptsRoot {
        let user = invoking_user();
        match dir {
            Some(dir) => {
                let text = dir.to_string_lossy();
                let home = user
                    .as_ref()
                    .map(|user| user.home.clone())
                    .or_else(|| env::var_os("HOME").map(PathBuf::from));
                ScriptsRoot {
                    dir: expand_tilde(&text, home.as_deref()),
                    explicit: true,
                    user,
                }
            }
            None => ScriptsRoot {
                dir: default_cache_dir(user.as_ref()),
                explicit: false,
                user,
            },
        }
    }

    /// Create the folder, taking ownership of the parts we create when the
    /// folder is implicit.
    pub fn ensure(&self) -> io::Result<()> {
        ensure_dir(&self.dir, self.owner())
    }

    /// The user new files should belong to, if any.
    pub fn owner(&self) -> Option<&User> {
        self.user.as_ref().filter(|_| !self.explicit)
    }

    /// The home `~` expands to.
    pub fn home(&self) -> Option<PathBuf> {
        self.user
            .as_ref()
            .map(|user| user.home.clone())
            .or_else(|| env::var_os("HOME").map(PathBuf::from))
    }

    /// The user the editor should run as, when this file is implicitly ours
    /// and lives in the invoking user's home. Explicit folders keep root.
    pub fn editor_user(&self, path: &Path) -> Option<&User> {
        self.user
            .as_ref()
            .filter(|user| !self.explicit && path.starts_with(&user.home))
    }

    /// Turns a path typed in the UI into an absolute one, `~` included.
    pub fn expand(&self, text: &str) -> PathBuf {
        expand_tilde(text.trim(), self.home().as_deref())
    }

    /// Resolves a path relative to the scripts folder: `thing.lua` becomes
    /// `<dir>/thing.lua`, `things/meow.lua` nests, `..` and absolute paths are
    /// rejected so a script cannot be created outside the folder by accident.
    pub fn resolve_new(&self, text: &str) -> Result<PathBuf, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty path".into());
        }
        if text.ends_with('/') {
            return Err("the path needs a file name".into());
        }
        let given = Path::new(text);
        if given.is_absolute() {
            return Err("use a path relative to the scripts folder".into());
        }
        let mut path = self.dir.clone();
        for component in given.components() {
            match component {
                Component::Normal(part) => path.push(part),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err("paths cannot leave the scripts folder".into());
                }
            }
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("the path needs a file name")?;
        if name.trim().is_empty() {
            return Err("the path needs a file name".into());
        }
        let has_lua = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("lua"));
        if !has_lua {
            if path.extension().is_some() {
                return Err("scripts must be .lua files".into());
            }
            path.set_extension("lua");
        }
        Ok(path)
    }

    /// Creates a new script from `text` (a relative path), refusing to
    /// overwrite. Parent folders are created as needed.
    pub fn write_new(&self, text: &str, contents: &str) -> Result<PathBuf, String> {
        let path = self.resolve_new(text)?;
        if path.exists() {
            return Err(format!("{} already exists", path.display()));
        }
        if let Some(parent) = path.parent() {
            ensure_dir(parent, self.owner())
                .map_err(|e| format!("cannot create the folder: {e}"))?;
        }
        fs::write(&path, contents).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        if let Some(user) = self.owner() {
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
            give_to_user(&path, Some(user));
        }
        Ok(path)
    }

    /// Whether `path` is inside the scripts folder, for `D`.
    pub fn is_managed(&self, path: &Path) -> bool {
        let Ok(dir) = self.dir.canonicalize() else {
            return false;
        };
        match path.canonicalize() {
            Ok(path) => path.starts_with(dir),
            Err(_) => path.starts_with(&self.dir),
        }
    }
}

/// `$SUDO_USER`'s cache folder when elevated, otherwise the XDG cache home.
fn default_cache_dir(user: Option<&User>) -> PathBuf {
    let base = user
        .map(|user| user.home.join(".cache"))
        .or_else(|| env::var_os("XDG_CACHE_HOME").map(PathBuf::from))
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| env::temp_dir().join("scanmem-tui-cache"));
    base.join("scanmem-tui").join("scripts")
}

/// `~` and `~/...` expansion against `home`.
pub fn expand_tilde(text: &str, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return PathBuf::from(text);
    };
    if text == "~" {
        return home.to_path_buf();
    }
    match text.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(text),
    }
}

/// `create_dir_all`, giving the newly created folders to `user` when set.
pub fn ensure_dir(path: &Path, user: Option<&User>) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut current = path.to_path_buf();
    while !current.exists() {
        missing.push(current.clone());
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
    fs::create_dir_all(path)?;
    if let Some(user) = user {
        for dir in missing.iter().rev() {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
            give_to_user(dir, Some(user));
        }
    }
    Ok(())
}

/// The `.lua` files directly inside `dir`, sorted, without recursing.
pub fn top_level_scripts(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lua"))
            && entry.file_type()?.is_file()
        {
            files.push(path);
        }
    }
    files.sort_by_cached_key(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
    });
    Ok(files)
}

/// Reads a script for the preview, capped so a huge file cannot stall us.
pub fn read_preview(path: &Path) -> Result<Vec<String>, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let cut = bytes.len().min(PREVIEW_MAX_BYTES);
    let text = String::from_utf8_lossy(&bytes[..cut]);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if lines.len() > PREVIEW_MAX_LINES {
        lines.truncate(PREVIEW_MAX_LINES);
        lines.push("… (preview truncated)".into());
    } else if cut < bytes.len() {
        lines.push("… (preview truncated)".into());
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(dir: &Path) -> ScriptsRoot {
        ScriptsRoot {
            dir: dir.to_path_buf(),
            explicit: true,
            user: None,
        }
    }

    #[test]
    fn relative_paths_stay_inside_and_get_the_lua_suffix() {
        let root = root(Path::new("/scripts"));
        assert_eq!(
            root.resolve_new("thing").unwrap(),
            PathBuf::from("/scripts/thing.lua")
        );
        assert_eq!(
            root.resolve_new("things/meow.lua").unwrap(),
            PathBuf::from("/scripts/things/meow.lua")
        );
        assert_eq!(
            root.resolve_new("things/MIA.LUA").unwrap(),
            PathBuf::from("/scripts/things/MIA.LUA")
        );
        assert_eq!(
            root.resolve_new("./thing.lua").unwrap(),
            PathBuf::from("/scripts/thing.lua")
        );
    }

    #[test]
    fn escapes_and_other_extensions_are_rejected() {
        let root = root(Path::new("/scripts"));
        assert!(root.resolve_new("../escape.lua").is_err());
        assert!(root.resolve_new("/etc/passwd.lua").is_err());
        assert!(root.resolve_new("thing.txt").is_err());
        assert!(root.resolve_new("").is_err());
        assert!(root.resolve_new("things/").is_err());
    }

    #[test]
    fn tilde_expands_only_at_the_start() {
        let home = Path::new("/home/sora");
        assert_eq!(expand_tilde("~", Some(home)), PathBuf::from("/home/sora"));
        assert_eq!(
            expand_tilde("~/games", Some(home)),
            PathBuf::from("/home/sora/games")
        );
        assert_eq!(expand_tilde("/tmp/x", Some(home)), PathBuf::from("/tmp/x"));
        assert_eq!(expand_tilde("~/x", None), PathBuf::from("~/x"));
    }

    #[test]
    fn new_scripts_are_created_once() {
        let dir = env::temp_dir().join(format!("scanmem-tui-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let root = root(&dir);
        let path = root.write_new("nested/meow", "return 1\n").unwrap();
        assert_eq!(path, dir.join("nested/meow.lua"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "return 1\n");
        assert!(root.write_new("nested/meow.lua", "x").is_err());
        assert!(root.is_managed(&path));
        assert!(!root.is_managed(Path::new("/etc/passwd")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn previews_are_capped() {
        let dir = env::temp_dir().join(format!("scanmem-tui-preview-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.lua");
        fs::write(&path, vec![b'a'; PREVIEW_MAX_BYTES + 10]).unwrap();
        let lines = read_preview(&path).unwrap();
        assert!(lines.last().unwrap().contains("truncated"));
        let _ = fs::remove_dir_all(&dir);
    }
}
