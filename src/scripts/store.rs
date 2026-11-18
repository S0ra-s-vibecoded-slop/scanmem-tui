//! The session's script list: files, enabled flags, and per-script logs.
//!
//! Nothing here is persisted. Imports point at the original file (so edits
//! outside the TUI show up on reload), and only the files we create through
//! `n` are guaranteed to live in the scripts folder.

use super::paths::{self, ScriptsRoot};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

/// How many log lines each script keeps.
pub const LOG_LINES: usize = 500;

/// The skeleton written by `n`.
const TEMPLATE: &str = "\
-- Runs while the script is enabled.
-- on_tick receives the milliseconds since the previous tick.

on_start = function()
end

on_tick = function(dt_ms)
end

on_stop = function()
end
";

pub struct Script {
    pub id: u64,
    pub path: PathBuf,
    /// File stem, as shown in the sidebar.
    pub name: String,
    pub enabled: bool,
    /// Why the script was last disabled (shown next to the name).
    pub problem: Option<String>,
    log: VecDeque<String>,
}

impl Script {
    fn new(id: u64, path: PathBuf) -> Script {
        let name = path.file_stem().map_or_else(
            || path.display().to_string(),
            |stem| stem.to_string_lossy().into_owned(),
        );
        Script {
            id,
            path,
            name,
            enabled: false,
            problem: None,
            log: VecDeque::new(),
        }
    }

    pub fn log(&self) -> impl Iterator<Item = &String> {
        self.log.iter()
    }

    fn push_line(&mut self, line: String) {
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }
}

pub struct Scripts {
    pub root: ScriptsRoot,
    list: Vec<Script>,
    pub selected: usize,
    next_id: u64,
    preview: Vec<String>,
    pub preview_scroll: usize,
}

impl Scripts {
    pub fn new(root: ScriptsRoot) -> Scripts {
        Scripts {
            root,
            list: Vec::new(),
            selected: 0,
            next_id: 1,
            preview: Vec::new(),
            preview_scroll: 0,
        }
    }

    /// With an explicit `--scripts-dir`, load what is already there (all off).
    /// The default cache folder is never auto-loaded. Returns a message when
    /// the folder itself could not be read.
    pub fn load_startup(&mut self) -> Option<String> {
        if !self.root.explicit {
            return None;
        }
        if let Err(error) = self.root.ensure() {
            return Some(format!("cannot create the scripts folder: {error}"));
        }
        match paths::top_level_scripts(&self.root.dir) {
            Ok(files) => {
                for file in files {
                    let _ = self.add(file);
                }
                self.select(0);
                None
            }
            Err(error) => Some(format!("cannot read {}: {error}", self.root.dir.display())),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn scripts(&self) -> &[Script] {
        &self.list
    }

    pub fn selected_script(&self) -> Option<&Script> {
        self.list.get(self.selected)
    }

    pub fn by_id_mut(&mut self, id: u64) -> Option<&mut Script> {
        self.list.iter_mut().find(|script| script.id == id)
    }

    pub fn select(&mut self, index: usize) {
        if self.list.is_empty() {
            self.selected = 0;
            self.preview.clear();
            self.preview_scroll = 0;
            return;
        }
        let index = index.min(self.list.len() - 1);
        if index != self.selected {
            self.preview_scroll = 0;
        }
        self.selected = index;
        self.refresh_preview();
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.list.is_empty() {
            return;
        }
        let last = self.list.len() - 1;
        let index = self.selected.saturating_add_signed(delta).min(last);
        self.select(index);
    }

    /// Adds a file by reference; duplicates (same canonical path) are ignored.
    /// Returns the index of the script, or `None` when it was already listed.
    fn add(&mut self, path: PathBuf) -> Option<usize> {
        let path = path.canonicalize().unwrap_or(path);
        if self.list.iter().any(|script| script.path == path) {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.list.push(Script::new(id, path));
        Some(self.list.len() - 1)
    }

    /// Imports a file or a folder (top-level `*.lua` only). Returns how many
    /// scripts were added.
    pub fn import(&mut self, text: &str) -> Result<usize, String> {
        let path = self.root.expand(text);
        let meta =
            fs::metadata(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let files = if meta.is_dir() {
            let files = paths::top_level_scripts(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            if files.is_empty() {
                return Err(format!("no .lua files in {}", path.display()));
            }
            files
        } else {
            if !is_lua(&path) {
                return Err("only .lua scripts can be imported".into());
            }
            vec![path]
        };
        let mut added = 0;
        let mut first = None;
        for file in files {
            if let Some(index) = self.add(file) {
                added += 1;
                first.get_or_insert(index);
            }
        }
        if let Some(index) = first {
            self.select(index);
        }
        if added == 0 {
            return Err("all of those scripts are already listed".into());
        }
        Ok(added)
    }

    /// Creates a script inside the scripts folder and selects it. `text` is a
    /// path relative to the folder (`things/meow.lua`).
    pub fn create(&mut self, text: &str) -> Result<PathBuf, String> {
        let path = self.root.write_new(text, TEMPLATE)?;
        if let Some(index) = self.add(path.clone()) {
            self.select(index);
        }
        Ok(path)
    }

    /// Removes the selected script from the list, leaving its file alone.
    pub fn delist_selected(&mut self) -> Option<Script> {
        if self.list.is_empty() {
            return None;
        }
        let script = self.list.remove(self.selected);
        let next = self.selected.min(self.list.len().saturating_sub(1));
        self.selected = 0;
        self.select(next);
        Some(script)
    }

    /// Deletes the selected script's file, but only inside the scripts folder.
    pub fn delete_selected_file(&mut self) -> Result<PathBuf, String> {
        let Some(script) = self.list.get(self.selected) else {
            return Err("nothing is selected".into());
        };
        if !self.root.is_managed(&script.path) {
            return Err("that file lives outside the scripts folder; delete it yourself".into());
        }
        fs::remove_file(&script.path)
            .map_err(|e| format!("cannot delete {}: {e}", script.path.display()))?;
        let path = script.path.clone();
        self.delist_selected();
        Ok(path)
    }

    /// The current preview (read-only lines of the selected script).
    pub fn preview(&self) -> &[String] {
        &self.preview
    }

    pub fn scroll_preview(&mut self, delta: isize) {
        let max = self.preview.len().saturating_sub(1);
        self.preview_scroll = self.preview_scroll.saturating_add_signed(delta).min(max);
    }

    pub fn refresh_preview(&mut self) {
        self.preview = match self.list.get(self.selected) {
            Some(script) => paths::read_preview(&script.path).unwrap_or_else(|error| vec![error]),
            None => Vec::new(),
        };
        let max = self.preview.len().saturating_sub(1);
        self.preview_scroll = self.preview_scroll.min(max);
    }

    /// The selected file's text, for (re)compiling or editing.
    pub fn source(&self) -> Result<(u64, String, String), String> {
        let script = self
            .list
            .get(self.selected)
            .ok_or_else(|| "nothing is selected".to_string())?;
        read_source(script)
    }

    /// Like [`Scripts::source`], but for a file already in the list.
    pub fn source_for(&self, path: &Path) -> Result<(u64, String, String), String> {
        let script = self
            .list
            .iter()
            .find(|script| script.path == path)
            .ok_or_else(|| format!("{} is not in the list", path.display()))?;
        read_source(script)
    }

    pub fn log_line(&mut self, id: u64, line: String) {
        if let Some(script) = self.by_id_mut(id) {
            script.push_line(line);
        }
    }

    /// Empties a script's log, so a reload starts with a clean console.
    pub fn clear_log(&mut self, id: u64) {
        if let Some(script) = self.by_id_mut(id) {
            script.log.clear();
        }
    }

    /// Marks a script off after the engine reported an error.
    pub fn mark_off(&mut self, id: u64, reason: String) {
        if let Some(script) = self.by_id_mut(id) {
            script.enabled = false;
            // A requested stop is not a problem worth flagging in the sidebar.
            script.problem = (reason != "stopped").then_some(reason);
        }
    }

    /// Turns every enabled script off, keeping their logs.
    pub fn mark_all_off(&mut self) -> Vec<u64> {
        let mut ids = Vec::new();
        for script in &mut self.list {
            if script.enabled {
                script.enabled = false;
                ids.push(script.id);
            }
        }
        ids
    }
}

fn is_lua(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lua"))
}

fn read_source(script: &Script) -> Result<(u64, String, String), String> {
    let source = fs::read_to_string(&script.path)
        .map_err(|e| format!("cannot read {}: {e}", script.path.display()))?;
    Ok((script.id, script.name.clone(), source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripts::paths::User;
    use std::fmt::Write as _;

    fn temp_root() -> ScriptsRoot {
        let dir = std::env::temp_dir().join(format!(
            "scanmem-tui-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        ScriptsRoot {
            dir,
            explicit: true,
            user: None::<User>,
        }
    }

    #[test]
    fn imports_files_and_ignores_duplicates() {
        let root = temp_root();
        root.ensure().unwrap();
        let file = root.dir.join("heal.lua");
        fs::write(&file, "return 1\n").unwrap();
        let mut scripts = Scripts::new(root.clone());
        assert_eq!(scripts.import(file.to_str().unwrap()), Ok(1));
        assert_eq!(
            scripts.import(file.to_str().unwrap()),
            Err("all of those scripts are already listed".into())
        );
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts.selected_script().unwrap().name, "heal");
        let _ = fs::remove_dir_all(&root.dir);
    }

    #[test]
    fn folder_imports_are_not_recursive() {
        let root = temp_root();
        fs::create_dir_all(root.dir.join("nested")).unwrap();
        fs::write(root.dir.join("a.lua"), "").unwrap();
        fs::write(root.dir.join("b.LUA"), "").unwrap();
        fs::write(root.dir.join("readme.txt"), "").unwrap();
        fs::write(root.dir.join("nested/c.lua"), "").unwrap();
        let mut scripts = Scripts::new(root.clone());
        assert_eq!(scripts.import(root.dir.to_str().unwrap()), Ok(2));
        let names: Vec<&str> = scripts
            .scripts()
            .iter()
            .map(|script| script.name.as_str())
            .collect();
        assert_eq!(names, ["a", "b"]);
        let _ = fs::remove_dir_all(&root.dir);
    }

    #[test]
    fn create_writes_the_template_and_selects_it() {
        let root = temp_root();
        let mut scripts = Scripts::new(root.clone());
        let path = scripts.create("things/meow").unwrap();
        assert_eq!(path, root.dir.join("things/meow.lua"));
        assert!(fs::read_to_string(&path).unwrap().contains("on_tick"));
        assert_eq!(scripts.selected_script().unwrap().name, "meow");
        assert!(scripts.create("things/meow.lua").is_err());
        let _ = fs::remove_dir_all(&root.dir);
    }

    #[test]
    fn only_managed_files_can_be_deleted() {
        let root = temp_root();
        root.ensure().unwrap();
        let inside = root.dir.join("inside.lua");
        fs::write(&inside, "").unwrap();
        let outside = root.dir.join("outside.txt");
        fs::write(&outside, "").unwrap();
        let mut scripts = Scripts::new(root.clone());
        scripts.import(inside.to_str().unwrap()).unwrap();
        scripts.delete_selected_file().unwrap();
        assert!(!inside.exists());
        assert!(scripts.is_empty());

        // An imported file outside the folder can only be delisted.
        let elsewhere =
            std::env::temp_dir().join(format!("scanmem-outside-{}.lua", std::process::id()));
        fs::write(&elsewhere, "").unwrap();
        scripts.import(elsewhere.to_str().unwrap()).unwrap();
        assert!(scripts.delete_selected_file().is_err());
        assert!(elsewhere.exists());
        assert!(scripts.delist_selected().is_some());
        let _ = fs::remove_file(&elsewhere);
        let _ = fs::remove_dir_all(&root.dir);
    }

    #[test]
    fn logs_are_rings() {
        let root = temp_root();
        root.ensure().unwrap();
        let file = root.dir.join("log.lua");
        fs::write(&file, "").unwrap();
        let mut scripts = Scripts::new(root);
        scripts.import(file.to_str().unwrap()).unwrap();
        let id = scripts.selected_script().unwrap().id;
        for n in 0..(LOG_LINES + 10) {
            scripts.log_line(id, format!("line {n}"));
        }
        let script = scripts.selected_script().unwrap();
        assert_eq!(script.log().count(), LOG_LINES);
        assert_eq!(script.log().next().unwrap(), "line 10");
    }

    #[test]
    fn clearing_a_log_leaves_it_empty() {
        let root = temp_root();
        root.ensure().unwrap();
        let file = root.dir.join("clear.lua");
        fs::write(&file, "").unwrap();
        let mut scripts = Scripts::new(root.clone());
        scripts.import(file.to_str().unwrap()).unwrap();
        let id = scripts.selected_script().unwrap().id;
        scripts.log_line(id, "old output".into());
        scripts.clear_log(id);
        assert_eq!(scripts.selected_script().unwrap().log().count(), 0);
        scripts.log_line(id, "fresh output".into());
        let lines: Vec<&String> = scripts.selected_script().unwrap().log().collect();
        assert_eq!(lines, ["fresh output"]);
        let _ = fs::remove_dir_all(&root.dir);
    }

    #[test]
    fn preview_scroll_stops_at_the_end() {
        let root = temp_root();
        root.ensure().unwrap();
        let file = root.dir.join("long.lua");
        let mut body = String::new();
        for n in 0..100 {
            let _ = writeln!(body, "line {n}");
        }
        fs::write(&file, body).unwrap();
        let mut scripts = Scripts::new(root.clone());
        scripts.import(file.to_str().unwrap()).unwrap();
        assert_eq!(scripts.preview().len(), 100);
        scripts.scroll_preview(1000);
        assert_eq!(scripts.preview_scroll, 99);
        scripts.scroll_preview(-1000);
        assert_eq!(scripts.preview_scroll, 0);
        let _ = fs::remove_dir_all(&root.dir);
    }
}
