//! The scanmem child process and the thread that reads its output.

use super::parse::{parse_progress, parse_sentinel, sentinel_command, strip_prompt};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

const EXIT_GRACE: Duration = Duration::from_millis(500);

pub enum BackendEvent {
    /// Region progress during a scan (`03/06 searching ...`).
    Progress { done: u32, total: u32 },
    /// All output belonging to one batch of commands.
    Done { id: u64, lines: Vec<String> },
    /// scanmem went away; carries whatever it printed last.
    Exited(Vec<String>),
}

pub struct Backend {
    child: Child,
    stdin: ChildStdin,
    next_id: u64,
}

impl Backend {
    pub fn spawn(path: &str) -> io::Result<(Backend, Receiver<BackendEvent>)> {
        let mut child = spawn_with_merged_output(path)?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("scanmem-reader".into())
            .spawn(move || read_events(stdout, &tx))?;
        Ok((
            Backend {
                child,
                stdin,
                next_id: 1,
            },
            rx,
        ))
    }

    /// Send a batch of commands; the matching `Done` event carries its output.
    pub fn send(&mut self, commands: &[String]) -> io::Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let mut script = String::new();
        for command in commands {
            // A stray newline would be run as a second command.
            script.push_str(&command.replace(['\n', '\r'], " "));
            script.push('\n');
        }
        script.push_str(&sentinel_command(id));
        self.stdin.write_all(script.as_bytes())?;
        self.stdin.flush()?;
        Ok(id)
    }

    /// Ask a running scan to stop (scanmem handles SIGINT gracefully).
    pub fn interrupt(&self) {
        // SAFETY: plain kill(2) on our own child's pid.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGINT);
        }
    }

    fn ask_to_exit(&mut self) {
        let _ = self.stdin.write_all(b"exit\n");
        let _ = self.stdin.flush();
    }

    fn exited_within(&mut self, grace: Duration) -> bool {
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.ask_to_exit();
        if !self.exited_within(EXIT_GRACE) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// `sh -c 'exec "$0" 2>&1' PATH` keeps scanmem's pid but merges stderr into
/// stdout, so everything arrives as one ordered stream.
fn spawn_with_merged_output(path: &str) -> io::Result<Child> {
    Command::new("sh")
        .arg("-c")
        .arg(r#"exec "$0" 2>&1"#)
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

fn read_events(stdout: impl Read, tx: &Sender<BackendEvent>) {
    let mut stream = BufReader::new(stdout);
    let mut batch: Vec<String> = Vec::new();
    while let Some(line) = read_line(&mut stream) {
        if let Some(id) = parse_sentinel(&line) {
            let _ = tx.send(BackendEvent::Done {
                id,
                lines: std::mem::take(&mut batch),
            });
        } else if let Some((done, total)) = parse_progress(&line) {
            let _ = tx.send(BackendEvent::Progress { done, total });
        } else if !line.trim().is_empty() {
            batch.push(line);
        }
    }
    let _ = tx.send(BackendEvent::Exited(batch));
}

/// The next output line with scanmem's prompt peeled off; `None` at EOF.
fn read_line(stream: &mut impl BufRead) -> Option<String> {
    let mut raw = Vec::new();
    match stream.read_until(b'\n', &mut raw) {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            let text = String::from_utf8_lossy(&raw);
            Some(strip_prompt(text.trim_end_matches(['\n', '\r'])).to_string())
        }
    }
}
