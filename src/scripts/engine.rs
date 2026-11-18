//! The Lua engine thread: script lifecycle, budgets, and the `mem` API.
//!
//! Every enabled script owns one Lua state, and every state lives on this
//! thread. The UI never enters Lua: it sends commands and drains events, so a
//! slow or looping script can only stall itself. Each callback runs under an
//! instruction/time budget (a debug hook), and disabling a script calls
//! `on_stop` and drops its state, so nothing outlives its script.

use crate::address::resolve_expression;
use crate::datatype::DataType;
use mlua::{
    Error, Function, HookTriggers, IntoLuaMulti, Lua, LuaOptions, StdLib, Table, UserData,
    UserDataFields, UserDataMethods, Value, Variadic, VmState,
};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How often `on_tick` runs while a script is enabled.
const TICK: Duration = Duration::from_millis(100);
/// What one callback (`on_start`, `on_tick`, `on_stop`, or the top level) may
/// spend before it is aborted.
const BUDGET: Duration = Duration::from_millis(20);
/// VM instructions between budget checks.
const INSTRUCTIONS: u32 = 100_000;
/// Consecutive runtime errors before a script is disabled.
const MAX_STRIKES: u32 = 5;
const BUDGET_MESSAGE: &str = "script exceeded its time budget";

/// Process memory as the scripting layer sees it; tests substitute a fake.
pub trait Memory: Send + Sync + 'static {
    fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()>;
    fn write(&self, addr: u64, data: &[u8]) -> io::Result<()>;
}

impl Memory for crate::memio::MemIo {
    fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.read_into(addr, buf)
    }

    fn write(&self, addr: u64, data: &[u8]) -> io::Result<()> {
        crate::memio::MemIo::write(self, addr, data)
    }
}

/// A saved address as scripts see it: for `mem:get` and for freeze warnings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub name: String,
    pub addr: u64,
    pub ty: DataType,
    pub frozen: bool,
}

/// Messages from the UI to the engine thread.
pub enum Command {
    /// A different process, or none at all.
    Memory(Option<Arc<dyn Memory>>),
    /// The saved list changed.
    Labels(Vec<Label>),
    /// Start a script; a script already using this id is stopped first.
    Enable {
        id: u64,
        name: String,
        source: String,
    },
    Disable(u64),
    Shutdown,
}

/// Messages from the engine thread to the UI.
#[derive(Debug)]
pub enum Event {
    /// One line of script output (or an error) for `id`'s log pane.
    Output { id: u64, line: String },
    /// The script is off now; `reason` is shown in the status line.
    Disabled { id: u64, reason: String },
    /// `mem:freeze(label, value)`: apply to the saved row with this label.
    Freeze {
        label: String,
        bytes: Vec<u8>,
        display: String,
    },
    /// `mem:unfreeze(label)`.
    Unfreeze { label: String },
}

/// The handle the UI keeps: a command sender, an event receiver, and the thread.
pub struct Engine {
    commands: Option<Sender<Command>>,
    pub events: Receiver<Event>,
    thread: Option<JoinHandle<()>>,
}

impl Engine {
    pub fn start(full_stdlib: bool) -> Engine {
        let (commands, command_rx) = mpsc::channel();
        let (event_tx, events) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("lua".into())
            .spawn(move || Worker::new(command_rx, event_tx, full_stdlib).run())
            .expect("spawn the Lua engine thread");
        Engine {
            commands: Some(commands),
            events,
            thread: Some(thread),
        }
    }

    fn send(&self, command: Command) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(command);
        }
    }

    pub fn set_memory(&self, memory: Option<Arc<dyn Memory>>) {
        self.send(Command::Memory(memory));
    }

    pub fn set_labels(&self, labels: Vec<Label>) {
        self.send(Command::Labels(labels));
    }

    pub fn enable(&self, id: u64, name: String, source: String) {
        self.send(Command::Enable { id, name, source });
    }

    pub fn disable(&self, id: u64) {
        self.send(Command::Disable(id));
    }

    /// Stop the thread, waiting for the current callback to hit its budget.
    pub fn shutdown(&mut self) {
        if let Some(commands) = self.commands.take() {
            let _ = commands.send(Command::Shutdown);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// State shared by every handle of one script.
struct Shared {
    id: u64,
    memory: Arc<Mutex<Option<Arc<dyn Memory>>>>,
    labels: Arc<Mutex<HashMap<String, Label>>>,
    events: Sender<Event>,
    /// Set while a callback runs; the debug hook aborts once it passes.
    deadline: Arc<Mutex<Option<Instant>>>,
    /// Set by the hook so a timeout is never mistaken for a normal error.
    timed_out: Arc<AtomicBool>,
    /// Set by API calls that must disable the script immediately.
    hard: Mutex<Option<String>>,
}

impl Shared {
    fn output(&self, line: impl Into<String>) {
        let _ = self.events.send(Event::Output {
            id: self.id,
            line: line.into(),
        });
    }

    /// A failure that only counts towards the strike limit.
    fn soft(message: impl Into<String>) -> Error {
        Error::RuntimeError(message.into())
    }

    /// A failure that disables the script right away.
    fn hard(&self, message: impl Into<String>) -> Error {
        let message = message.into();
        *self.hard.lock().unwrap() = Some(message.clone());
        Error::RuntimeError(message)
    }

    /// A label by name, case-insensitively.
    fn label(&self, name: &str) -> Option<Label> {
        self.labels
            .lock()
            .unwrap()
            .get(&name.to_ascii_lowercase())
            .cloned()
    }

    fn memory(&self) -> Result<Arc<dyn Memory>, Error> {
        self.memory
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Self::soft("no process is attached"))
    }
}

/// A typed window into the target's memory, as handed to Lua.
#[derive(Clone)]
struct Handle {
    addr: u64,
    ty: DataType,
    /// The saved label this came from, if any (used for freeze warnings).
    label: Option<String>,
    shared: Arc<Shared>,
}

impl Handle {
    fn effective_type(&self, name: Option<&str>) -> Result<DataType, Error> {
        let Some(name) = name else {
            return Ok(self.ty);
        };
        name.parse::<DataType>()
            .map_err(|message| self.shared.hard(message))
    }

    fn read(&self, ty: Option<&str>) -> Result<Value, Error> {
        let ty = self.effective_type(ty)?;
        let memory = self.shared.memory()?;
        let mut buf = [0u8; 8];
        memory
            .read(self.addr, &mut buf[..ty.size()])
            .map_err(|e| Shared::soft(format!("cannot read 0x{:x}: {e}", self.addr)))?;
        Ok(decode(ty, &buf[..ty.size()]))
    }

    fn write(&self, value: &Value, ty: Option<&str>) -> Result<(), Error> {
        let ty = self.effective_type(ty)?;
        let bytes = encode(ty, value).map_err(Shared::soft)?;
        let memory = self.shared.memory()?;
        memory
            .write(self.addr, &bytes)
            .map_err(|e| Shared::soft(format!("cannot write 0x{:x}: {e}", self.addr)))?;
        if let Some(label) = self
            .label
            .as_deref()
            .filter(|label| self.shared.label(label).is_some_and(|label| label.frozen))
        {
            self.shared.output(format!(
                "warning: `{label}` is frozen; the freezer will write over this"
            ));
        }
        Ok(())
    }

    fn offset(&self, offset: i64) -> Result<Handle, Error> {
        let addr = if offset >= 0 {
            self.addr.checked_add(offset.unsigned_abs())
        } else {
            self.addr.checked_sub(offset.unsigned_abs())
        }
        .ok_or_else(|| Shared::soft("address out of range"))?;
        Ok(Handle {
            addr,
            ..self.clone()
        })
    }
}

impl UserData for Handle {
    fn add_fields<F: UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("addr", |_, handle| Ok(handle.addr));
        fields.add_field_method_get("ty", |_, handle| Ok(handle.ty.scanmem_name()));
    }

    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("read", |_, handle, ty: Option<String>| {
            handle.read(ty.as_deref())
        });
        methods.add_method(
            "write",
            |_, handle, (value, ty): (Value, Option<String>)| handle.write(&value, ty.as_deref()),
        );
        methods.add_method("offset", |_, handle, offset: i64| handle.offset(offset));
        methods.add_method("type", |_, handle, name: String| {
            let ty = handle.effective_type(Some(&name))?;
            Ok(Handle {
                ty,
                ..handle.clone()
            })
        });
    }
}

/// Bytes read from memory as the Lua value the type implies.
fn decode(ty: DataType, bytes: &[u8]) -> Value {
    match ty {
        DataType::I8 => Value::Integer(i64::from(i8::from_le_bytes(bytes.try_into().unwrap()))),
        DataType::I16 => Value::Integer(i64::from(i16::from_le_bytes(bytes.try_into().unwrap()))),
        DataType::I32 => Value::Integer(i64::from(i32::from_le_bytes(bytes.try_into().unwrap()))),
        DataType::I64 => Value::Integer(i64::from_le_bytes(bytes.try_into().unwrap())),
        DataType::F32 => Value::Number(f64::from(f32::from_le_bytes(bytes.try_into().unwrap()))),
        DataType::F64 => Value::Number(f64::from_le_bytes(bytes.try_into().unwrap())),
    }
}

/// A Lua value converted to the bytes `ty` means (conversion, not bit-casting).
fn encode(ty: DataType, value: &Value) -> Result<Vec<u8>, String> {
    if ty.is_float() {
        let number = match value {
            Value::Integer(n) => {
                #[expect(clippy::cast_precision_loss)]
                let number = *n as f64;
                number
            }
            Value::Number(n) => *n,
            Value::String(text) => {
                let text = text.to_string_lossy();
                text.trim()
                    .parse::<f64>()
                    .map_err(|_| format!("`{text}` is not a number"))?
            }
            other => {
                return Err(format!(
                    "{} needs a number, got {}",
                    ty.scanmem_name(),
                    other.type_name()
                ));
            }
        };
        if ty == DataType::F32 {
            #[expect(clippy::cast_possible_truncation)]
            let narrowed = number as f32;
            if narrowed.is_infinite() && number.is_finite() {
                return Err(format!("{number} overflows float32"));
            }
            return Ok(narrowed.to_le_bytes().to_vec());
        }
        return Ok(number.to_le_bytes().to_vec());
    }
    let integer: i128 = match value {
        Value::Integer(n) => i128::from(*n),
        Value::Number(n) => {
            if !n.is_finite() || n.fract() != 0.0 {
                return Err(format!(
                    "{n} is not a whole number ({} needs one)",
                    ty.scanmem_name()
                ));
            }
            whole_number(*n)
        }
        Value::String(text) => {
            let text = text
                .to_str()
                .map_err(|_| "the value string is not valid UTF-8".to_string())?;
            crate::datatype::parse_int(&text)
                .ok_or_else(|| format!("`{text}` is not a valid integer"))?
        }
        other => {
            return Err(format!(
                "{} needs an integer, got {}",
                ty.scanmem_name(),
                other.type_name()
            ));
        }
    };
    ty.encode_int(integer)
}

/// An exactly-integral float as an integer; callers check the fraction first.
#[expect(clippy::cast_possible_truncation)]
fn whole_number(n: f64) -> i128 {
    n as i128
}

/// One running script: its state, its callbacks, and its error streak.
struct Script {
    name: String,
    lua: Lua,
    shared: Arc<Shared>,
    on_tick: Option<Function>,
    on_stop: Option<Function>,
    strikes: u32,
    last_tick: Instant,
}

impl Script {
    fn create(
        id: u64,
        name: String,
        memory: Arc<Mutex<Option<Arc<dyn Memory>>>>,
        labels: Arc<Mutex<HashMap<String, Label>>>,
        events: Sender<Event>,
        full_stdlib: bool,
    ) -> Result<Script, String> {
        let shared = Arc::new(Shared {
            id,
            memory,
            labels,
            events,
            deadline: Arc::new(Mutex::new(None)),
            timed_out: Arc::new(AtomicBool::new(false)),
            hard: Mutex::new(None),
        });
        let libs = if full_stdlib {
            StdLib::ALL_SAFE
        } else {
            StdLib::MATH
                | StdLib::STRING
                | StdLib::TABLE
                | StdLib::UTF8
                | StdLib::COROUTINE
                | StdLib::OS
        };
        let lua = Lua::new_with(libs, LuaOptions::default()).map_err(|e| e.to_string())?;
        install_budget(&lua, &shared).map_err(|e| e.to_string())?;
        install_print(&lua, &shared).map_err(|e| e.to_string())?;
        restrict(&lua, full_stdlib).map_err(|e| e.to_string())?;
        install_mem(&lua, &shared).map_err(|e| e.to_string())?;
        Ok(Script {
            name,
            lua,
            shared,
            on_tick: None,
            on_stop: None,
            strikes: 0,
            last_tick: Instant::now(),
        })
    }

    /// Runs the chunk and remembers the hooks it defined.
    fn load(&mut self, source: &str) -> Result<(), String> {
        *self.shared.deadline.lock().unwrap() = Some(Instant::now() + BUDGET);
        let result = self.lua.load(source).set_name(self.name.clone()).exec();
        *self.shared.deadline.lock().unwrap() = None;
        if self.shared.timed_out.swap(false, Ordering::Relaxed) {
            return Err(BUDGET_MESSAGE.into());
        }
        result.map_err(|e| e.to_string())?;
        let globals = self.lua.globals();
        self.on_tick = globals
            .get("on_tick")
            .map_err(|e| format!("on_tick: {e}"))?;
        self.on_stop = globals
            .get("on_stop")
            .map_err(|e| format!("on_stop: {e}"))?;
        Ok(())
    }

    fn on_start(&self) -> Result<Option<Function>, String> {
        self.lua
            .globals()
            .get("on_start")
            .map_err(|e| format!("on_start: {e}"))
    }

    fn call(&self, function: &Function, args: impl IntoLuaMulti) -> Result<(), Error> {
        *self.shared.deadline.lock().unwrap() = Some(Instant::now() + BUDGET);
        let result = function.call::<()>(args);
        *self.shared.deadline.lock().unwrap() = None;
        result
    }

    fn take_hard(&self) -> Option<String> {
        self.shared.hard.lock().unwrap().take()
    }

    fn take_timeout(&self) -> bool {
        self.shared.timed_out.swap(false, Ordering::Relaxed)
    }
}

/// Calls `on_stop` if it exists, reporting anything it raises.
fn finish(script: &mut Script) {
    let Some(on_stop) = script.on_stop.take() else {
        return;
    };
    if let Err(error) = script.call(&on_stop, ()) {
        let message = script.take_hard().unwrap_or_else(|| error.to_string());
        script.shared.output(format!("on_stop: {message}"));
    }
}

/// The engine thread's state.
struct Worker {
    commands: Receiver<Command>,
    events: Sender<Event>,
    memory: Arc<Mutex<Option<Arc<dyn Memory>>>>,
    labels: Arc<Mutex<HashMap<String, Label>>>,
    full_stdlib: bool,
    scripts: HashMap<u64, Script>,
    last_tick: Instant,
}

impl Worker {
    fn new(commands: Receiver<Command>, events: Sender<Event>, full_stdlib: bool) -> Worker {
        Worker {
            commands,
            events,
            memory: Arc::new(Mutex::new(None)),
            labels: Arc::new(Mutex::new(HashMap::new())),
            full_stdlib,
            scripts: HashMap::new(),
            last_tick: Instant::now(),
        }
    }

    fn run(mut self) {
        loop {
            let wait = TICK.saturating_sub(self.last_tick.elapsed());
            match self.commands.recv_timeout(wait) {
                Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                Ok(command) => self.handle(command),
                Err(RecvTimeoutError::Timeout) => {}
            }
            if self.drain() {
                break;
            }
            if self.last_tick.elapsed() >= TICK {
                self.tick();
                self.last_tick = Instant::now();
            }
        }
        let ids: Vec<u64> = self.scripts.keys().copied().collect();
        for id in ids {
            self.stop(id, "the engine is shutting down", false);
        }
    }

    /// Handles commands without waiting; true means "shut down".
    fn drain(&mut self) -> bool {
        loop {
            match self.commands.try_recv() {
                Ok(Command::Shutdown) | Err(TryRecvError::Disconnected) => return true,
                Ok(command) => self.handle(command),
                Err(TryRecvError::Empty) => return false,
            }
        }
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Memory(memory) => {
                if memory.is_none() {
                    let ids: Vec<u64> = self.scripts.keys().copied().collect();
                    for id in ids {
                        self.stop(id, "the target is gone", true);
                    }
                }
                *self.memory.lock().unwrap() = memory;
            }
            Command::Labels(labels) => {
                let labels = labels
                    .into_iter()
                    .map(|label| (label.name.to_ascii_lowercase(), label))
                    .collect();
                *self.labels.lock().unwrap() = labels;
            }
            Command::Enable { id, name, source } => self.enable(id, &name, &source),
            Command::Disable(id) => self.stop(id, "stopped", true),
            Command::Shutdown => {}
        }
    }

    fn enable(&mut self, id: u64, name: &str, source: &str) {
        self.stop(id, "reloaded", false);
        let mut script = match Script::create(
            id,
            name.to_string(),
            self.memory.clone(),
            self.labels.clone(),
            self.events.clone(),
            self.full_stdlib,
        ) {
            Ok(script) => script,
            Err(message) => return self.report_off(id, name, &message),
        };
        if let Err(message) = script.load(source) {
            return self.report_off(id, name, &message);
        }
        if let Some(hard) = script.take_hard() {
            return self.report_off(id, name, &hard);
        }
        let on_start = match script.on_start() {
            Ok(on_start) => on_start,
            Err(message) => return self.report_off(id, name, &message),
        };
        if let Some(on_start) = on_start {
            match script.call(&on_start, ()) {
                Ok(()) => {
                    let hard = script.take_hard();
                    let timeout = script.take_timeout();
                    if let Some(hard) = hard {
                        return self.report_off(id, name, &hard);
                    }
                    if timeout {
                        return self.report_off(id, name, BUDGET_MESSAGE);
                    }
                }
                Err(error) => {
                    let hard = script.take_hard();
                    let timeout = script.take_timeout();
                    let immediate = hard.is_some() || timeout;
                    let message = hard.unwrap_or_else(|| error.to_string());
                    if immediate {
                        return self.report_off(id, name, &message);
                    }
                    script.shared.output(format!("error: {message}"));
                    script.strikes = 1;
                }
            }
        }
        script.shared.output(format!("enabled `{name}`"));
        self.scripts.insert(id, script);
    }

    /// Reports a script that could not start, staying off.
    fn report_off(&self, id: u64, name: &str, message: &str) {
        let _ = self.events.send(Event::Output {
            id,
            line: format!("error: {message}"),
        });
        let _ = self.events.send(Event::Disabled {
            id,
            reason: format!("{name}: {message}"),
        });
    }

    /// Stops `id` if it is running; `announce` sends the event that turns the
    /// script off in the UI.
    fn stop(&mut self, id: u64, reason: &str, announce: bool) {
        let Some(mut script) = self.scripts.remove(&id) else {
            return;
        };
        finish(&mut script);
        if announce {
            let message = if reason == "stopped" {
                "stopped".to_string()
            } else {
                format!("stopped: {reason}")
            };
            script.shared.output(message);
            let _ = self.events.send(Event::Disabled {
                id,
                reason: reason.to_string(),
            });
        }
    }

    fn tick(&mut self) {
        let ids: Vec<u64> = self.scripts.keys().copied().collect();
        let mut failed = Vec::new();
        for id in ids {
            let Some(script) = self.scripts.get_mut(&id) else {
                continue;
            };
            let dt = u64::try_from(script.last_tick.elapsed().as_millis()).unwrap_or(u64::MAX);
            script.last_tick = Instant::now();
            let Some(on_tick) = script.on_tick.clone() else {
                script.strikes = 0;
                continue;
            };
            match script.call(&on_tick, dt) {
                Ok(()) => {
                    script.strikes = 0;
                    // A script can catch a hard API error with pcall; the
                    // mistake is still fatal.
                    if let Some(hard) = script.take_hard() {
                        failed.push((id, hard));
                    } else if script.take_timeout() {
                        failed.push((id, BUDGET_MESSAGE.to_string()));
                    }
                }
                Err(error) => {
                    let hard = script.take_hard();
                    let timeout = script.take_timeout();
                    let immediate = hard.is_some() || timeout;
                    let message = hard.unwrap_or_else(|| error.to_string());
                    script.shared.output(format!("error: {message}"));
                    script.strikes += 1;
                    let fatal = immediate || script.strikes >= MAX_STRIKES;
                    if fatal {
                        failed.push((id, message));
                    }
                }
            }
        }
        for (id, message) in failed {
            self.stop(id, &message, true);
        }
    }
}

/// Arms the budget hook: every callback gets `BUDGET` from the moment it starts.
fn install_budget(lua: &Lua, shared: &Arc<Shared>) -> Result<(), Error> {
    let deadline = shared.deadline.clone();
    let timed_out = shared.timed_out.clone();
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(INSTRUCTIONS),
        move |_, _| {
            let expired = deadline
                .lock()
                .ok()
                .and_then(|deadline| *deadline)
                .is_some_and(|deadline| Instant::now() > deadline);
            if expired {
                timed_out.store(true, Ordering::Relaxed);
                Err(Error::RuntimeError(BUDGET_MESSAGE.into()))
            } else {
                Ok(VmState::Continue)
            }
        },
    )
}

/// Sends `print` to the script's own log instead of the terminal.
fn install_print(lua: &Lua, shared: &Arc<Shared>) -> Result<(), Error> {
    let tostring: Function = lua.globals().get("tostring")?;
    let shared = shared.clone();
    let print = lua.create_function(move |_, values: Variadic<Value>| {
        let mut line = String::new();
        for (index, value) in values.into_iter().enumerate() {
            if index > 0 {
                line.push('\t');
            }
            match tostring.call::<String>(value) {
                Ok(text) => line.push_str(&text),
                Err(_) => line.push_str("<?>"),
            }
        }
        shared.output(line);
        Ok(())
    })?;
    lua.globals().set("print", print)
}

/// The default profile: no files, processes, or module loading.
fn restrict(lua: &Lua, full_stdlib: bool) -> Result<(), Error> {
    if full_stdlib {
        return Ok(());
    }
    let globals = lua.globals();
    for name in ["dofile", "loadfile", "load", "require"] {
        globals.set(name, Value::Nil)?;
    }
    let os: Table = globals.get("os")?;
    for name in [
        "execute",
        "exit",
        "getenv",
        "remove",
        "rename",
        "tmpname",
        "setlocale",
    ] {
        os.set(name, Value::Nil)?;
    }
    Ok(())
}

/// Installs the `mem` global.
fn install_mem(lua: &Lua, shared: &Arc<Shared>) -> Result<(), Error> {
    let mem = lua.create_table()?;
    {
        let shared = shared.clone();
        let get = lua.create_function(
            move |lua, (_this, target, ty): (Value, Value, Option<String>)| {
                get(lua, &shared, target, ty)
            },
        )?;
        mem.set("get", get)?;
    }
    {
        let shared = shared.clone();
        let freeze =
            lua.create_function(move |_, (_this, name, value): (Value, String, Value)| {
                freeze(&shared, &name, &value)
            })?;
        mem.set("freeze", freeze)?;
    }
    {
        let shared = shared.clone();
        let unfreeze =
            lua.create_function(move |_, (_this, name): (Value, String)| unfreeze(&shared, &name))?;
        mem.set("unfreeze", unfreeze)?;
    }
    lua.globals().set("mem", mem)
}

/// `mem:get(addr [, type])`.
fn get(
    lua: &Lua,
    shared: &Arc<Shared>,
    target: Value,
    requested: Option<String>,
) -> Result<mlua::AnyUserData, Error> {
    let requested = match requested {
        Some(name) => Some(name.parse::<DataType>().map_err(|m| shared.hard(m))?),
        None => None,
    };
    let (addr, ty, label) = match target {
        Value::Integer(address) => {
            let address =
                u64::try_from(address).map_err(|_| shared.hard("addresses cannot be negative"))?;
            let ty = requested.ok_or_else(|| {
                shared.hard("a raw address needs a type, e.g. mem:get(0x140902b8a, \"i32\")")
            })?;
            (address, ty, None)
        }
        Value::Number(number) => {
            if !number.is_finite() || number.fract() != 0.0 || number < 0.0 {
                return Err(shared.hard(format!("{number} is not an address")));
            }
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let address = number as u64;
            let ty = requested.ok_or_else(|| {
                shared.hard("a raw address needs a type, e.g. mem:get(0x140902b8a, \"i32\")")
            })?;
            (address, ty, None)
        }
        Value::String(text) => {
            let text = text.to_string_lossy();
            let base = text.split(['+', '-']).next().unwrap_or_default();
            let base_label = shared.label(base);
            let resolved = resolve_expression(&text, |name| {
                shared.label(name).map(|label| (label.addr, Some(label.ty)))
            })
            .map_err(|message| shared.hard(message))?;
            let label = base_label
                .filter(|label| label.addr == resolved.addr)
                .map(|label| label.name);
            match (resolved.ty, requested) {
                (_, Some(ty)) | (Some(ty), None) => (resolved.addr, ty, label),
                (None, None) => {
                    return Err(shared
                        .hard("a raw address needs a type, e.g. mem:get(0x140902b8a, \"i32\")"));
                }
            }
        }
        other => {
            return Err(shared.hard(format!(
                "mem:get needs a label or address, got {}",
                other.type_name()
            )));
        }
    };
    lua.create_userdata(Handle {
        addr,
        ty,
        label,
        shared: shared.clone(),
    })
}

/// `mem:freeze(label, value)`.
fn freeze(shared: &Arc<Shared>, name: &str, value: &Value) -> Result<(), Error> {
    let label = shared
        .label(name)
        .ok_or_else(|| shared.hard(format!("`{name}` is not a saved label")))?;
    let bytes = encode(label.ty, value).map_err(Shared::soft)?;
    let display = label.ty.format_bytes(&bytes);
    shared.output(format!("froze `{}` at {display}", label.name));
    let _ = shared.events.send(Event::Freeze {
        label: label.name,
        bytes,
        display,
    });
    Ok(())
}

/// `mem:unfreeze(label)`.
fn unfreeze(shared: &Arc<Shared>, name: &str) -> Result<(), Error> {
    let label = shared
        .label(name)
        .ok_or_else(|| shared.hard(format!("`{name}` is not a saved label")))?;
    shared.output(format!("unfroze `{}`", label.name));
    let _ = shared.events.send(Event::Unfreeze { label: label.name });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small byte array standing in for `/proc/<pid>/mem`.
    struct Fake {
        base: u64,
        bytes: Mutex<Vec<u8>>,
    }

    impl Fake {
        fn new(base: u64, len: usize) -> Arc<Fake> {
            Arc::new(Fake {
                base,
                bytes: Mutex::new(vec![0; len]),
            })
        }

        fn bytes(&self, addr: u64, len: usize) -> Vec<u8> {
            let start = usize::try_from(addr - self.base).unwrap();
            self.bytes.lock().unwrap()[start..start + len].to_vec()
        }
    }

    impl Memory for Fake {
        fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
            let start = addr
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|start| start + buf.len() <= self.bytes.lock().unwrap().len())
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            buf.copy_from_slice(&self.bytes.lock().unwrap()[start..start + buf.len()]);
            Ok(())
        }

        fn write(&self, addr: u64, data: &[u8]) -> io::Result<()> {
            let start = addr
                .checked_sub(self.base)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|start| start + data.len() <= self.bytes.lock().unwrap().len())
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            self.bytes.lock().unwrap()[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    fn health(frozen: bool) -> Label {
        Label {
            name: "health".into(),
            addr: 0x1000,
            ty: DataType::I32,
            frozen,
        }
    }

    fn start(source: &str, full_stdlib: bool) -> (Arc<Fake>, Engine) {
        let memory = Fake::new(0x1000, 0x100);
        let engine = Engine::start(full_stdlib);
        engine.set_memory(Some(memory.clone()));
        engine.set_labels(vec![health(false)]);
        engine.enable(1, "test.lua".into(), source.into());
        (memory, engine)
    }

    /// Drains events until the script is disabled or `wait` runs out.
    fn collect(engine: &Engine, wait: Duration) -> Vec<Event> {
        let deadline = Instant::now() + wait;
        let mut events = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match engine.events.recv_timeout(left) {
                Ok(event) => {
                    let done = matches!(event, Event::Disabled { .. });
                    events.push(event);
                    if done {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        events
    }

    fn lines(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Output { line, .. } => Some(line.clone()),
                _ => None,
            })
            .collect()
    }

    fn disabled(events: &[Event]) -> Option<String> {
        events.iter().find_map(|event| match event {
            Event::Disabled { reason, .. } => Some(reason.clone()),
            _ => None,
        })
    }

    const QUIET: Duration = Duration::from_millis(300);

    #[test]
    fn labels_read_and_write_with_offsets() {
        let (_memory, engine) = start(
            r#"
            on_start = function()
                local hp = mem:get("health")
                print(hp:read(), hp.ty, hp.addr)
                hp:write(-7)
                print(mem:get("health"):read())
                mem:get("health+4"):write("0xFFFFFFFF", "i32")
                print(mem:get("health"):offset(4):read())
            end
            "#,
            false,
        );
        let events = collect(&engine, QUIET);
        assert_eq!(
            lines(&events),
            vec!["0\tint32\t4096", "-7", "-1", "enabled `test.lua`"]
        );
        assert!(disabled(&events).is_none());
    }

    #[test]
    fn handles_reinterpret_the_same_bytes() {
        let (_memory, engine) = start(
            r#"
            on_start = function()
                local hp = mem:get(0x1000, "i32")
                hp:write(0x3f800000, "i32")
                print(hp:read("f32"))
                local as_float = hp:type("f32")
                print(as_float.ty, as_float:read())
            end
            "#,
            false,
        );
        let events = collect(&engine, QUIET);
        assert_eq!(lines(&events)[..2], ["1.0", "float32\t1.0"]);
    }

    #[test]
    fn whole_floats_are_fine_fractions_are_not() {
        let (memory, engine) = start(
            r#"
            on_start = function()
                local hp = mem:get("health")
                hp:write(25.0)
                print(hp:read())
                hp:write(1.5)
            end
            "#,
            false,
        );
        let events = collect(&engine, QUIET);
        assert_eq!(memory.bytes(0x1000, 4), 25i32.to_le_bytes());
        let lines = lines(&events);
        assert_eq!(lines[0], "25");
        assert!(lines[1].contains("not a whole number"));
    }

    #[test]
    fn a_raw_address_without_a_type_is_a_hard_error() {
        let (_memory, engine) = start("on_start = function() mem:get(0x1000) end", false);
        let events = collect(&engine, QUIET);
        assert!(
            disabled(&events)
                .unwrap()
                .contains("raw address needs a type")
        );
    }

    #[test]
    fn unknown_labels_and_types_are_hard_errors() {
        for source in [
            "on_start = function() mem:get(\"nope\") end",
            "on_start = function() mem:get(\"health\", \"u32\") end",
            "on_start = function() mem:get(\"health\"):read(\"banana\") end",
        ] {
            let (_memory, engine) = start(source, false);
            let events = collect(&engine, QUIET);
            assert!(disabled(&events).is_some(), "{source}");
        }
    }

    #[test]
    fn five_consecutive_errors_disable_a_script() {
        let (_memory, engine) = start(
            "on_tick = function(dt) mem:get(\"health\"):write(1.5) end",
            false,
        );
        let events = collect(&engine, Duration::from_secs(2));
        let errors = lines(&events)
            .into_iter()
            .filter(|line| line.starts_with("error:") && line.contains("not a whole number"))
            .count();
        assert_eq!(errors, MAX_STRIKES as usize);
        assert!(disabled(&events).is_some());
    }

    #[test]
    fn a_clean_tick_resets_the_strike_count() {
        let (_memory, engine) = start(
            r#"
            local n = 0
            on_tick = function()
                n = n + 1
                if n % 2 == 1 and n < 20 then
                    mem:get("health"):write(1.5)
                end
            end
            "#,
            false,
        );
        let events = collect(&engine, Duration::from_millis(1200));
        assert!(disabled(&events).is_none());
    }

    #[test]
    fn freeze_and_unfreeze_events_carry_the_bytes() {
        let (_memory, engine) = start(
            r#"
            on_start = function()
                mem:freeze("health", 7)
                mem:unfreeze("health")
            end
            "#,
            false,
        );
        let events = collect(&engine, QUIET);
        let freeze = events.iter().find_map(|event| match event {
            Event::Freeze {
                label,
                bytes,
                display,
            } => Some((label.clone(), bytes.clone(), display.clone())),
            _ => None,
        });
        assert_eq!(
            freeze,
            Some(("health".into(), 7i32.to_le_bytes().to_vec(), "7".into()))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Unfreeze { label } if label == "health"
        )));
    }

    #[test]
    fn writes_to_a_frozen_label_warn() {
        let memory = Fake::new(0x1000, 0x100);
        let engine = Engine::start(false);
        engine.set_memory(Some(memory));
        engine.set_labels(vec![health(true)]);
        engine.enable(
            1,
            "test.lua".into(),
            "on_start = function() mem:get(\"health\"):write(1) end".into(),
        );
        let events = collect(&engine, QUIET);
        assert!(
            lines(&events)
                .iter()
                .any(|line| line.contains("frozen; the freezer"))
        );
    }

    #[test]
    fn infinite_loops_hit_the_budget_and_disable_the_script() {
        let (_memory, engine) = start("on_start = function() while true do end end", false);
        let events = collect(&engine, Duration::from_secs(2));
        assert!(disabled(&events).is_some());
    }

    #[test]
    fn on_stop_runs_when_a_script_is_disabled() {
        let (_memory, engine) = start("on_stop = function() print(\"bye\") end", false);
        let _ = collect(&engine, QUIET);
        engine.disable(1);
        let events = collect(&engine, QUIET);
        assert!(lines(&events).contains(&"bye".to_string()));
        assert!(disabled(&events).is_some());
    }

    #[test]
    fn the_default_profile_hides_files_modules_and_processes() {
        let (_memory, engine) = start(
            r"
            on_start = function()
                print(io == nil, require == nil, load == nil, os.getenv == nil)
            end
            ",
            false,
        );
        let events = collect(&engine, QUIET);
        assert_eq!(lines(&events)[0], "true\ttrue\ttrue\ttrue");
    }

    #[test]
    fn the_full_profile_keeps_the_standard_libraries() {
        let (_memory, engine) = start(
            "on_start = function() print(load == nil, io == nil) end",
            true,
        );
        let events = collect(&engine, QUIET);
        assert_eq!(lines(&events)[0], "false\tfalse");
    }
}
