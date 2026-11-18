//! Rendering.

mod panes;
mod popups;

use crate::app::{App, InputKind, Level, Mode};
use crate::keymap;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Paragraph};
use std::time::Instant;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_FRAME_MS: u128 = 80;

pub fn draw(f: &mut Frame, app: &mut App) {
    let screen = f.area();
    let outer = outer_block(app);
    let inner = outer.inner(screen);
    f.render_widget(outer, screen);

    let [header, main, bottom, hints] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(inner);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(main);

    draw_header(f, app, header);
    panes::draw_results(f, app, left);
    panes::draw_saved(f, app, right);
    draw_bottom(f, app, bottom);
    draw_hints(f, app, hints);
    popups::draw(f, app);
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

fn rounded() -> Block<'static> {
    Block::bordered().border_type(BorderType::Rounded)
}

/// A rounded box with a coloured border and a title.
fn framed(color: Color, title: impl Into<Line<'static>>) -> Block<'static> {
    let title: Line<'static> = title.into();
    rounded().border_style(Style::new().fg(color)).title(title)
}

fn outer_block(app: &App) -> Block<'static> {
    rounded()
        .title_top(Line::from(" scanmem-tui ").bold())
        .title_bottom(Line::from(format!(" {} ", app.stats.title())).centered())
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let target = match &app.target {
        Some(target) => format!("{} (pid {})", target.name, target.pid),
        None => "none (press p)".to_string(),
    };
    let matches = if app.results.is_truncated() {
        format!("{} (showing {})", app.results.total, app.results.rows.len())
    } else {
        app.results.total.to_string()
    };
    let line = Line::from(vec![
        Span::styled(" Target ", dim()),
        Span::styled(target, Style::new().bold()),
        Span::styled("  │  Type ", dim()),
        Span::styled(
            app.scan_type.scanmem_name(),
            Style::new().bold().fg(Color::Cyan),
        ),
        Span::styled("  │  Matches ", dim()),
        Span::styled(matches, Style::new().bold()),
        Span::styled("  │  Freeze every ", dim()),
        Span::styled(
            format!("{}ms", app.freezer.interval.as_millis()),
            Style::new().bold(),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_bottom(f: &mut Frame, app: &App, area: Rect) {
    match app.mode {
        Mode::Input(kind) => draw_prompt(f, app, kind, area),
        _ => draw_status(f, app, area),
    }
}

#[expect(clippy::cast_possible_truncation)]
fn draw_prompt(f: &mut Frame, app: &App, kind: InputKind, area: Rect) {
    let block = framed(Color::Yellow, prompt_title(app, kind));
    let inner = block.inner(area);
    f.render_widget(
        Paragraph::new(format!("› {}", app.input)).block(block),
        area,
    );
    let x = inner.x + 2 + app.input.chars().count() as u16;
    f.set_cursor_position((x.min(inner.right().saturating_sub(1)), inner.y));
}

fn prompt_title(app: &App, kind: InputKind) -> String {
    match kind {
        InputKind::Scan => {
            " Scan: value | > N | < N | = | != | + | - | snapshot | reset | range <label|addr> <offset> "
                .to_string()
        }
        InputKind::SetValue(index) => match app.saved.items.get(index) {
            Some(saved) => format!(
                " Write {} value to 0x{:x} ",
                saved.ty.scanmem_name(),
                saved.addr
            ),
            None => " Write value ".to_string(),
        },
        InputKind::Label(_) => " Label (letters, digits and _) ".to_string(),
        InputKind::EditType(_) => " Type: int8/16/32/64, float32/64 ".to_string(),
        InputKind::AddAddr => {
            " Add address: <label|addr>±<offset> [type]  e.g. 7ffc8dc5328c, health+0x10, 0xaddr-0x1140 int32 "
                .to_string()
        }
    }
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let line = match (&app.job, &app.range_job) {
        (Some(job), _) => spinner_line(
            job.label,
            job.progress
                .map(|(done, total)| format!("region {done}/{total}")),
            job.since,
        ),
        (None, Some(range)) => spinner_line(
            range.label,
            range.percent().map(|percent| format!("{percent}%")),
            range.since,
        ),
        (None, None) => Line::styled(
            app.status.text.clone(),
            Style::new().fg(level_color(app.status.level)),
        ),
    };
    f.render_widget(
        Paragraph::new(line).block(framed(Color::DarkGray, " Status ")),
        area,
    );
}

fn spinner_line(label: &str, detail: Option<String>, since: Instant) -> Line<'static> {
    let frame = SPINNER[(since.elapsed().as_millis() / SPINNER_FRAME_MS) as usize % SPINNER.len()];
    let mut spans = vec![Span::styled(
        format!("{frame} {label}"),
        Style::new().fg(Color::Yellow),
    )];
    if let Some(detail) = detail {
        spans.push(Span::styled(format!("   {detail}"), dim()));
    }
    spans.push(Span::styled("   Esc to stop", dim()));
    Line::from(spans)
}

fn level_color(level: Level) -> Color {
    match level {
        Level::Info => Color::Reset,
        Level::Ok => Color::Green,
        Level::Warn => Color::Yellow,
        Level::Error => Color::Red,
    }
}

fn draw_hints(f: &mut Frame, app: &App, area: Rect) {
    let text = match app.mode {
        Mode::Input(_) => "Enter confirm   Esc cancel   Ctrl-U clear".to_string(),
        Mode::Picker => "type to filter   ↑↓ choose   Enter attach   Esc cancel".to_string(),
        Mode::Help => "any key to close".to_string(),
        Mode::Normal => keymap::hint_line(app.focus),
    };
    f.render_widget(
        Paragraph::new(text)
            .style(dim())
            .alignment(Alignment::Center),
        area,
    );
}
