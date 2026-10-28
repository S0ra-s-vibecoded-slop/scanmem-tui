//! The two tables: scan results on the left, saved addresses on the right.

use super::{dim, framed};
use crate::app::{App, Focus, ResultRow, Saved};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, Wrap};

const RESULTS_NEED_PROCESS: &str = "Press p to pick a process.";
const RESULTS_EMPTY: &str = "No results.\n\nPress s and type a value (e.g. 100),\nor `snapshot` to start without one.\nThen narrow down with: value, > N, < N,\n=, !=, +, -";
const SAVED_EMPTY: &str = "Empty.\n\nSelect a scan result and press a (or Enter) to save it here,\nor press A to add an address by hand.\n\nIn this list: w sets a value, which adds a checkbox;\nSpace ticks it to hold that value.";

pub fn draw_results(f: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Results;
    let block = pane_block(
        format!(" Scan results ({}) ", app.results.rows.len()),
        focused,
    );
    app.results.viewport = block.inner(area).height.saturating_sub(1) as usize;

    if app.results.rows.is_empty() {
        let message = if app.target.is_none() {
            RESULTS_NEED_PROCESS
        } else {
            RESULTS_EMPTY
        };
        return draw_placeholder(f, block, area, message);
    }

    let rows = app.results.rows.iter().map(result_row);
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Min(8),
            Constraint::Length(7),
        ],
    )
    .header(header_row(["Address", "Value", "Region"]))
    .block(block)
    .row_highlight_style(highlight(focused))
    .highlight_symbol("▶ ");
    f.render_stateful_widget(table, area, &mut app.results.state);
}

pub fn draw_saved(f: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.focus == Focus::Saved;
    let block = pane_block(saved_title(app), focused);

    if app.saved.items.is_empty() {
        return draw_placeholder(f, block, area, SAVED_EMPTY);
    }

    let rows = app.saved.items.iter().map(saved_row);
    let widths = [
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Min(8),
    ];
    let table = Table::new(rows, widths)
        .header(header_row(["", "Description", "Address", "Type", "Value"]))
        .block(block)
        .row_highlight_style(highlight(focused))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(table, area, &mut app.saved.state);
}

fn saved_title(app: &App) -> String {
    let count = app.saved.items.len();
    match app.saved.frozen_count() {
        0 => format!(" Saved addresses ({count}) "),
        frozen => format!(" Saved addresses ({count}, {frozen} frozen) "),
    }
}

fn result_row(row: &ResultRow) -> Row<'static> {
    let shown = row.live.as_deref().unwrap_or(&row.m.value);
    let changed = row.live.as_deref().is_some_and(|live| live != row.m.value);
    let value_style = if changed {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new()
    };
    Row::new([
        Cell::from(format!("0x{:x}", row.m.addr)),
        Cell::from(shown.to_string()).style(value_style),
        Cell::from(row.m.region.clone()),
    ])
}

fn saved_row(saved: &Saved) -> Row<'static> {
    let checkbox = match (&saved.set_value, saved.frozen) {
        (None, _) => "   ",
        (Some(_), false) => "[ ]",
        (Some(_), true) => "[x]",
    };
    let row_style = if saved.frozen {
        Style::new().fg(Color::Green)
    } else {
        Style::new()
    };
    let description = if saved.desc.is_empty() {
        "—".to_string()
    } else {
        saved.desc.clone()
    };
    Row::new([
        Cell::from(checkbox),
        Cell::from(description),
        Cell::from(format!("0x{:x}", saved.addr)),
        Cell::from(saved.ty.scanmem_name()),
        Cell::from(saved.live.clone().unwrap_or_else(|| "??".into())),
    ])
    .style(row_style)
}

fn header_row<const N: usize>(titles: [&'static str; N]) -> Row<'static> {
    Row::new(titles).style(Style::new().bold().fg(Color::Gray))
}

fn pane_block(title: String, focused: bool) -> Block<'static> {
    let (color, weight) = if focused {
        (Color::Cyan, Style::new().bold())
    } else {
        (Color::DarkGray, Style::new())
    };
    framed(color, Line::from(title).style(weight))
}

fn highlight(focused: bool) -> Style {
    if focused {
        Style::new().add_modifier(Modifier::REVERSED)
    } else {
        Style::new().bg(Color::Rgb(50, 50, 50))
    }
}

fn draw_placeholder(f: &mut Frame, block: Block<'_>, area: Rect, message: &str) {
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(message)
            .style(dim())
            .wrap(Wrap { trim: false }),
        inner,
    );
}
