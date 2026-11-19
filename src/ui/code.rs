//! The Code tab: mappings or references on the left, disassembly on the right.

use super::{dim, framed};
use crate::app::{App, CodeFocus};
use crate::code::Flow;
use crate::maps;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};

pub fn draw_code(f: &mut Frame, app: &mut App, area: Rect) {
    let [sidebar, disassembly] =
        Layout::horizontal([Constraint::Length(42), Constraint::Min(20)]).areas(area);
    draw_sidebar(f, app, sidebar);
    draw_disassembly(f, app, disassembly);
}

fn draw_sidebar(f: &mut Frame, app: &mut App, area: Rect) {
    if app.code.showing_refs {
        draw_refs(f, app, area);
    } else {
        draw_mappings(f, app, area);
    }
}

fn draw_mappings(f: &mut Frame, app: &App, area: Rect) {
    let count = app.code.executable_count();
    let title = format!(" Mappings ({count} executable) ");
    let block = pane_block(title, app.code.focus == CodeFocus::Sidebar);
    if app.code.pid.is_none() {
        return placeholder(f, block, area, "Pick a process first (p).");
    }
    if count == 0 {
        return placeholder(
            f,
            block,
            area,
            "No executable mappings.\n\nThe process may have exited, or /proc/<pid>/maps is not readable.",
        );
    }
    let items: Vec<ListItem> = app
        .code
        .executable()
        .map(|mapping| {
            ListItem::new(Line::from(vec![
                Span::raw(mapping.display_name()),
                Span::styled(format!("  0x{:x}", mapping.start), dim()),
            ]))
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(app.code.selected_mapping));
    let list = List::new(items)
        .block(block)
        .highlight_style(highlight(app.code.focus == CodeFocus::Sidebar))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_refs(f: &mut Frame, app: &mut App, area: Rect) {
    let target = app.code.ref_target.unwrap_or_default();
    let what = app
        .code
        .ref_label
        .clone()
        .unwrap_or_else(|| format!("0x{target:x}"));
    let count = app.code.refs.len();
    let title = format!(" References to {what} ({count}) ");
    let block = pane_block(title, app.code.focus == CodeFocus::Sidebar);
    if app.code.refs.is_empty() {
        return placeholder(
            f,
            block,
            area,
            "No instruction encodes that address.\n\nHeap and stack values are usually reached through pointers, which a static scan cannot see.",
        );
    }
    let items: Vec<ListItem> = app
        .code
        .refs
        .iter()
        .map(|reference| {
            let kind = App::ref_kind_text(reference.kind);
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("0x{:x}", reference.addr),
                    Style::new().fg(Color::Cyan),
                ),
                Span::styled(format!(" {kind} "), dim()),
                Span::raw(reference.text.clone()),
            ]))
        })
        .collect();
    let mut state = app.code.ref_state;
    let list = List::new(items)
        .block(block)
        .highlight_style(highlight(app.code.focus == CodeFocus::Sidebar))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut state);
    app.code.ref_state = state;
}

fn draw_disassembly(f: &mut Frame, app: &mut App, area: Rect) {
    let here = app.code_cursor_label().unwrap_or_default();
    let title = if here.is_empty() {
        " Disassembly ".to_string()
    } else {
        format!(" Disassembly · {here} ")
    };
    let block = pane_block(title, app.code.focus == CodeFocus::Disassembly);
    let inner = block.inner(area);
    app.code.viewport = usize::from(inner.height).max(1);
    app.code.ensure_visible();

    if app.code.pid.is_none() {
        f.render_widget(block, area);
        return placeholder_inner(f, inner, "Pick a process first (p).");
    }
    if app.code.lines.is_empty() {
        f.render_widget(block, area);
        return placeholder_inner(
            f,
            inner,
            "No disassembly yet.\n\nSelect a mapping on the left and press Enter,\nor press g to go to a label, module+offset or address.",
        );
    }

    f.render_widget(block, area);
    let height = usize::from(inner.height);
    let focused = app.code.focus == CodeFocus::Disassembly;
    let lines: Vec<Line> = app
        .code
        .lines
        .iter()
        .enumerate()
        .skip(app.code.scroll)
        .take(height)
        .map(|(index, line)| {
            let selected = index == app.code.cursor;
            let prefix = if selected { "▶ " } else { "  " };
            let mut spans = vec![
                Span::styled(prefix, Style::new().fg(Color::Cyan)),
                Span::styled(
                    format!("0x{:016x}", line.addr),
                    if selected { Style::new().bold() } else { dim() },
                ),
            ];
            if app.code.bytes {
                let bytes = line
                    .bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                spans.push(Span::styled(format!("  {bytes:<44}"), dim()));
            }
            spans.push(Span::raw("  "));
            spans.push(Span::styled(line.text.clone(), flow_style(line.flow)));
            if let Some(target) = line.target {
                spans.push(Span::styled(
                    format!(
                        "  → {}",
                        maps::format_module_offset(&app.code.mappings, target)
                    ),
                    dim(),
                ));
            }
            let mut drawn = Line::from(spans);
            if selected {
                drawn = drawn.style(highlight(focused));
            }
            drawn
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn flow_style(flow: Flow) -> Style {
    match flow {
        Flow::Call => Style::new().fg(Color::Yellow),
        Flow::Jump | Flow::Conditional => Style::new().fg(Color::Cyan),
        Flow::Return => Style::new().fg(Color::Magenta),
        Flow::Indirect | Flow::Interrupt => Style::new().fg(Color::Blue),
        Flow::Invalid => Style::new().fg(Color::Red),
        Flow::Normal => Style::new(),
    }
}

fn pane_block(title: String, focused: bool) -> ratatui::widgets::Block<'static> {
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

fn placeholder(f: &mut Frame, block: ratatui::widgets::Block<'_>, area: Rect, message: &str) {
    let inner = block.inner(area);
    f.render_widget(block, area);
    placeholder_inner(f, inner, message);
}

fn placeholder_inner(f: &mut Frame, area: Rect, message: &str) {
    f.render_widget(
        Paragraph::new(message)
            .style(dim())
            .wrap(Wrap { trim: false }),
        area,
    );
}
