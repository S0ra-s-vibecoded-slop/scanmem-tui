//! The Code tab: mappings or references on the left, disassembly on the right.

use super::{dim, framed};
use crate::app::{App, CodeFocus, Sidebar};
use crate::code::{self, Flow, POINTER_WINDOW};
use crate::maps;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};

pub fn draw_code(f: &mut Frame, app: &mut App, area: Rect) {
    let [sidebar, pane] =
        Layout::horizontal([Constraint::Length(42), Constraint::Min(20)]).areas(area);
    draw_sidebar(f, app, sidebar);
    if app.code.trace.is_some() {
        draw_trace(f, app, pane);
    } else if app.code.data.is_some() {
        draw_data(f, app, pane);
    } else {
        draw_disassembly(f, app, pane);
    }
}

fn draw_sidebar(f: &mut Frame, app: &mut App, area: Rect) {
    match app.code.sidebar {
        Sidebar::Refs => draw_refs(f, app, area),
        Sidebar::Pointers => draw_pointers(f, app, area),
        Sidebar::Mappings => draw_mappings(f, app, area),
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
    let range = app.code.ref_range.unwrap_or_default();
    let what = app
        .code
        .ref_label
        .clone()
        .unwrap_or_else(|| range.to_string());
    let count = app.code.refs.len();
    let title = format!(" References to {what} ({count}) ");
    let block = pane_block(title, app.code.focus == CodeFocus::Sidebar);
    if app.code.refs.is_empty() {
        let message = if range.is_single() {
            "No instruction encodes that address.\n\nHeap and stack values are usually reached through pointers, which a static scan cannot see."
        } else {
            "No instruction encodes an address in that range."
        };
        return placeholder(f, block, area, message);
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

fn draw_pointers(f: &mut Frame, app: &mut App, area: Rect) {
    let target = app.code.pointer_target.unwrap_or_default();
    let what = app
        .code
        .pointer_label
        .clone()
        .unwrap_or_else(|| format!("0x{target:x}"));
    let count = app.code.pointers.len();
    let hop = app.code.pointer_hop();
    let suffix = if hop > 1 {
        format!(" · hop {hop}")
    } else {
        String::new()
    };
    let title = format!(" Pointers to {what} ({count}){suffix} ");
    let block = pane_block(title, app.code.focus == CodeFocus::Sidebar);
    if app.code.pointers.is_empty() {
        return placeholder(
            f,
            block,
            area,
            &format!(
                "No slot holds a pointer to that address (or to the {POINTER_WINDOW:#x} bytes before it).\n\nThe access may be computed from a base register, or the pointer may live in a register or another object; a static scan cannot follow that."
            ),
        );
    }
    let items: Vec<ListItem> = app
        .code
        .pointers
        .iter()
        .map(|pointer| {
            let delta = target.saturating_sub(pointer.value);
            let arrow = if delta == 0 {
                "exact".to_string()
            } else {
                format!("-0x{delta:x}")
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("0x{:x}", pointer.slot),
                    Style::new().fg(Color::Cyan),
                ),
                Span::styled(
                    format!(
                        "  {} ",
                        maps::format_module_offset(&app.code.mappings, pointer.slot)
                    ),
                    dim(),
                ),
                Span::styled(format!("→ {arrow}"), dim()),
            ]))
        })
        .collect();
    let mut state = app.code.pointer_state;
    let list = List::new(items)
        .block(block)
        .highlight_style(highlight(app.code.focus == CodeFocus::Sidebar))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, area, &mut state);
    app.code.pointer_state = state;
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
            if let Some(note) = app.code.notes.get(&line.addr) {
                spans.push(Span::styled(format!("  ↳ {note}"), dim()));
            }
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

/// Everything the report needs from the app, gathered so the layout can be
/// tested without a terminal.
struct TraceView<'a> {
    report: &'a code::TraceReport,
    mappings: &'a [maps::Mapping],
    label: Option<&'a str>,
    ty: Option<crate::datatype::DataType>,
    /// The saved value, already formatted; `None` when it is unreadable.
    value: Option<String>,
    selected: usize,
}

/// The Analyze report: direct refs, then ranked candidate paths. The report
/// replaces the hex pane and uses the full width; each path takes its own
/// lines rather than being clipped into a sidebar-sized column.
fn draw_trace(f: &mut Frame, app: &mut App, area: Rect) {
    let block = pane_block(
        " Trace · Analyze ".to_string(),
        app.code.focus == CodeFocus::Disassembly,
    );
    let inner = block.inner(area);
    let height = usize::from(inner.height).max(1);
    let selected = app.code.trace_state.selected().unwrap_or(0);
    let (lines, selected_start) = {
        let Some(report) = &app.code.trace else {
            return;
        };
        let saved = app
            .saved
            .items
            .iter()
            .find(|item| item.addr == report.target);
        let label = saved
            .map(|item| item.label.clone())
            .filter(|label| !label.is_empty())
            .or_else(|| (!report.target_label.is_empty()).then(|| report.target_label.clone()));
        let ty = saved.map(|item| item.ty);
        let value = ty.and_then(|ty| {
            app.target
                .as_ref()
                .and_then(|target| target.memory().ok())
                .and_then(|memory| code::read_typed(memory, report.target, ty))
        });
        trace_lines(&TraceView {
            report,
            mappings: &app.code.mappings,
            label: label.as_deref(),
            ty,
            value,
            selected,
        })
    };

    let mut scroll = app.code.trace_scroll.min(lines.len().saturating_sub(1));
    if let Some(start) = selected_start
        && (start < scroll || start >= scroll + height)
    {
        scroll = start;
    }
    app.code.trace_scroll = scroll;
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0)),
        area,
    );
}

#[expect(clippy::too_many_lines, reason = "the report is one coherent layout")]
fn trace_lines(view: &TraceView<'_>) -> (Vec<Line<'static>>, Option<usize>) {
    let report = view.report;
    let mappings = view.mappings;
    let selected = view.selected;
    let value = view.value.clone().map(|value| format!(" = {value}"));
    let kind = report
        .target_kind
        .map_or("unmapped", crate::maps::RegionKind::text);
    let hops = report
        .paths
        .get(selected)
        .or_else(|| report.paths.first())
        .map_or(0, |path| path.hops.len());
    let named = view.label.map_or_else(
        || format!("0x{:x}", report.target),
        |label| format!("{label} 0x{:x}", report.target),
    );
    let typing = view.ty.map_or_else(
        || kind.to_string(),
        |ty| format!("{kind}, {}", ty.scanmem_name()),
    );
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Trace", Style::new().bold().fg(Color::Cyan)),
        Span::raw(" · "),
        Span::styled(named.clone(), Style::new().bold()),
        Span::styled(
            format!(" ({typing}{})", value.clone().unwrap_or_default()),
            dim(),
        ),
        Span::styled(
            format!(" · {} · {} ms", hop_count(hops), report.stats.elapsed_ms),
            dim(),
        ),
    ]));
    let mut summary = format!(
        "{} direct instruction(s); {} candidate path(s); {} static root(s)",
        report.refs.len(),
        report.paths.len(),
        report.stats.roots
    );
    if report.stats.truncated {
        summary.push_str(" · truncated");
    }
    if report.stats.cancelled {
        summary.push_str(" · cancelled");
    }
    lines.push(Line::styled(summary, dim()));
    lines.push(Line::default());

    if !report.refs.is_empty() {
        lines.push(Line::styled("Direct references", Style::new().bold()));
        for reference in report.refs.iter().take(8) {
            lines.push(Line::from(vec![
                Span::styled("  code  ", dim()),
                Span::styled(
                    maps::format_module_offset(mappings, reference.addr),
                    Style::new().fg(Color::Cyan),
                ),
                Span::raw("   "),
                Span::styled(reference.text.clone(), Style::new()),
            ]));
        }
        if report.refs.len() > 8 {
            lines.push(Line::styled(
                format!("  … {} more direct reference(s)", report.refs.len() - 8),
                dim(),
            ));
        }
        lines.push(Line::default());
    }

    if report.paths.is_empty() {
        lines.push(Line::styled(
            format!(
                "No static pointer path at depth {}.",
                report.stats.levels.max(1)
            ),
            Style::new().bold().fg(Color::Yellow),
        ));
        lines.push(Line::styled(
            format!(
                "Tried: {} direct ref(s); {} slot(s) across {} level(s); {} static root(s).",
                report.refs.len(),
                report.stats.slots,
                report.stats.levels,
                report.stats.roots
            ),
            dim(),
        ));
        if report.stats.truncated {
            lines.push(Line::styled(
                "A cap dropped candidates; this report is partial.",
                Style::new().fg(Color::Yellow),
            ));
        }
        lines.push(Line::styled(
            "Static scans see encoded operands and stored pointers. A pointer computed in a register, or written after this snapshot, cannot be followed; a slot is a candidate, not proof.",
            dim(),
        ));
    }

    let mut selected_start = None;
    for (index, path) in report.paths.iter().enumerate() {
        if index == selected {
            selected_start = Some(lines.len());
        }
        let is_selected = index == selected;
        let marker = if is_selected {
            "▶ "
        } else if path.root.is_some() {
            "● "
        } else {
            "○ "
        };
        let mut head = vec![Span::styled(
            marker,
            Style::new().fg(if is_selected {
                Color::Cyan
            } else {
                Color::DarkGray
            }),
        )];
        head.push(Span::styled(
            hop_count(path.hops.len()),
            if is_selected {
                Style::new().bold()
            } else {
                Style::new()
            },
        ));
        match path.root {
            Some(root) => head.push(Span::styled(
                format!(
                    " · root {} (static)",
                    maps::format_module_offset(mappings, root.slot)
                ),
                dim(),
            )),
            None => head.push(Span::styled(" · no static root", dim())),
        }
        if path.offset != 0 {
            head.push(Span::styled(
                format!(" · target-0x{:x}", path.offset),
                dim(),
            ));
        }
        if !path.stable {
            head.push(Span::styled(" · unstable", Style::new().fg(Color::Yellow)));
        }
        lines.push(Line::from(head));

        if let Some(code) = &path.code {
            lines.push(Line::from(vec![
                Span::styled("  code  ", dim()),
                Span::styled(
                    maps::format_module_offset(mappings, code.addr),
                    Style::new().fg(Color::Cyan),
                ),
                Span::raw("   "),
                Span::raw(code.text.clone()),
            ]));
        }
        let skip = usize::from(path.root.is_some());
        for (hop_index, hop) in path.hops.iter().enumerate().skip(skip) {
            let next = path
                .hops
                .get(hop_index + 1)
                .map_or(report.target, |hop| hop.slot);
            let delta = match hop.value.cmp(&next) {
                std::cmp::Ordering::Equal => "exact".to_string(),
                std::cmp::Ordering::Greater => format!("+0x{:x}", hop.value - next),
                std::cmp::Ordering::Less => format!("-0x{:x}", next - hop.value),
            };
            lines.push(Line::from(vec![
                Span::styled("  slot  ", dim()),
                Span::styled(format!("0x{:x}", hop.slot), Style::new().fg(Color::Cyan)),
                Span::styled(format!(" = 0x{:x}", hop.value), Style::new()),
                Span::styled(
                    format!("   {}+0x{:x}", region_tag(hop.kind), hop.offset),
                    dim(),
                ),
                Span::styled(format!("  ({delta})"), dim()),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("  →     ", dim()),
            Span::styled(named.clone(), Style::new().bold()),
            Span::styled(
                format!(" ({typing}{})", value.clone().unwrap_or_default()),
                dim(),
            ),
        ]));
        lines.push(Line::default());
    }
    (lines, selected_start)
}

fn hop_count(hops: usize) -> String {
    format!("{hops} hop{}", if hops == 1 { "" } else { "s" })
}

fn region_tag(kind: crate::maps::RegionKind) -> &'static str {
    match kind {
        crate::maps::RegionKind::Module => "module",
        crate::maps::RegionKind::Heap => "[heap]",
        crate::maps::RegionKind::Stack => "[stack]",
        crate::maps::RegionKind::Anonymous => "[anon]",
        crate::maps::RegionKind::Other => "[special]",
    }
}

/// The hex view: addresses, bytes, and ASCII. Unreadable bytes stay `??`.
fn draw_data(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(data) = &app.code.data else {
        return;
    };
    let here = app
        .code_cursor_label()
        .unwrap_or_else(|| format!("0x{:x}", data.cursor));
    let title = format!(" Data · {here} ({}) ", data.perms);
    let block = pane_block(title, app.code.focus == CodeFocus::Disassembly);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let height = usize::from(inner.height).max(1);
    let rows = data.rows();
    let cursor_row = data.cursor_row();
    let mut scroll = data.scroll;
    if cursor_row < scroll {
        scroll = cursor_row;
    } else if cursor_row >= scroll + height {
        scroll = cursor_row + 1 - height;
    }
    let focused = app.code.focus == CodeFocus::Disassembly;
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .skip(scroll)
        .take(height)
        .map(|(index, row)| {
            let selected = index == cursor_row;
            let mut spans = vec![
                Span::styled(
                    if selected { "▶ " } else { "  " },
                    Style::new().fg(Color::Cyan),
                ),
                Span::styled(
                    format!("0x{:016x}", row.addr),
                    if selected { Style::new().bold() } else { dim() },
                ),
                Span::raw("  "),
                Span::styled(row.hex.clone(), Style::new().fg(Color::LightGreen)),
                Span::raw("  |"),
                Span::styled(row.ascii.clone(), dim()),
                Span::raw("|"),
            ];
            if selected {
                spans.push(Span::styled(
                    format!("  ← 0x{:x}", data.cursor),
                    Style::new().fg(Color::Cyan),
                ));
            }
            let mut drawn = Line::from(spans);
            if selected {
                drawn = drawn.style(highlight(focused));
            }
            drawn
        })
        .collect();
    if let Some(data) = &mut app.code.data {
        data.scroll = scroll;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::{Hop, RefKind, Reference, TracePath, TraceReport, TraceRoot, TraceStats};
    use crate::datatype::DataType;
    use crate::maps::{Mapping, Perms, RegionKind};

    fn mapping(start: u64, len: u64, path: &str, write: bool, exec: bool) -> Mapping {
        Mapping {
            start,
            end: start + len,
            perms: Perms {
                read: true,
                write,
                exec,
                shared: false,
            },
            offset: 0,
            dev: "00:00".into(),
            inode: 0,
            path: Some(path.to_string()),
        }
    }

    fn fixture_maps() -> Vec<Mapping> {
        vec![
            mapping(0x10_0000, 0x100, "/tmp/game", false, true),
            mapping(0x20_0000, 0x1000, "[heap]", true, false),
            mapping(0x30_0000, 0x1000, "[heap]", true, false),
            mapping(0x40_0000, 0x1000, "/tmp/game", true, false),
        ]
    }

    fn hop(slot: u64, value: u64, kind: RegionKind, offset: u64) -> Hop {
        Hop {
            slot,
            value,
            kind,
            offset,
        }
    }

    fn root(slot: u64) -> TraceRoot {
        TraceRoot {
            slot,
            kind: RegionKind::Module,
            offset: 0,
        }
    }

    fn reference(addr: u64, text: &str) -> Reference {
        Reference {
            addr,
            target: 0,
            text: text.to_string(),
            kind: RefKind::RipRelative,
        }
    }

    fn path(
        hops: Vec<Hop>,
        root: Option<TraceRoot>,
        code: Option<Reference>,
        offset: u64,
        stable: bool,
    ) -> TracePath {
        TracePath {
            hops,
            root,
            code,
            offset,
            stable,
        }
    }

    fn report(paths: Vec<TracePath>, refs: Vec<Reference>, stats: TraceStats) -> TraceReport {
        TraceReport {
            target: 0x30_0000,
            target_label: "health".to_string(),
            target_kind: Some(RegionKind::Heap),
            refs,
            paths,
            stats,
        }
    }

    fn view<'a>(
        report: &'a TraceReport,
        mappings: &'a [Mapping],
        selected: usize,
    ) -> TraceView<'a> {
        TraceView {
            report,
            mappings,
            label: Some("health"),
            ty: Some(DataType::I32),
            value: Some("42".to_string()),
            selected,
        }
    }

    fn text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn joined(lines: &[Line<'_>]) -> String {
        lines.iter().map(text).collect::<Vec<_>>().join("\n")
    }

    fn stats(levels: usize, roots: usize, truncated: bool) -> TraceStats {
        TraceStats {
            levels,
            nodes: roots,
            slots: roots,
            roots,
            truncated,
            cancelled: false,
            elapsed_ms: 31,
        }
    }

    #[test]
    fn report_header_names_the_target_type_and_counts() {
        let maps = fixture_maps();
        let report = report(
            vec![path(
                vec![hop(0x20_0010, 0x30_0000, RegionKind::Heap, 0x10)],
                Some(root(0x40_0000)),
                Some(reference(0x10_0000, "mov rax,[rip+0x2ffff9]")),
                0,
                true,
            )],
            vec![reference(0x10_0000, "mov rax,[rip+0x2ffff9]")],
            stats(2, 1, false),
        );
        let (lines, selected) = trace_lines(&view(&report, &maps, 0));
        let head = text(&lines[0]);
        assert!(head.contains("health 0x300000"), "{head}");
        assert!(head.contains("(heap, int32 = 42)"), "{head}");
        assert!(head.contains("1 hop · 31 ms"), "{head}");
        let body = joined(&lines);
        assert!(
            body.contains("1 direct instruction(s); 1 candidate path(s); 1 static root(s)"),
            "{body}"
        );
        assert_eq!(selected, Some(6)); // header, summary, blank, refs heading, ref, blank
    }

    #[test]
    fn rooted_path_shows_its_code_and_slot_lines() {
        let maps = fixture_maps();
        let report = report(
            vec![path(
                vec![
                    hop(0x40_0000, 0x20_0010, RegionKind::Module, 0),
                    hop(0x20_0010, 0x30_0000, RegionKind::Heap, 0x10),
                ],
                Some(root(0x40_0000)),
                Some(reference(0x10_0000, "mov rax,[rip+0x2ffff9]")),
                0,
                true,
            )],
            Vec::new(),
            stats(2, 1, false),
        );
        let (lines, selected) = trace_lines(&view(&report, &maps, 0));
        let body = joined(&lines);
        assert!(
            body.contains("▶ 2 hops · root game+0x300000 (static)"),
            "{body}"
        );
        assert!(
            body.contains("code  game+0x0   mov rax,[rip+0x2ffff9]"),
            "{body}"
        );
        assert!(
            body.contains("slot  0x200010 = 0x300000   [heap]+0x10  (exact)"),
            "{body}"
        );
        assert!(
            body.contains("→     health 0x300000 (heap, int32 = 42)"),
            "{body}"
        );
        assert_eq!(selected, Some(3));
    }

    #[test]
    fn unrooted_offset_path_is_marked() {
        let maps = fixture_maps();
        let report = report(
            vec![
                path(
                    vec![hop(0x40_0000, 0x30_0000, RegionKind::Module, 0)],
                    Some(root(0x40_0000)),
                    None,
                    0,
                    true,
                ),
                path(
                    vec![hop(0x20_0010, 0x30_0010, RegionKind::Heap, 0x10)],
                    None,
                    None,
                    0x10,
                    false,
                ),
            ],
            Vec::new(),
            stats(1, 1, false),
        );
        let (lines, _) = trace_lines(&view(&report, &maps, 0));
        let body = joined(&lines);
        assert!(
            body.contains("○ 1 hop · no static root · target-0x10 · unstable"),
            "{body}"
        );
    }

    #[test]
    fn empty_report_explains_what_was_tried() {
        let maps = fixture_maps();
        let report = report(Vec::new(), Vec::new(), stats(2, 0, true));
        let (lines, selected) = trace_lines(&view(&report, &maps, 0));
        assert_eq!(selected, None);
        let body = joined(&lines);
        assert!(
            body.contains("No static pointer path at depth 2."),
            "{body}"
        );
        assert!(
            body.contains("Tried: 0 direct ref(s); 0 slot(s) across 2 level(s); 0 static root(s)."),
            "{body}"
        );
        assert!(
            body.contains("A cap dropped candidates; this report is partial."),
            "{body}"
        );
        assert!(body.contains("register"), "{body}");
    }

    #[test]
    fn direct_refs_are_capped_and_counted() {
        let maps = fixture_maps();
        let refs: Vec<Reference> = (0..10)
            .map(|index| reference(0x10_0000 + index, "nop"))
            .collect();
        let report = report(Vec::new(), refs, stats(1, 0, false));
        let (lines, _) = trace_lines(&view(&report, &maps, 0));
        let body = joined(&lines);
        assert!(body.contains("Direct references"), "{body}");
        assert!(body.contains("… 2 more direct reference(s)"), "{body}");
    }
}
