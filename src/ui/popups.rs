//! The process picker and the help screen.

use super::framed;
use crate::app::{App, Confirm, Mode};
use crate::keymap;
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Clear, List, ListItem, Paragraph, Wrap};

pub fn draw(f: &mut Frame, app: &mut App) {
    match app.mode {
        Mode::Picker => draw_picker(f, app),
        Mode::Help => draw_help(f, app),
        Mode::Confirm(confirm) => draw_confirm(f, app, confirm),
        Mode::Normal | Mode::Input(_) => {}
    }
}

#[expect(clippy::cast_possible_truncation)]
fn draw_picker(f: &mut Frame, app: &mut App) {
    let area = centered(f.area(), 60, 70);
    f.render_widget(Clear, area);
    let block = framed(Color::Cyan, " Select process ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [filter, list] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    f.render_widget(
        Paragraph::new(format!("filter › {}", app.picker.filter)),
        filter,
    );
    f.set_cursor_position((
        filter.x + 9 + app.picker.filter.chars().count() as u16,
        filter.y,
    ));

    let items: Vec<ListItem> = app
        .picker
        .visible()
        .iter()
        .map(|(pid, name)| ListItem::new(format!("{pid:>8}  {name}")))
        .collect();
    let widget = List::new(items)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(widget, list, &mut app.picker.state);
}

fn draw_help(f: &mut Frame, app: &mut App) {
    let area = centered(f.area(), 70, 85);
    f.render_widget(Clear, area);
    let block = framed(Color::Cyan, " Help ");
    let inner = block.inner(area);
    let text = keymap::help_text();
    let lines = text.lines().count();
    let hidden = lines.saturating_sub(usize::from(inner.height));
    let scroll = usize::from(app.help_scroll).min(hidden);
    app.help_scroll = u16::try_from(scroll).unwrap_or(u16::MAX);
    f.render_widget(block, area);
    f.render_widget(Paragraph::new(text).scroll((app.help_scroll, 0)), inner);
}

fn draw_confirm(f: &mut Frame, app: &App, confirm: Confirm) {
    let area = centered(f.area(), 60, 30);
    f.render_widget(Clear, area);
    let message = match confirm {
        Confirm::Delist(id) => {
            let name = app
                .scripts
                .scripts()
                .iter()
                .find(|script| script.id == id)
                .map_or_else(String::new, |script| script.name.clone());
            format!("Remove `{name}` from the list?\nThe file stays on disk.")
        }
        Confirm::DeleteFile(id) => {
            let path = app
                .scripts
                .scripts()
                .iter()
                .find(|script| script.id == id)
                .map_or_else(String::new, |script| script.path.display().to_string());
            format!("Delete {path} from disk?\nThis cannot be undone.")
        }
    };
    let body = format!("{message}\n\n[y] yes     [n] no");
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .block(framed(Color::Yellow, " Confirm ")),
        area,
    );
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let [row] = Layout::vertical([Constraint::Percentage(percent_y)])
        .flex(Flex::Center)
        .areas(area);
    let [cell] = Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .areas(row);
    cell
}
