use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use projd_types::{
    client, default_socket_path, DownParams, LogsParams, LogsResult, NameParams,
    ProjectLifecycleState, ProjectStatus, StatusParams, StatusResult, UpParams, METHOD_DOWN,
    METHOD_FOCUS, METHOD_LOGS, METHOD_PEEK, METHOD_RESUME, METHOD_STATUS, METHOD_SUSPEND,
    METHOD_SWITCH, METHOD_UP,
};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(name = "proj-tui", version, about = "Terminal dashboard for projd")]
struct Cli {
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long = "autostart", default_value_t = true, action = ArgAction::Set)]
    autostart: bool,
    #[arg(long = "no-autostart")]
    no_autostart: bool,
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,
}

#[derive(Debug, Default)]
struct App {
    projects: Vec<ProjectStatus>,
    selected: usize,
    logs: String,
    status_message: String,
    follow_logs: bool,
    show_help: bool,
    log_scroll: u16,
}

impl App {
    fn selected_project_name(&self) -> Option<&str> {
        self.projects
            .get(self.selected)
            .map(|status| status.project.name.as_str())
    }

    fn set_projects(&mut self, projects: Vec<ProjectStatus>) {
        self.projects = projects;
        if self.projects.is_empty() {
            self.selected = 0;
            return;
        }
        if self.selected >= self.projects.len() {
            self.selected = self.projects.len() - 1;
        }
    }

    fn select_next(&mut self) {
        if self.projects.is_empty() {
            self.selected = 0;
            return;
        }
        self.selected = (self.selected + 1) % self.projects.len();
    }

    fn select_previous(&mut self) {
        if self.projects.is_empty() {
            self.selected = 0;
            return;
        }
        if self.selected == 0 {
            self.selected = self.projects.len() - 1;
        } else {
            self.selected -= 1;
        }
    }

    fn select_first(&mut self) {
        self.selected = 0;
    }

    fn select_last(&mut self) {
        self.selected = self.projects.len().saturating_sub(1);
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(default_socket_path);
    run_tui(
        &socket_path,
        resolve_autostart(cli.autostart, cli.no_autostart),
        cli.refresh_ms,
    )
}

const fn resolve_autostart(autostart: bool, no_autostart: bool) -> bool {
    autostart && !no_autostart
}

fn tui_rpc<P: serde::Serialize, R: serde::de::DeserializeOwned>(
    socket_path: &Path,
    method: &str,
    params: &P,
    autostart: bool,
) -> Result<R> {
    let value = serde_json::to_value(params)
        .with_context(|| format!("failed to serialize {method} params"))?;
    let resp = client::request_with_autostart(socket_path, method, value, autostart)?;
    client::parse_ok_response(resp.response)
}

fn run_tui(socket_path: &Path, autostart: bool, refresh_ms: u64) -> Result<()> {
    let mut app = App::default();
    if let Err(err) = refresh_status(socket_path, autostart, &mut app) {
        app.status_message = format!("status refresh failed: {err}");
    }

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal backend")?;
    let refresh_interval = Duration::from_millis(refresh_ms.max(200));
    let mut last_refresh = Instant::now();

    loop {
        terminal
            .draw(|frame| draw_ui(frame, &app))
            .context("failed to render tui frame")?;

        if event::poll(Duration::from_millis(100)).context("failed to poll terminal events")? {
            let event = event::read().context("failed to read terminal event")?;
            if let Event::Key(key) = event {
                if key.kind == KeyEventKind::Press
                    && handle_key(key, socket_path, autostart, &mut app)?
                {
                    break;
                }
            }
        }

        if last_refresh.elapsed() >= refresh_interval {
            if let Err(err) = refresh_status(socket_path, autostart, &mut app) {
                app.status_message = format!("status refresh failed: {err}");
            } else if app.follow_logs {
                if let Err(err) = load_selected_logs(socket_path, autostart, &mut app) {
                    app.status_message = format!("logs refresh failed: {err}");
                }
            }
            last_refresh = Instant::now();
        }
    }

    Ok(())
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Min(8),
        Constraint::Length(1),
    ])
    .split(frame.area());

    let help = Paragraph::new(
        "q quit | j/k move | g/G first/last | enter focus | p peek | r refresh | u up(cwd) | s switch | z suspend | e resume | d down | l logs | f follow | ? help",
    );
    frame.render_widget(help, chunks[0]);

    let table_block = Block::default().title("Projects").borders(Borders::ALL);
    if app.projects.is_empty() {
        let empty = Paragraph::new("No projects registered").block(table_block);
        frame.render_widget(empty, chunks[1]);
    } else {
        let rows = app.projects.iter().map(|status| {
            let state_color = match status.state {
                ProjectLifecycleState::Active => Color::Green,
                ProjectLifecycleState::Backgrounded => Color::Yellow,
                ProjectLifecycleState::Suspended => Color::DarkGray,
                ProjectLifecycleState::Stopped => Color::Red,
            };
            let mut style = Style::default().fg(state_color);
            if status.focused {
                style = style.add_modifier(Modifier::BOLD);
            }
            Row::new([
                Cell::from(status.project.name.as_str()),
                Cell::from(status.state.as_str()),
                Cell::from(if status.focused { "yes" } else { "no" }),
                Cell::from(status.project.port.to_string()),
                Cell::from(status.project.workspace.as_str()),
            ])
            .style(style)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(24),
                Constraint::Length(13),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Min(20),
            ],
        )
        .header(
            Row::new(["name", "state", "focused", "port", "workspace"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(table_block)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        let mut state = TableState::default().with_selected(Some(app.selected));
        frame.render_stateful_widget(table, chunks[1], &mut state);
    }

    let log_title = if app.follow_logs {
        if let Some(name) = app.selected_project_name() {
            format!("Logs: {name} (following)")
        } else {
            "Logs (following)".to_string()
        }
    } else if let Some(name) = app.selected_project_name() {
        if !app.logs.is_empty() {
            format!("Logs: {name}")
        } else {
            "Logs".to_string()
        }
    } else {
        "Logs".to_string()
    };

    let logs = Paragraph::new(app.logs.as_str())
        .block(Block::default().title(log_title).borders(Borders::ALL))
        .scroll((app.log_scroll, 0));
    frame.render_widget(logs, chunks[2]);

    let status_line = if app.status_message.is_empty() {
        format!(
            "{} projects | follow: {}",
            app.projects.len(),
            if app.follow_logs { "on" } else { "off" }
        )
    } else {
        format!("{} | {} projects", app.status_message, app.projects.len())
    };
    let status = Paragraph::new(status_line);
    frame.render_widget(status, chunks[3]);

    if app.show_help {
        let area = frame.area();
        let overlay = centered_rect(60, 70, area);
        frame.render_widget(Clear, overlay);
        let help_text = "\
Keybindings:

  j / k        Navigate down / up
  g / G        Jump to first / last
  Enter        Focus selected project
  s            Switch to selected project
  u            Up (register cwd)
  d            Down (remove project)
  z            Suspend selected project
  e            Resume selected project
  p            Peek at selected project
  l            Load logs for selected project
  f            Toggle log following
  r            Refresh status
  PageUp/Down  Scroll logs
  ?            Toggle this help overlay
  Ctrl+C / q   Quit";
        let help_paragraph = Paragraph::new(help_text)
            .block(Block::default().title("Help").borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        frame.render_widget(help_paragraph, overlay);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn handle_key(
    key: crossterm::event::KeyEvent,
    socket_path: &Path,
    autostart: bool,
    app: &mut App,
) -> Result<bool> {
    let mut selection_changed = false;
    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Char('c')
            if key
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL) =>
        {
            return Ok(true);
        }
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.select_next();
            selection_changed = true;
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.select_previous();
            selection_changed = true;
        }
        KeyCode::Char('g') => {
            app.select_first();
            selection_changed = true;
        }
        KeyCode::Char('G') => {
            app.select_last();
            selection_changed = true;
        }
        KeyCode::PageDown => {
            app.log_scroll = app.log_scroll.saturating_add(10);
        }
        KeyCode::PageUp => {
            app.log_scroll = app.log_scroll.saturating_sub(10);
        }
        KeyCode::Enter => {
            invoke_selected_name_action(socket_path, METHOD_FOCUS, autostart, app)?;
        }
        KeyCode::Char('p') => {
            invoke_selected_name_action(socket_path, METHOD_PEEK, autostart, app)?;
        }
        KeyCode::Char('r') => {
            refresh_all(socket_path, autostart, app)?;
            app.status_message = "refreshed status".to_string();
        }
        KeyCode::Char('u') => {
            let cwd = std::env::current_dir().context("failed to resolve current directory")?;
            let result: projd_types::UpResult = tui_rpc(
                socket_path,
                METHOD_UP,
                &UpParams {
                    path: cwd.to_string_lossy().to_string(),
                    workspace: None,
                },
                autostart,
            )?;
            app.status_message =
                format!("up {} (created={})", result.project.name, result.created);
            refresh_all(socket_path, autostart, app)?;
        }
        KeyCode::Char('s') => {
            invoke_selected_name_action(socket_path, METHOD_SWITCH, autostart, app)?;
        }
        KeyCode::Char('z') => {
            invoke_selected_name_action(socket_path, METHOD_SUSPEND, autostart, app)?;
        }
        KeyCode::Char('e') => {
            invoke_selected_name_action(socket_path, METHOD_RESUME, autostart, app)?;
        }
        KeyCode::Char('d') => {
            let Some(name) = app.selected_project_name().map(ToString::to_string) else {
                app.status_message = "no project selected".to_string();
                return Ok(false);
            };
            let removed: projd_types::ProjectRecord = tui_rpc(
                socket_path,
                METHOD_DOWN,
                &DownParams { name: name.clone() },
                autostart,
            )?;
            app.status_message = format!("down {}", removed.name);
            refresh_all(socket_path, autostart, app)?;
        }
        KeyCode::Char('l') => {
            load_selected_logs(socket_path, autostart, app)?;
        }
        KeyCode::Char('f') => {
            app.follow_logs = !app.follow_logs;
            if app.follow_logs {
                load_selected_logs(socket_path, autostart, app)?;
                app.status_message = format!(
                    "log follow enabled for {}",
                    app.selected_project_name().unwrap_or("none")
                );
            } else {
                app.status_message = "log follow disabled".to_string();
            }
        }
        _ => {}
    }

    if selection_changed && app.follow_logs {
        load_selected_logs(socket_path, autostart, app)?;
    }
    Ok(false)
}

fn invoke_selected_name_action(
    socket_path: &Path,
    method: &str,
    autostart: bool,
    app: &mut App,
) -> Result<()> {
    let Some(name) = app.selected_project_name().map(ToString::to_string) else {
        app.status_message = "no project selected".to_string();
        return Ok(());
    };
    let _: ProjectStatus = tui_rpc(
        socket_path,
        method,
        &NameParams { name: name.clone() },
        autostart,
    )?;
    app.status_message = format!("{method} {name}");
    refresh_all(socket_path, autostart, app)?;
    Ok(())
}

fn refresh_all(socket_path: &Path, autostart: bool, app: &mut App) -> Result<()> {
    refresh_status(socket_path, autostart, app)?;
    if app.follow_logs {
        load_selected_logs(socket_path, autostart, app)?;
    }
    Ok(())
}

fn refresh_status(socket_path: &Path, autostart: bool, app: &mut App) -> Result<()> {
    let status: StatusResult =
        tui_rpc(socket_path, METHOD_STATUS, &StatusParams { name: None }, autostart)?;
    app.set_projects(status.projects);
    if app.projects.is_empty() {
        app.logs.clear();
    }
    Ok(())
}

fn load_selected_logs(socket_path: &Path, autostart: bool, app: &mut App) -> Result<()> {
    let Some(name) = app.selected_project_name().map(ToString::to_string) else {
        app.logs.clear();
        app.status_message = "no project selected".to_string();
        return Ok(());
    };
    let logs: LogsResult = tui_rpc(
        socket_path,
        METHOD_LOGS,
        &LogsParams {
            name: name.clone(),
            process: None,
        },
        autostart,
    )?;
    app.logs = render_logs(&logs);
    app.log_scroll = 0;
    app.status_message = format!("loaded logs for {name}");
    Ok(())
}

fn render_logs(logs: &LogsResult) -> String {
    if logs.logs.is_empty() {
        return format!("no logs for {}\n", logs.project);
    }

    let mut output = String::new();
    for (index, entry) in logs.logs.iter().enumerate() {
        if logs.logs.len() > 1 {
            if index > 0 {
                output.push('\n');
            }
            let _ = writeln!(output, "== {} ({}) ==", entry.process, entry.path);
        }
        output.push_str(entry.content.as_str());
        if !entry.content.ends_with('\n') {
            output.push('\n');
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use projd_types::ProcessLogs;

    #[test]
    fn app_set_projects_clamps_selection() {
        let mut app = App {
            projects: vec![
                status("a", ProjectLifecycleState::Active),
                status("b", ProjectLifecycleState::Backgrounded),
            ],
            selected: 1,
            logs: String::new(),
            status_message: String::new(),
            follow_logs: false,
            show_help: false,
            log_scroll: 0,
        };
        app.set_projects(vec![status("a", ProjectLifecycleState::Active)]);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn render_logs_formats_multi_entry_sections() {
        let logs = LogsResult {
            project: "demo".to_string(),
            logs: vec![
                ProcessLogs {
                    process: "server".to_string(),
                    path: "/tmp/server.log".to_string(),
                    content: "hello\n".to_string(),
                },
                ProcessLogs {
                    process: "agent".to_string(),
                    path: "/tmp/agent.log".to_string(),
                    content: "world\n".to_string(),
                },
            ],
        };
        let rendered = render_logs(&logs);
        assert!(rendered.contains("== server (/tmp/server.log) =="));
        assert!(rendered.contains("== agent (/tmp/agent.log) =="));
    }

    #[test]
    fn cli_autostart_defaults_true_and_supports_disable_flags() {
        let default_cli = Cli::try_parse_from(["proj-tui"]).unwrap();
        assert!(default_cli.autostart);
        assert!(!default_cli.no_autostart);

        let no_autostart_cli = Cli::try_parse_from(["proj-tui", "--no-autostart"]).unwrap();
        assert!(no_autostart_cli.autostart);
        assert!(no_autostart_cli.no_autostart);
        assert!(!resolve_autostart(
            no_autostart_cli.autostart,
            no_autostart_cli.no_autostart
        ));

        let explicit_false_cli = Cli::try_parse_from(["proj-tui", "--autostart=false"]).unwrap();
        assert!(!explicit_false_cli.autostart);
        assert!(!explicit_false_cli.no_autostart);
        assert!(!resolve_autostart(
            explicit_false_cli.autostart,
            explicit_false_cli.no_autostart
        ));
    }

    fn status(name: &str, state: ProjectLifecycleState) -> ProjectStatus {
        ProjectStatus {
            project: projd_types::ProjectRecord {
                name: name.to_string(),
                path: format!("/tmp/{name}"),
                workspace: name.to_string(),
                port: 3001,
            },
            state,
            focused: false,
        }
    }
}
