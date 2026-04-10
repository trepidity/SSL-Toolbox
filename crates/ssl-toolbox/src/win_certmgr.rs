use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use cliclack::{confirm, input, password, select};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    DefaultTerminal,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use ssl_toolbox_win_certstore::{
    CertDetails, CertEntry, ExportFormat, ExportOptions, ImportOptions, PhysicalStoreInfo,
    PrivateKeyInfo, StoreLocation, StoreLocationContext, StorePath, delete_certificate,
    delete_certificate_by_path, delete_certificate_in_store, export_certificate,
    export_certificate_by_path, get_certificate, get_certificate_by_path, get_certificate_in_store,
    get_private_key_info, get_private_key_info_by_path, get_private_key_info_in_store, import_file,
    is_elevated, list_certificates, list_certificates_in_store, list_physical_stores,
    list_store_location_contexts, list_store_locations, list_stores, list_stores_for_context,
};

const PAGE_JUMP: usize = 10;

#[derive(Debug, Clone, Default)]
pub struct ResumeArgs {
    pub location: Option<String>,
    pub store: Option<String>,
    pub thumbprint: Option<String>,
    pub physical: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Location,
    Store,
    PhysicalStore,
    CertList,
    CertDetail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Normal,
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalAction {
    Continue,
    Reinit,
    Exit,
    Relaunched,
}

struct BrowserApp {
    screen: Screen,
    input_mode: InputMode,
    location_index: usize,
    store_index: usize,
    physical_index: usize,
    cert_index: usize,
    locations: Vec<StoreLocationContext>,
    stores: Vec<ssl_toolbox_win_certstore::StoreInfo>,
    physical_stores: Vec<PhysicalStoreInfo>,
    certs: Vec<CertEntry>,
    filtered_indices: Vec<usize>,
    details: Option<CertDetails>,
    key_info: Option<PrivateKeyInfo>,
    show_key_modal: bool,
    current_location: Option<StoreLocationContext>,
    current_store: Option<String>,
    current_physical: Option<String>,
    search_query: String,
    elevated: bool,
    status: Option<(String, Instant)>,
}

impl BrowserApp {
    fn new() -> Result<Self> {
        let mut locations = list_store_location_contexts();
        if locations.is_empty() {
            locations = list_store_locations()
                .into_iter()
                .map(|location| StoreLocationContext::new(location, None))
                .collect::<Result<Vec<_>>>()?;
        }
        Ok(Self {
            screen: Screen::Location,
            input_mode: InputMode::Normal,
            location_index: 0,
            store_index: 0,
            physical_index: 0,
            cert_index: 0,
            locations,
            stores: Vec::new(),
            physical_stores: Vec::new(),
            certs: Vec::new(),
            filtered_indices: Vec::new(),
            details: None,
            key_info: None,
            show_key_modal: false,
            current_location: None,
            current_store: None,
            current_physical: None,
            search_query: String::new(),
            elevated: is_elevated().unwrap_or(false),
            status: None,
        })
    }

    fn resume(&mut self, args: ResumeArgs) -> Result<()> {
        if let Some(location) = args.location {
            let location = StoreLocationContext::parse(&location)?;
            self.current_location = Some(location);
            self.location_index = self
                .locations
                .iter()
                .position(|candidate| *candidate == location)
                .unwrap_or(0);
            self.load_stores()?;
            self.screen = Screen::Store;
        }

        if let Some(store) = args.store {
            self.current_store = Some(store);
            if let Some(store_name) = self.current_store.clone() {
                self.store_index = self
                    .stores
                    .iter()
                    .position(|candidate| candidate.name.eq_ignore_ascii_case(&store_name))
                    .unwrap_or(0);
                if let Some(physical) = args.physical {
                    self.current_physical = Some(physical.clone());
                    self.load_physical_stores()?;
                    self.physical_index = self
                        .physical_stores
                        .iter()
                        .position(|candidate| candidate.name.eq_ignore_ascii_case(&physical))
                        .unwrap_or(0);
                    self.load_certs()?;
                } else {
                    self.load_certs()?;
                }
                self.screen = Screen::CertList;
            }
        }

        if let Some(thumbprint) = args.thumbprint {
            if let Some(index) = self.filtered_indices.iter().position(|index| {
                self.certs[*index]
                    .thumbprint
                    .eq_ignore_ascii_case(thumbprint.as_str())
            }) {
                self.cert_index = index;
                self.open_detail()?;
            } else {
                self.set_status("Saved certificate selection was not found.".to_string());
            }
        }

        Ok(())
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        self.expire_status();

        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());

        frame.render_widget(self.header(), layout[0]);

        match self.screen {
            Screen::Location => self.render_locations(frame, layout[1]),
            Screen::Store => self.render_stores(frame, layout[1]),
            Screen::PhysicalStore => self.render_physical_stores(frame, layout[1]),
            Screen::CertList => self.render_certs(frame, layout[1]),
            Screen::CertDetail => self.render_details(frame, layout[1]),
        }

        frame.render_widget(self.footer(), layout[2]);

        if self.show_key_modal {
            let area = centered_rect(70, 50, frame.area());
            frame.render_widget(Clear, area);
            frame.render_widget(self.key_modal(), area);
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        if key.kind != KeyEventKind::Press {
            return Ok(TerminalAction::Continue);
        }

        if self.show_key_modal {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.show_key_modal = false;
                }
                _ => {}
            }
            return Ok(TerminalAction::Continue);
        }

        if self.input_mode == InputMode::Search {
            return self.handle_search_input(key);
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            return Ok(TerminalAction::Exit);
        }

        match self.screen {
            Screen::Location => self.handle_location_key(key),
            Screen::Store => self.handle_store_key(key),
            Screen::PhysicalStore => self.handle_physical_key(key),
            Screen::CertList => self.handle_cert_key(key),
            Screen::CertDetail => self.handle_detail_key(key),
        }
    }

    fn handle_location_key(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.location_index = self.location_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.location_index = bounded_next(self.location_index, self.locations.len())
            }
            KeyCode::PageUp => self.location_index = self.location_index.saturating_sub(PAGE_JUMP),
            KeyCode::PageDown => {
                self.location_index =
                    bounded_advance(self.location_index, self.locations.len(), PAGE_JUMP)
            }
            KeyCode::Home => self.location_index = 0,
            KeyCode::End => self.location_index = self.locations.len().saturating_sub(1),
            KeyCode::Enter => {
                self.current_location = Some(self.locations[self.location_index].clone());
                self.load_stores()?;
                self.screen = Screen::Store;
            }
            KeyCode::Char('s') => {
                self.current_location = Some(prompt_location_context(StoreLocation::Service)?);
                self.load_stores()?;
                self.screen = Screen::Store;
                return Ok(TerminalAction::Reinit);
            }
            KeyCode::Char('a') => {
                self.current_location = Some(prompt_location_context(StoreLocation::User)?);
                self.load_stores()?;
                self.screen = Screen::Store;
                return Ok(TerminalAction::Reinit);
            }
            KeyCode::Esc | KeyCode::Char('q') => return Ok(TerminalAction::Exit),
            KeyCode::Char('u') => return self.request_elevation(),
            _ => {}
        }
        Ok(TerminalAction::Continue)
    }

    fn handle_store_key(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.store_index = self.store_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.store_index = bounded_next(self.store_index, self.stores.len())
            }
            KeyCode::PageUp => self.store_index = self.store_index.saturating_sub(PAGE_JUMP),
            KeyCode::PageDown => {
                self.store_index = bounded_advance(self.store_index, self.stores.len(), PAGE_JUMP)
            }
            KeyCode::Home => self.store_index = 0,
            KeyCode::End => self.store_index = self.stores.len().saturating_sub(1),
            KeyCode::Enter => {
                let store = self
                    .stores
                    .get(self.store_index)
                    .ok_or_else(|| anyhow!("No store selected"))?;
                self.current_store = Some(store.name.clone());
                self.current_physical = None;
                self.load_certs()?;
                self.screen = Screen::CertList;
            }
            KeyCode::Char('p') => {
                let store = self
                    .stores
                    .get(self.store_index)
                    .ok_or_else(|| anyhow!("No store selected"))?;
                self.current_store = Some(store.name.clone());
                self.load_physical_stores()?;
                self.screen = Screen::PhysicalStore;
            }
            KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Location,
            KeyCode::Char('r') => self.load_stores()?,
            KeyCode::Char('u') => return self.request_elevation(),
            KeyCode::Char('q') => return Ok(TerminalAction::Exit),
            _ => {}
        }
        Ok(TerminalAction::Continue)
    }

    fn handle_physical_key(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.physical_index = self.physical_index.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.physical_index = bounded_next(self.physical_index, self.physical_stores.len())
            }
            KeyCode::PageUp => self.physical_index = self.physical_index.saturating_sub(PAGE_JUMP),
            KeyCode::PageDown => {
                self.physical_index =
                    bounded_advance(self.physical_index, self.physical_stores.len(), PAGE_JUMP)
            }
            KeyCode::Home => self.physical_index = 0,
            KeyCode::End => self.physical_index = self.physical_stores.len().saturating_sub(1),
            KeyCode::Enter => {
                let physical = self
                    .physical_stores
                    .get(self.physical_index)
                    .ok_or_else(|| anyhow!("No physical store selected"))?;
                self.current_physical = if physical.is_logical_view {
                    None
                } else {
                    Some(physical.name.clone())
                };
                self.load_certs()?;
                self.screen = Screen::CertList;
            }
            KeyCode::Esc | KeyCode::Backspace => self.screen = Screen::Store,
            KeyCode::Char('r') => self.load_physical_stores()?,
            KeyCode::Char('q') => return Ok(TerminalAction::Exit),
            _ => {}
        }
        Ok(TerminalAction::Continue)
    }

    fn handle_cert_key(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.cert_index = self.cert_index.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.cert_index = bounded_next(self.cert_index, self.filtered_indices.len())
            }
            KeyCode::PageUp => self.cert_index = self.cert_index.saturating_sub(PAGE_JUMP),
            KeyCode::PageDown => {
                self.cert_index =
                    bounded_advance(self.cert_index, self.filtered_indices.len(), PAGE_JUMP)
            }
            KeyCode::Home => self.cert_index = 0,
            KeyCode::End => self.cert_index = self.filtered_indices.len().saturating_sub(1),
            KeyCode::Enter => self.open_detail()?,
            KeyCode::Char('/') => self.input_mode = InputMode::Search,
            KeyCode::Char('r') => self.load_certs()?,
            KeyCode::Char('m') => return self.prompt_import(),
            KeyCode::Char('u') => return self.request_elevation(),
            KeyCode::Esc | KeyCode::Backspace => {
                self.screen = Screen::Store;
                self.search_query.clear();
                self.apply_filter();
            }
            KeyCode::Char('q') => return Ok(TerminalAction::Exit),
            _ => {}
        }
        Ok(TerminalAction::Continue)
    }

    fn handle_detail_key(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => {
                self.screen = Screen::CertList;
                self.key_info = None;
            }
            KeyCode::Char('e') => return self.prompt_export(),
            KeyCode::Char('d') => return self.prompt_delete(),
            KeyCode::Char('i') => {
                let cert = self.current_cert()?.clone();
                self.key_info = Some(if cert.path.is_empty() {
                    get_private_key_info_in_store(&self.current_store_path()?, &cert.thumbprint)?
                } else {
                    get_private_key_info_by_path(&cert.path)?
                });
                self.show_key_modal = true;
            }
            KeyCode::Char('u') => return self.request_elevation(),
            KeyCode::Char('q') => return Ok(TerminalAction::Exit),
            _ => {}
        }
        Ok(TerminalAction::Continue)
    }

    fn handle_search_input(&mut self, key: crossterm::event::KeyEvent) -> Result<TerminalAction> {
        match key.code {
            KeyCode::Esc => self.input_mode = InputMode::Normal,
            KeyCode::Enter => self.input_mode = InputMode::Normal,
            KeyCode::Backspace => {
                self.search_query.pop();
                self.apply_filter();
            }
            KeyCode::Char(ch) => {
                self.search_query.push(ch);
                self.apply_filter();
            }
            _ => {}
        }
        Ok(TerminalAction::Continue)
    }

    fn load_stores(&mut self) -> Result<()> {
        let location = self
            .current_location
            .clone()
            .ok_or_else(|| anyhow!("No location selected"))?;
        self.stores = list_stores_for_context(&location)?;
        self.store_index = 0;
        self.current_store = None;
        self.current_physical = None;
        self.physical_stores.clear();
        Ok(())
    }

    fn load_physical_stores(&mut self) -> Result<()> {
        let location = self
            .current_location
            .clone()
            .ok_or_else(|| anyhow!("No location selected"))?;
        let store = self
            .current_store
            .as_ref()
            .ok_or_else(|| anyhow!("No store selected"))?;
        self.physical_stores = list_physical_stores(&location, store)?;
        self.physical_index = 0;
        Ok(())
    }

    fn load_certs(&mut self) -> Result<()> {
        let path = self.current_store_path()?;
        self.certs = list_certificates_in_store(&path)?;
        self.cert_index = 0;
        self.details = None;
        self.apply_filter();
        Ok(())
    }

    fn apply_filter(&mut self) {
        let query = self.search_query.to_ascii_lowercase();
        self.filtered_indices = self
            .certs
            .iter()
            .enumerate()
            .filter_map(|(index, cert)| {
                if query.is_empty()
                    || cert.subject.to_ascii_lowercase().contains(&query)
                    || cert.issuer.to_ascii_lowercase().contains(&query)
                    || cert.thumbprint.to_ascii_lowercase().contains(&query)
                    || cert
                        .friendly_name
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains(&query)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect();
        if self.cert_index >= self.filtered_indices.len() {
            self.cert_index = self.filtered_indices.len().saturating_sub(1);
        }
    }

    fn open_detail(&mut self) -> Result<()> {
        let cert = self.current_cert()?.clone();
        self.details = Some(if cert.path.is_empty() {
            get_certificate_in_store(&self.current_store_path()?, &cert.thumbprint)?
        } else {
            get_certificate_by_path(&cert.path)?
        });
        self.key_info = None;
        self.screen = Screen::CertDetail;
        Ok(())
    }

    fn prompt_import(&mut self) -> Result<TerminalAction> {
        let location = self
            .current_location
            .clone()
            .ok_or_else(|| anyhow!("No location selected"))?;
        let store = self
            .current_store
            .clone()
            .ok_or_else(|| anyhow!("No store selected"))?;
        if location.location.requires_qualifier() || self.current_physical.is_some() {
            self.set_status(
                "Import remains limited to the logical current-user/local-machine flow."
                    .to_string(),
            );
            return Ok(TerminalAction::Continue);
        }
        suspend_terminal(|| import_interactive(location.location, &store))?;
        self.load_certs()?;
        self.set_status(format!("Import completed for {}\\{}", location, store));
        Ok(TerminalAction::Reinit)
    }

    fn prompt_export(&mut self) -> Result<TerminalAction> {
        let cert = self.current_cert()?.clone();
        let location = self
            .current_location
            .clone()
            .ok_or_else(|| anyhow!("No location selected"))?;
        let store = self
            .current_store
            .clone()
            .ok_or_else(|| anyhow!("No store selected"))?;
        suspend_terminal(|| export_interactive(location.location, &store, &cert))?;
        self.set_status(format!("Exported {}", cert.thumbprint));
        Ok(TerminalAction::Reinit)
    }

    fn prompt_delete(&mut self) -> Result<TerminalAction> {
        let cert = self.current_cert()?.clone();
        let location = self
            .current_location
            .clone()
            .ok_or_else(|| anyhow!("No location selected"))?;
        let store = self
            .current_store
            .clone()
            .ok_or_else(|| anyhow!("No store selected"))?;
        let store_path = self.current_store_path()?;

        let deleted = suspend_terminal(|| {
            let confirmed = confirm(&format!(
                "Delete certificate {} from {}\\{}?",
                cert.thumbprint, location, store
            ))
            .initial_value(false)
            .interact()?;
            if !confirmed {
                return Ok(false);
            }
            if let Some(path) = &cert.store_path {
                delete_certificate_in_store(path, &cert.thumbprint)?;
            } else if cert.path.is_empty() {
                delete_certificate_in_store(&store_path, &cert.thumbprint)?;
            } else {
                delete_certificate_by_path(&cert.path)?;
            }
            Ok(true)
        })?;

        if !deleted {
            self.set_status("Delete cancelled.".to_string());
            return Ok(TerminalAction::Reinit);
        }

        self.screen = Screen::CertList;
        self.load_certs()?;
        self.set_status(format!("Deleted {}", cert.thumbprint));
        Ok(TerminalAction::Reinit)
    }

    fn request_elevation(&mut self) -> Result<TerminalAction> {
        if self.elevated {
            self.set_status("Already running elevated.".to_string());
            return Ok(TerminalAction::Continue);
        }

        let location = self
            .current_location
            .as_ref()
            .map(|value| value.to_string());
        let store = self.current_store.clone();
        let thumbprint = self
            .current_cert_optional()
            .map(|cert| cert.thumbprint.clone());
        let physical = self.current_physical.clone();

        suspend_terminal(|| {
            let confirmed = confirm("Relaunch the certificate manager as Administrator?")
                .initial_value(true)
                .interact()?;
            if !confirmed {
                return Ok(false);
            }
            relaunch_elevated(ResumeArgs {
                location,
                store,
                thumbprint,
                physical,
            })?;
            Ok(true)
        })
        .and_then(|launched| {
            if launched {
                Ok(TerminalAction::Relaunched)
            } else {
                Ok(TerminalAction::Reinit)
            }
        })
    }

    fn current_cert(&self) -> Result<&CertEntry> {
        let index = *self
            .filtered_indices
            .get(self.cert_index)
            .ok_or_else(|| anyhow!("No certificate selected"))?;
        self.certs
            .get(index)
            .ok_or_else(|| anyhow!("Selected certificate is out of range"))
    }

    fn current_cert_optional(&self) -> Option<&CertEntry> {
        self.filtered_indices
            .get(self.cert_index)
            .and_then(|index| self.certs.get(*index))
    }

    fn current_store_path(&self) -> Result<StorePath> {
        Ok(StorePath::new(
            self.current_location
                .clone()
                .ok_or_else(|| anyhow!("No location selected"))?,
            self.current_store
                .clone()
                .ok_or_else(|| anyhow!("No store selected"))?,
            self.current_physical.clone(),
        ))
    }

    fn header(&self) -> Paragraph<'static> {
        let location = self
            .current_location
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "choose-location".to_string());
        let store = self.current_store.as_deref().unwrap_or("choose-store");
        let physical = self.current_physical.as_deref().unwrap_or(".Logical");
        let title = format!(
            " Windows Certificate Manager  {}  {} ",
            if self.elevated {
                "[elevated]"
            } else {
                "[standard]"
            },
            match self.screen {
                Screen::Location => "location",
                Screen::Store => "stores",
                Screen::PhysicalStore => "physical",
                Screen::CertList => "certs",
                Screen::CertDetail => "detail",
            }
        );
        Paragraph::new(Line::from(vec![
            Span::styled("Path: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{location}\\{store}\\{physical}")),
        ]))
        .block(Block::default().borders(Borders::ALL).title(title))
    }

    fn footer(&self) -> Paragraph<'static> {
        let status = self
            .status
            .as_ref()
            .map(|value| value.0.as_str())
            .unwrap_or("");
        let help = match self.screen {
            Screen::Location => "Enter open  s service  a alt-user  PgUp/PgDn jump  u elevate",
            Screen::Store => "Enter open  p physical  PgUp/PgDn jump  r refresh  Esc back",
            Screen::PhysicalStore => "Enter open  PgUp/PgDn jump  r refresh  Esc back  q quit",
            Screen::CertList => "/ search  PgUp/PgDn jump  m import  r refresh  Enter detail",
            Screen::CertDetail => "i key info  e export  d delete  Esc back  u elevate",
        };
        let query = if self.input_mode == InputMode::Search {
            format!("Search: {}", self.search_query)
        } else if self.search_query.is_empty() {
            String::new()
        } else {
            format!("Filter: {}", self.search_query)
        };
        Paragraph::new(Text::from(vec![
            Line::from(query),
            Line::from(vec![
                Span::styled(help, Style::default().fg(Color::Yellow)),
                Span::raw("  "),
                Span::styled(status, Style::default().fg(Color::Green)),
            ]),
        ]))
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .wrap(Wrap { trim: true })
    }

    fn render_locations(&self, frame: &mut ratatui::Frame, area: Rect) {
        let layout = two_pane(area);
        let items = self
            .locations
            .iter()
            .map(|location| ListItem::new(location.to_string()))
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected(Some(self.location_index));
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Store Locations")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, layout[0], &mut state);
        frame.render_widget(self.location_overview(), layout[1]);
    }

    fn render_stores(&self, frame: &mut ratatui::Frame, area: Rect) {
        let layout = two_pane(area);
        let items = self
            .stores
            .iter()
            .map(|store| ListItem::new(store.name.clone()))
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected(Some(self.store_index));
        let list = List::new(items)
            .block(Block::default().title("Stores").borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, layout[0], &mut state);
        frame.render_widget(self.store_overview(), layout[1]);
    }

    fn render_physical_stores(&self, frame: &mut ratatui::Frame, area: Rect) {
        let layout = two_pane(area);
        let items = self
            .physical_stores
            .iter()
            .map(|store| {
                let label = if store.is_logical_view {
                    format!("{} (logical)", store.name)
                } else {
                    store.name.clone()
                };
                ListItem::new(label)
            })
            .collect::<Vec<_>>();
        let mut state = ListState::default().with_selected(Some(self.physical_index));
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Physical Stores")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, layout[0], &mut state);
        frame.render_widget(self.physical_overview(), layout[1]);
    }

    fn render_certs(&self, frame: &mut ratatui::Frame, area: Rect) {
        let layout = two_pane(area);
        let rows = self
            .filtered_indices
            .iter()
            .map(|index| {
                let cert = &self.certs[*index];
                let detail = format!(
                    "{} | {} | {}",
                    short_subject(&cert.subject),
                    cert.not_after,
                    if cert.has_private_key {
                        "key"
                    } else {
                        "public"
                    }
                );
                ListItem::new(Line::from(vec![
                    Span::styled(
                        short_thumbprint(&cert.thumbprint),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw("  "),
                    Span::raw(detail),
                ]))
            })
            .collect::<Vec<_>>();

        let title = if self.search_query.is_empty() {
            "Certificates"
        } else {
            "Certificates (filtered)"
        };
        let mut state = ListState::default().with_selected(Some(self.cert_index));
        let list = List::new(rows)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, layout[0], &mut state);
        frame.render_widget(self.cert_overview(), layout[1]);
    }

    fn render_details(&self, frame: &mut ratatui::Frame, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(9), Constraint::Min(8)])
            .split(area);

        let details = self.details.as_ref();
        let cert = details.map(|value| &value.entry);
        let summary = if let Some(cert) = cert {
            vec![
                Line::from(format!("Thumbprint: {}", cert.thumbprint)),
                Line::from(format!("Subject: {}", cert.subject)),
                Line::from(format!("Issuer: {}", cert.issuer)),
                Line::from(format!("Valid From: {}", cert.not_before)),
                Line::from(format!("Valid Until: {}", cert.not_after)),
                Line::from(format!(
                    "Private Key: {}",
                    if cert.has_private_key { "Yes" } else { "No" }
                )),
                Line::from(format!(
                    "Friendly Name: {}",
                    cert.friendly_name.as_deref().unwrap_or("-")
                )),
            ]
        } else {
            vec![Line::from("No certificate details loaded.")]
        };
        frame.render_widget(
            Paragraph::new(summary)
                .block(Block::default().title("Summary").borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            layout[0],
        );

        let mut extra = Vec::new();
        if let Some(details) = details {
            if let Some(serial) = &details.serial_number {
                extra.push(Line::from(format!("Serial Number: {serial}")));
            }
            if let Some(version) = &details.version {
                extra.push(Line::from(format!("Version: {version}")));
            }
            if let Some(alg) = &details.signature_algorithm {
                extra.push(Line::from(format!("Signature Algorithm: {alg}")));
            }
            if !details.dns_names.is_empty() {
                extra.push(Line::from("DNS Names:"));
                extra.extend(
                    details
                        .dns_names
                        .iter()
                        .map(|name| Line::from(format!("  - {name}"))),
                );
            }
        }
        if extra.is_empty() {
            extra.push(Line::from("No additional metadata."));
        }
        frame.render_widget(
            Paragraph::new(extra)
                .block(Block::default().title("Details").borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
            layout[1],
        );
    }

    fn key_modal(&self) -> Paragraph<'static> {
        let lines = if let Some(info) = &self.key_info {
            vec![
                Line::from(format!("Provider Kind: {}", info.provider_kind)),
                Line::from(format!(
                    "Provider Name: {}",
                    info.provider_name.as_deref().unwrap_or("-")
                )),
                Line::from(format!(
                    "Container Name: {}",
                    info.container_name.as_deref().unwrap_or("-")
                )),
                Line::from(format!(
                    "Key Spec: {}",
                    info.key_spec.as_deref().unwrap_or("-")
                )),
                Line::from(format!("Exportable: {}", bool_or_unknown(info.exportable))),
                Line::from(format!(
                    "User Protected: {}",
                    bool_or_unknown(info.user_protected)
                )),
                Line::from(format!(
                    "Accessible: {}",
                    if info.accessible { "Yes" } else { "No" }
                )),
                Line::from(format!(
                    "Message: {}",
                    info.message.as_deref().unwrap_or("-")
                )),
                Line::from(""),
                Line::from("Esc closes this dialog."),
            ]
        } else {
            vec![Line::from("Private-key metadata is not loaded.")]
        };
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Private Key Inspection")
                    .borders(Borders::ALL)
                    .style(Style::default().bg(Color::Black)),
            )
            .wrap(Wrap { trim: true })
    }

    fn location_overview(&self) -> Paragraph<'static> {
        let selected = self
            .locations
            .get(self.location_index)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        Paragraph::new(vec![
            Line::from(format!("Selected: {selected}")),
            Line::from(format!("Discovered locations: {}", self.locations.len())),
            Line::from(""),
            Line::from("Enter opens a built-in location."),
            Line::from("Press 's' to prompt for a named service store."),
            Line::from("Press 'a' to prompt for an alternate user store."),
        ])
        .block(Block::default().title("Overview").borders(Borders::ALL))
        .wrap(Wrap { trim: true })
    }

    fn store_overview(&self) -> Paragraph<'static> {
        let selected = self
            .stores
            .get(self.store_index)
            .map(|value| value.name.as_str())
            .unwrap_or("-");
        let location = self
            .current_location
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        Paragraph::new(vec![
            Line::from(format!("Location: {location}")),
            Line::from(format!("Selected store: {selected}")),
            Line::from(format!("Visible stores: {}", self.stores.len())),
            Line::from(""),
            Line::from("Enter opens the logical store view."),
            Line::from("Press 'p' to inspect physical stores for the selection."),
            Line::from("Qualified service/user contexts also flow through here."),
        ])
        .block(Block::default().title("Overview").borders(Borders::ALL))
        .wrap(Wrap { trim: true })
    }

    fn physical_overview(&self) -> Paragraph<'static> {
        let selected = self
            .physical_stores
            .get(self.physical_index)
            .map(|value| value.name.as_str())
            .unwrap_or("-");
        let location = self
            .current_location
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        let store = self.current_store.as_deref().unwrap_or("-");
        Paragraph::new(vec![
            Line::from(format!("Location: {location}")),
            Line::from(format!("Store: {store}")),
            Line::from(format!("Selected physical view: {selected}")),
            Line::from(format!("Views discovered: {}", self.physical_stores.len())),
            Line::from(""),
            Line::from("Use Enter to browse certificates in the selected view."),
        ])
        .block(Block::default().title("Overview").borders(Borders::ALL))
        .wrap(Wrap { trim: true })
    }

    fn cert_overview(&self) -> Paragraph<'static> {
        let lines = if let Some(cert) = self.current_cert_optional() {
            vec![
                Line::from(format!("Subject: {}", short_subject(&cert.subject))),
                Line::from(format!("Issuer: {}", short_subject(&cert.issuer))),
                Line::from(format!("Thumbprint: {}", cert.thumbprint)),
                Line::from(format!("Expires: {}", cert.not_after)),
                Line::from(format!(
                    "Private Key: {}",
                    if cert.has_private_key { "Yes" } else { "No" }
                )),
                Line::from(format!(
                    "Friendly Name: {}",
                    cert.friendly_name.as_deref().unwrap_or("-")
                )),
                Line::from(format!(
                    "Identity: {}",
                    cert.identity_hint.as_deref().unwrap_or("-")
                )),
                Line::from(""),
                Line::from(format!(
                    "Result {}/{}",
                    self.cert_index.saturating_add(1),
                    self.filtered_indices.len()
                )),
            ]
        } else {
            vec![
                Line::from("No certificate selected."),
                Line::from(""),
                Line::from("Use search to narrow results."),
            ]
        };
        Paragraph::new(lines)
            .block(Block::default().title("Selection").borders(Borders::ALL))
            .wrap(Wrap { trim: true })
    }

    fn set_status(&mut self, message: String) {
        self.status = Some((message, Instant::now()));
    }

    fn expire_status(&mut self) {
        if let Some((_, timestamp)) = &self.status {
            if timestamp.elapsed() > Duration::from_secs(6) {
                self.status = None;
            }
        }
    }
}

pub fn launch_certmgr(resume: Option<ResumeArgs>) -> Result<()> {
    let mut terminal = ratatui::init();
    terminal.clear()?;

    let mut app = BrowserApp::new()?;
    if let Some(args) = resume {
        app.resume(args)?;
    }

    let result = run_browser(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run_browser(terminal: &mut DefaultTerminal, app: &mut BrowserApp) -> Result<()> {
    loop {
        terminal.draw(|frame| app.render(frame))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        if let Event::Key(key) = event::read()? {
            match app.handle_key(key)? {
                TerminalAction::Continue => {}
                TerminalAction::Reinit => {
                    *terminal = ratatui::init();
                    terminal.clear()?;
                }
                TerminalAction::Exit => return Ok(()),
                TerminalAction::Relaunched => return Ok(()),
            }
        }
    }
}

pub fn browse() -> Result<()> {
    launch_certmgr(None)
}

pub fn list_store_names(location: &str) -> Result<()> {
    let location = StoreLocation::parse(location)?;
    let stores = list_stores(location)?;

    if stores.is_empty() {
        println!("No stores found for {}.", location);
        return Ok(());
    }

    println!("Stores for {}:", location);
    for store in stores {
        println!("  {}", store.name);
    }
    Ok(())
}

pub fn list_store_certs(location: &str, store: &str) -> Result<()> {
    let location = StoreLocation::parse(location)?;
    let certs = list_certificates(location, store)?;
    print_cert_list(location, store, &certs);
    Ok(())
}

pub fn show_certificate_details(location: &str, store: &str, thumbprint: &str) -> Result<()> {
    let location = StoreLocation::parse(location)?;
    let details = get_certificate(location, store, thumbprint)?;
    let key_info = get_private_key_info(location, store, thumbprint).ok();
    print_cert_details(location, store, &details, key_info.as_ref());
    Ok(())
}

pub fn import_into_store(
    location: &str,
    store: &str,
    file: &str,
    password: Option<String>,
    exportable: bool,
) -> Result<()> {
    let options = ImportOptions {
        location: StoreLocation::parse(location)?,
        store: store.to_string(),
        file_path: file.to_string(),
        password,
        exportable,
    };
    let result = import_file(&options)?;
    println!(
        "Imported {} certificate(s) into {}\\{}.",
        result.imported, location, store
    );
    for thumbprint in result.thumbprints {
        println!("  {}", thumbprint);
    }
    Ok(())
}

pub fn export_from_store(
    location: &str,
    store: &str,
    thumbprint: &str,
    out: &str,
    format: &str,
    pfx_password: Option<String>,
) -> Result<()> {
    let options = ExportOptions {
        location: StoreLocation::parse(location)?,
        store: store.to_string(),
        thumbprint: thumbprint.to_string(),
        output_path: out.to_string(),
        format: ExportFormat::parse(format)?,
        password: pfx_password,
    };
    export_certificate(&options)?;
    println!("Exported {} to {}", thumbprint, out);
    Ok(())
}

pub fn delete_from_store(location: &str, store: &str, thumbprint: &str, force: bool) -> Result<()> {
    let location = StoreLocation::parse(location)?;
    if !force {
        let confirmed = confirm(&format!(
            "Delete certificate {} from {}\\{}?",
            thumbprint, location, store
        ))
        .initial_value(false)
        .interact()?;
        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }
    delete_certificate(location, store, thumbprint)?;
    println!("Deleted {} from {}\\{}", thumbprint, location, store);
    Ok(())
}

fn import_interactive(location: StoreLocation, store: &str) -> Result<()> {
    let file_path: String = input("Path to certificate file").interact()?;
    let password_input: String = password("PFX password (leave blank if not needed)")
        .allow_empty()
        .interact()?;
    let exportable = confirm("Mark imported private keys as exportable?")
        .initial_value(false)
        .interact()?;

    import_file(&ImportOptions {
        location,
        store: store.to_string(),
        file_path,
        password: if password_input.is_empty() {
            None
        } else {
            Some(password_input)
        },
        exportable,
    })?;
    println!("Import complete.");
    Ok(())
}

fn export_interactive(
    location: StoreLocation,
    store: &str,
    cert: &ssl_toolbox_win_certstore::CertEntry,
) -> Result<()> {
    let format = select("Export format")
        .item("der".to_string(), "DER", "Binary X.509 certificate")
        .item("pem".to_string(), "PEM", "Base64 with certificate headers")
        .item(
            "pfx".to_string(),
            "PFX",
            "Certificate and private key container",
        )
        .interact()?;
    let default_name = default_export_filename(&cert.thumbprint, &format);
    let out: String = input("Output path")
        .default_input(&default_name)
        .interact()?;
    let pfx_password = if format == "pfx" {
        let value: String = password("PFX export password").interact()?;
        Some(value)
    } else {
        None
    };

    let export_format = ExportFormat::parse(&format)?;
    if cert.path.is_empty() {
        export_certificate(&ExportOptions {
            location,
            store: store.to_string(),
            thumbprint: cert.thumbprint.clone(),
            output_path: out.clone(),
            format: export_format,
            password: pfx_password,
        })?;
    } else {
        export_certificate_by_path(&cert.path, &out, export_format, pfx_password)?;
    }
    println!("Exported to {}", out);
    Ok(())
}

fn print_cert_list(
    location: StoreLocation,
    store: &str,
    certs: &[ssl_toolbox_win_certstore::CertEntry],
) {
    println!();
    println!("Store: {}\\{}", location, store);
    if certs.is_empty() {
        println!("  No certificates found.");
        println!();
        return;
    }

    for cert in certs {
        println!(
            "  {} | {} | {} | {}",
            short_thumbprint(&cert.thumbprint),
            short_subject(&cert.subject),
            cert.not_after,
            if cert.has_private_key {
                "private-key"
            } else {
                "public-only"
            }
        );
    }
    println!();
}

fn print_cert_details(
    location: StoreLocation,
    store: &str,
    details: &ssl_toolbox_win_certstore::CertDetails,
    key_info: Option<&PrivateKeyInfo>,
) {
    println!();
    println!("Store: {}\\{}", location, store);
    println!("Thumbprint: {}", details.entry.thumbprint);
    println!("Subject: {}", details.entry.subject);
    println!("Issuer: {}", details.entry.issuer);
    println!("Valid From: {}", details.entry.not_before);
    println!("Valid Until: {}", details.entry.not_after);
    println!(
        "Private Key: {}",
        if details.entry.has_private_key {
            "Yes"
        } else {
            "No"
        }
    );
    if let Some(name) = &details.entry.friendly_name {
        println!("Friendly Name: {}", name);
    }
    if let Some(serial) = &details.serial_number {
        println!("Serial Number: {}", serial);
    }
    if let Some(version) = &details.version {
        println!("Version: {}", version);
    }
    if let Some(alg) = &details.signature_algorithm {
        println!("Signature Algorithm: {}", alg);
    }
    if !details.dns_names.is_empty() {
        println!("DNS Names:");
        for name in &details.dns_names {
            println!("  - {}", name);
        }
    }
    if let Some(info) = key_info {
        println!("Key Provider: {}", info.provider_kind);
        if let Some(provider_name) = &info.provider_name {
            println!("Key Provider Name: {}", provider_name);
        }
        if let Some(container_name) = &info.container_name {
            println!("Key Container: {}", container_name);
        }
        println!(
            "Key Accessible: {}",
            if info.accessible { "Yes" } else { "No" }
        );
        if let Some(value) = info.exportable {
            println!("Key Exportable: {}", if value { "Yes" } else { "No" });
        }
        if let Some(message) = &info.message {
            println!("Key Message: {}", message);
        }
    }
    println!();
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn two_pane(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area)
        .to_vec()
}

fn suspend_terminal<T, F>(action: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    ratatui::restore();
    let result = action();
    result
}

fn relaunch_elevated(resume: ResumeArgs) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut args = vec!["--certmgr".to_string()];
    if let Some(location) = resume.location {
        args.push("--certmgr-location".to_string());
        args.push(location);
    }
    if let Some(store) = resume.store {
        args.push("--certmgr-store".to_string());
        args.push(store);
    }
    if let Some(thumbprint) = resume.thumbprint {
        args.push("--certmgr-thumbprint".to_string());
        args.push(thumbprint);
    }
    if let Some(physical) = resume.physical {
        args.push("--certmgr-physical".to_string());
        args.push(physical);
    }

    let args_literal = args
        .into_iter()
        .map(|arg| format!("'{}'", ps_quote(&arg)))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        "Start-Process -Verb RunAs -FilePath '{}' -ArgumentList @({})",
        ps_quote(&exe.display().to_string()),
        args_literal
    );
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Failed to relaunch elevated: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn ps_quote(input: &str) -> String {
    input.replace('\'', "''")
}

fn short_thumbprint(thumbprint: &str) -> String {
    thumbprint.chars().take(12).collect()
}

fn short_subject(subject: &str) -> String {
    subject
        .split(',')
        .next()
        .unwrap_or(subject)
        .trim()
        .to_string()
}

fn default_export_filename(thumbprint: &str, format: &str) -> String {
    format!("cert-{}.{}", short_thumbprint(thumbprint), format)
}

fn bool_or_unknown(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "Yes",
        Some(false) => "No",
        None => "Unknown",
    }
}

fn bounded_next(current: usize, len: usize) -> usize {
    if current + 1 < len {
        current + 1
    } else {
        current
    }
}

fn bounded_advance(current: usize, len: usize, amount: usize) -> usize {
    if len == 0 {
        0
    } else {
        current.saturating_add(amount).min(len.saturating_sub(1))
    }
}

fn prompt_location_context(location: StoreLocation) -> Result<StoreLocationContext> {
    let label = match location {
        StoreLocation::Service => "Service name",
        StoreLocation::User => "Domain\\Username",
        _ => "Qualifier",
    };
    let qualifier: String = input(label).interact()?;
    StoreLocationContext::new(location, Some(qualifier))
}
