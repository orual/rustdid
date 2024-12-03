use crate::{
    coordinator::{AccountParams, SetupCoordinator, SetupStep},
    errors::{SetupError, SetupResult},
};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use std::{io, path::PathBuf};

const LOGO: &str = r#"                                               
                     ___________________________
___________  __________  /______  /__(_)_____  /
__  ___/  / / /_  ___/  __/  __  /__  /_  __  / 
_  /   / /_/ /_(__  )/ /_ / /_/ / _  / / /_/ /  
/_/    \__,_/ /____/ \__/ \__,_/  /_/  \__,_/   
"#;

#[derive(Debug, Clone)]
enum AccountField {
    Handle,
    Password,
    Email,
    InviteCode,
}

#[derive(Debug, Clone, PartialEq)]
enum SetupMode {
    Menu,
    Did,
    Account,
}

#[derive(Debug, Clone, PartialEq)]
struct SetupState {
    did_complete: bool,
    account_complete: bool,
}

pub struct SetupUI {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    coordinator: SetupCoordinator,
    current_input: String,
    input_prompt: String,
    status_message: String,
    output_buffer: Vec<String>,
    is_error: bool,
    account_field: Option<AccountField>,
    account_params: AccountParams,
    mode: SetupMode,
    state: SetupState,
}

impl SetupUI {
    pub fn new() -> SetupResult<Self> {
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| {
            SetupError::input(format!("Failed to initialize terminal: {}", e), "terminal")
        })?;
        let coordinator = SetupCoordinator::new(std::path::PathBuf::from("./.rustdid"));

        Ok(Self {
            terminal,
            coordinator,
            current_input: String::new(),
            input_prompt: String::new(),
            status_message: String::from("Welcome to RustDID Setup!"),
            output_buffer: Vec::new(),
            is_error: false,
            account_field: None,
            account_params: AccountParams {
                handle: String::new(),
                password: String::new(),
                email: None,
                invite_code: None,
            },
            mode: SetupMode::Menu,
            state: SetupState {
                did_complete: false,
                account_complete: false,
            },
        })
    }

    fn add_output(&mut self, message: String) {
        self.output_buffer.push(message);
        if self.output_buffer.len() > 100 {
            self.output_buffer.remove(0);
        }
    }

    fn start_account_setup(&mut self) {
        self.account_field = Some(AccountField::Handle);
        self.current_input.clear();
        self.input_prompt = "Enter your handle (e.g. example.com)".into();
        self.status_message = "Setting up account - Step 1/4: Handle".into();
    }

    async fn verify_did_setup(&mut self) -> SetupResult<bool> {
        if let Some(domain) = self.coordinator.domain() {
            match self.coordinator.atp_client.resolve_identifier(domain).await {
                Ok(doc) => {
                    self.add_output(format!("Successfully verified DID document at {}", doc.id));
                    self.add_output(
                        "DID Web configuration is complete and working correctly.".into(),
                    );
                    self.status_message = "DID setup completed successfully".into();
                    self.is_error = false;
                    Ok(true)
                }
                Err(e) => {
                    self.add_output(format!("Warning: Could not verify DID document: {}", e));
                    self.add_output(
                        "Setup is complete but your web server may need additional configuration."
                            .into(),
                    );
                    self.status_message = "DID setup completed with warnings".into();
                    self.is_error = true;
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    }

    fn render_menu(state: &SetupState) -> Vec<Line> {
        vec![
            Line::from(vec![
                Span::styled("DID Document Setup ", Style::default().fg(Color::Blue)),
                Span::raw("["),
                Span::styled(
                    if state.did_complete {
                        "Complete"
                    } else {
                        "Incomplete"
                    },
                    Style::default().fg(if state.did_complete {
                        Color::Green
                    } else {
                        Color::Yellow
                    }),
                ),
                Span::raw("]"),
            ]),
            Line::from("Press 1 to setup or update your DID document"),
            Line::from(""),
            Line::from(vec![
                Span::styled("Account Setup ", Style::default().fg(Color::Blue)),
                Span::raw("["),
                Span::styled(
                    if state.account_complete {
                        "Complete"
                    } else {
                        "Incomplete"
                    },
                    Style::default().fg(if state.account_complete {
                        Color::Green
                    } else {
                        Color::Yellow
                    }),
                ),
                Span::raw("]"),
            ]),
            Line::from(if state.did_complete {
                "Press 2 to setup your account"
            } else {
                "Complete DID document setup before account setup"
            }),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Press ESC to exit",
                Style::default().fg(Color::DarkGray),
            )]),
        ]
    }

    fn handle_menu_input(&mut self, key: KeyCode) -> SetupResult<bool> {
        match key {
            KeyCode::Char('1') => {
                self.mode = SetupMode::Did;
                self.add_output("Starting DID document setup...".into());
                Ok(false)
            }
            KeyCode::Char('2') if self.state.did_complete => {
                self.mode = SetupMode::Account;
                self.start_account_setup();
                self.add_output("Starting account setup...".into());
                Ok(false)
            }
            KeyCode::Esc => Ok(true),
            _ => Ok(false),
        }
    }

    fn handle_account_input(&mut self) -> SetupResult<bool> {
        match self.account_field.as_ref() {
            Some(AccountField::Handle) => {
                if self.current_input.is_empty() {
                    self.status_message = "Handle cannot be empty".into();
                    self.is_error = true;
                    return Ok(false);
                }
                self.account_params.handle = self.current_input.clone();
                self.account_field = Some(AccountField::Password);
                self.input_prompt = "Enter your password (minimum 8 characters)".into();
                self.status_message = "Setting up account - Step 2/4: Password".into();
            }
            Some(AccountField::Password) => {
                if self.current_input.len() < 8 {
                    self.status_message = "Password must be at least 8 characters".into();
                    self.is_error = true;
                    return Ok(false);
                }
                self.account_params.password = self.current_input.clone();
                self.account_field = Some(AccountField::Email);
                self.input_prompt = "Enter your email (optional, press Enter to skip)".into();
                self.status_message = "Setting up account - Step 3/4: Email".into();
            }
            Some(AccountField::Email) => {
                if !self.current_input.is_empty() {
                    if !self.current_input.contains('@') || !self.current_input.contains('.') {
                        self.status_message = "Invalid email format".into();
                        self.is_error = true;
                        return Ok(false);
                    }
                    self.account_params.email = Some(self.current_input.clone());
                }
                self.account_field = Some(AccountField::InviteCode);
                self.input_prompt = "Enter your invite code".into();
                self.status_message = "Setting up account - Step 4/4: Invite Code".into();
            }
            Some(AccountField::InviteCode) => {
                if !self.current_input.is_empty() {
                    self.account_params.invite_code = Some(self.current_input.clone());
                }
                self.coordinator
                    .set_account_params(self.account_params.clone())?;
                return Ok(true);
            }
            None => {}
        }
        self.current_input.clear();
        self.is_error = false;
        Ok(false)
    }

    fn check_existing_setup(&mut self) -> SetupResult<()> {
        let did_path = PathBuf::from("./.rustdid/did.json");
        if did_path.exists() {
            self.state.did_complete = true;
            self.add_output("Found existing DID configuration.".into());
        }
        Ok(())
    }

    pub async fn run(&mut self) -> SetupResult<()> {
        enable_raw_mode().map_err(|e| {
            SetupError::input(format!("Failed to enable raw mode: {}", e), "terminal")
        })?;

        self.check_existing_setup()?;

        self.terminal
            .backend_mut()
            .execute(EnterAlternateScreen)
            .map_err(|e| {
                SetupError::input(
                    format!("Failed to enter alternate screen: {}", e),
                    "terminal",
                )
            })?;

        let result = self.run_setup().await;

        // Cleanup
        disable_raw_mode().map_err(|e| {
            SetupError::input(format!("Failed to disable raw mode: {}", e), "terminal")
        })?;
        self.terminal
            .backend_mut()
            .execute(LeaveAlternateScreen)
            .map_err(|e| {
                SetupError::input(
                    format!("Failed to leave alternate screen: {}", e),
                    "terminal",
                )
            })?;
        self.terminal
            .show_cursor()
            .map_err(|e| SetupError::input(format!("Failed to show cursor: {}", e), "terminal"))?;

        result
    }

    async fn run_setup(&mut self) -> SetupResult<()> {
        self.coordinator.initialize().await?;
        self.add_output("Starting setup process...".into());

        loop {
            self.draw()
                .map_err(|e| SetupError::input(format!("Failed to draw UI: {}", e), "terminal"))?;

            if let Event::Key(key) = event::read().map_err(|e| {
                SetupError::input(format!("Failed to read event: {}", e), "terminal")
            })? {
                match self.mode {
                    SetupMode::Menu => {
                        if self.handle_menu_input(key.code)? {
                            return Ok(());
                        }
                    }
                    SetupMode::Did => match key.code {
                        KeyCode::Enter => match self.coordinator.current_step() {
                            SetupStep::Domain => {
                                self.handle_domain_setup().await?;
                            }
                            SetupStep::Pds => {
                                self.handle_pds_setup().await?;
                            }
                            SetupStep::Keys => {
                                self.handle_key_generation().await?;
                            }
                            SetupStep::DidDocument => {
                                self.handle_did_creation().await?;
                            }
                            SetupStep::ServiceAuth => {
                                self.handle_auth_generation().await?;
                                self.state.did_complete = true;
                                self.mode = SetupMode::Menu;
                            }
                            _ => {}
                        },
                        KeyCode::Char(c) => {
                            self.current_input.push(c);
                        }
                        KeyCode::Backspace => {
                            self.current_input.pop();
                        }
                        KeyCode::Esc => {
                            self.mode = SetupMode::Menu;
                            self.current_input.clear();
                        }
                        _ => {}
                    },
                    SetupMode::Account => match key.code {
                        KeyCode::Enter => {
                            if self.handle_account_input()? {
                                match self.coordinator.proceed().await {
                                    Ok(_) => {
                                        self.state.account_complete = true;
                                        self.mode = SetupMode::Menu;
                                        self.add_output(
                                            "Account setup completed successfully.".into(),
                                        );
                                    }
                                    Err(e) => {
                                        self.status_message = format!("Error: {}", e);
                                        self.add_output(format!("Account setup failed: {}", e));
                                        self.is_error = true;
                                    }
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            self.current_input.push(c);
                        }
                        KeyCode::Backspace => {
                            self.current_input.pop();
                        }
                        KeyCode::Esc => {
                            self.mode = SetupMode::Menu;
                            self.current_input.clear();
                            self.account_field = None;
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    async fn handle_domain_setup(&mut self) -> SetupResult<()> {
        if self.current_input.is_empty() {
            self.status_message = "Domain cannot be empty".into();
            self.is_error = true;
            return Ok(());
        }

        match self.coordinator.set_domain(self.current_input.clone()) {
            Ok(_) => {
                self.add_output(format!("Setting domain to: {}", self.current_input));
                match self.coordinator.proceed().await {
                    Ok(_) => {
                        self.add_output("Domain configuration completed successfully.".into());
                        self.current_input.clear();
                        self.is_error = false;
                        self.status_message = self.coordinator.step_description().into();
                    }
                    Err(e) => {
                        self.status_message = format!("Error: {}", e);
                        self.add_output(format!("Domain configuration failed: {}", e));
                        self.is_error = true;
                    }
                }
            }
            Err(e) => {
                self.status_message = format!("Error: {}", e);
                self.is_error = true;
            }
        }
        Ok(())
    }

    async fn handle_pds_setup(&mut self) -> SetupResult<()> {
        if self.current_input.is_empty() {
            self.status_message = "PDS host cannot be empty".into();
            self.is_error = true;
            return Ok(());
        }

        if self.current_input.contains("bsky.social") {
            self.status_message = "Error: bsky.social cannot be used as PDS".into();
            self.is_error = true;
            return Ok(());
        }

        match self.coordinator.set_pds_host(self.current_input.clone()) {
            Ok(_) => {
                self.add_output(format!("Setting PDS host to: {}", self.current_input));
                match self.coordinator.proceed().await {
                    Ok(_) => {
                        self.add_output("PDS host configuration completed successfully.".into());
                        self.current_input.clear();
                        self.is_error = false;
                        self.status_message = self.coordinator.step_description().into();
                    }
                    Err(e) => {
                        self.status_message = format!("Error: {}", e);
                        self.add_output(format!("PDS configuration failed: {}", e));
                        self.is_error = true;
                    }
                }
            }
            Err(e) => {
                self.status_message = format!("Error: {}", e);
                self.is_error = true;
            }
        }
        Ok(())
    }

    async fn handle_key_generation(&mut self) -> SetupResult<()> {
        self.add_output("Generating cryptographic keypair...".into());
        match self.coordinator.proceed().await {
            Ok(_) => {
                self.add_output("Keypair generated successfully.".into());
                self.status_message = self.coordinator.step_description().into();
            }
            Err(e) => {
                self.status_message = format!("Error: {}", e);
                self.add_output(format!("Key generation failed: {}", e));
                self.is_error = true;
            }
        }
        Ok(())
    }

    async fn handle_did_creation(&mut self) -> SetupResult<()> {
        self.add_output("Creating DID document...".into());
        match self.coordinator.proceed().await {
            Ok(_) => {
                self.add_output("DID document created successfully.".into());
                self.status_message = self.coordinator.step_description().into();
            }
            Err(e) => {
                self.status_message = format!("Error: {}", e);
                self.add_output(format!("DID document creation failed: {}", e));
                self.is_error = true;
            }
        }
        Ok(())
    }

    async fn handle_auth_generation(&mut self) -> SetupResult<()> {
        self.add_output("Generating service authentication...".into());
        match self.coordinator.proceed().await {
            Ok(_) => {
                self.add_output("Service authentication generated successfully.".into());
                self.status_message = "Verifying DID document configuration...".into();

                let verified = self.verify_did_setup().await?;
                self.state.did_complete = true;
                self.mode = SetupMode::Menu;

                if verified {
                    self.add_output("Ready to proceed with account setup.".into());
                }
            }
            Err(e) => {
                self.status_message = format!("Error: {}", e);
                self.add_output(format!("Service auth generation failed: {}", e));
                self.is_error = true;
            }
        }
        Ok(())
    }

    fn draw(&mut self) -> SetupResult<()> {
        let status_message = self.status_message.clone();
        let input_prompt = self.input_prompt.clone();
        let current_input = self.current_input.clone();
        let current_step = self.coordinator.current_step();
        let step_help = self.coordinator.step_help().to_string();
        let mode = self.mode.clone();
        let is_error = self.is_error;
        let state = self.state.clone();
        let output_buffer = self.output_buffer.clone();

        // Use the updated render_menu function
        let menu_text = match mode {
            SetupMode::Menu => SetupUI::render_menu(&state),
            _ => vec![Line::from(step_help)],
        };

        let output_text = if output_buffer.len() > 10 {
            output_buffer
                .iter()
                .skip(output_buffer.len() - 10)
                .map(|s| Line::from(s.clone()))
                .collect::<Vec<Line>>()
        } else {
            output_buffer
                .iter()
                .map(|s| Line::from(s.clone()))
                .collect::<Vec<Line>>()
        };

        let terminal = &mut self.terminal;
        terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(7), // Logo
                        Constraint::Length(3), // Status
                        Constraint::Length(3), // Input
                        Constraint::Length(8), // Menu/Help
                        Constraint::Min(5),    // Output Area
                        Constraint::Length(3), // Controls
                    ])
                    .split(f.area());

                // Logo
                let logo = Paragraph::new(Text::from(LOGO)).style(Style::default().fg(Color::Cyan));
                f.render_widget(logo, chunks[0]);

                // Status Message
                let status_style = if is_error {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                };
                let status = Paragraph::new(Text::from(status_message))
                    .style(status_style)
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(status, chunks[1]);

                // Input Field
                if mode != SetupMode::Menu
                    && !matches!(
                        current_step,
                        SetupStep::Keys | SetupStep::DidDocument | SetupStep::ServiceAuth
                    )
                {
                    let input = Paragraph::new(Text::from(Line::from(vec![
                        Span::raw(&input_prompt),
                        Span::raw(" "),
                        Span::styled(&current_input, Style::default().fg(Color::Yellow)),
                    ])))
                    .block(Block::default().borders(Borders::ALL));
                    f.render_widget(input, chunks[2]);
                }

                // Menu/Help Text
                let menu = Paragraph::new(menu_text).block(Block::default().borders(Borders::ALL));
                f.render_widget(menu, chunks[3]);

                // Output Area
                let output = Paragraph::new(Text::from(output_text))
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL).title("Output"))
                    .wrap(Wrap { trim: true })
                    .scroll((0, 0));
                f.render_widget(output, chunks[4]);

                // Controls
                let controls_text = match mode {
                    SetupMode::Menu => vec![Line::from(vec![
                        Span::styled("1", Style::default().fg(Color::Blue)),
                        Span::raw(" DID Setup  |  "),
                        Span::styled("2", Style::default().fg(Color::Blue)),
                        Span::raw(" Account Setup  |  "),
                        Span::styled("ESC", Style::default().fg(Color::Blue)),
                        Span::raw(" Exit"),
                    ])],
                    _ => vec![Line::from(vec![
                        Span::styled("ENTER", Style::default().fg(Color::Blue)),
                        Span::raw(" Continue  |  "),
                        Span::styled("ESC", Style::default().fg(Color::Blue)),
                        Span::raw(" Back to Menu"),
                    ])],
                };

                let controls = Paragraph::new(Text::from(controls_text))
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(controls, chunks[5]);
            })
            .map_err(|e| SetupError::input(format!("Failed to draw UI: {}", e), "terminal"))?;

        Ok(())
    }
}
