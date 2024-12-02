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
use std::io;

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
            }
            Some(AccountField::Password) => {
                if self.current_input.len() < 8 {
                    self.status_message = "Password must be at least 8 characters".into();
                    self.is_error = true;
                    return Ok(false);
                }
                self.account_params.password = self.current_input.clone();
                self.account_field = Some(AccountField::Email);
            }
            Some(AccountField::Email) => {
                if !self.current_input.is_empty() {
                    self.account_params.email = Some(self.current_input.clone());
                }
                self.account_field = Some(AccountField::InviteCode);
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

    pub async fn run(&mut self) -> SetupResult<()> {
        enable_raw_mode().map_err(|e| {
            SetupError::input(format!("Failed to enable raw mode: {}", e), "terminal")
        })?;
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
                match key.code {
                    KeyCode::Enter => match self.coordinator.current_step() {
                        SetupStep::Domain => {
                            if self.current_input.is_empty() {
                                self.status_message = "Domain cannot be empty".into();
                                self.is_error = true;
                                continue;
                            }

                            match self.coordinator.set_domain(self.current_input.clone()) {
                                Ok(_) => {
                                    self.add_output(format!(
                                        "Setting domain to: {}",
                                        self.current_input
                                    ));
                                    match self.coordinator.proceed().await {
                                        Ok(_) => {
                                            self.add_output(
                                                "Domain configuration completed successfully."
                                                    .into(),
                                            );
                                            self.current_input.clear();
                                            self.is_error = false;
                                            self.status_message =
                                                self.coordinator.step_description().into();
                                        }
                                        Err(e) => {
                                            self.status_message = format!("Error: {}", e);
                                            self.add_output(format!(
                                                "Domain configuration failed: {}",
                                                e
                                            ));
                                            self.is_error = true;
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.status_message = format!("Error: {}", e);
                                    self.is_error = true;
                                }
                            }
                        }

                        SetupStep::Pds => {
                            if self.current_input.is_empty() {
                                self.status_message = "PDS host cannot be empty".into();
                                self.is_error = true;
                                continue;
                            }

                            if self.current_input.contains("bsky.social") {
                                self.status_message =
                                    "Error: bsky.social cannot be used as PDS".into();
                                self.is_error = true;
                                continue;
                            }

                            match self.coordinator.set_pds_host(self.current_input.clone()) {
                                Ok(_) => {
                                    self.add_output(format!(
                                        "Setting PDS host to: {}",
                                        self.current_input
                                    ));
                                    match self.coordinator.proceed().await {
                                        Ok(_) => {
                                            self.add_output(
                                                "PDS host configuration completed successfully."
                                                    .into(),
                                            );
                                            self.current_input.clear();
                                            self.is_error = false;
                                            self.status_message =
                                                self.coordinator.step_description().into();
                                        }
                                        Err(e) => {
                                            self.status_message = format!("Error: {}", e);
                                            self.add_output(format!(
                                                "PDS configuration failed: {}",
                                                e
                                            ));
                                            self.is_error = true;
                                        }
                                    }
                                }
                                Err(e) => {
                                    self.status_message = format!("Error: {}", e);
                                    self.is_error = true;
                                }
                            }
                        }

                        SetupStep::Keys => {
                            self.add_output("Generating cryptographic keypair...".into());
                            match self.coordinator.proceed().await {
                                Ok(_) => {
                                    self.add_output("Keypair generated successfully.".into());
                                    self.status_message =
                                        self.coordinator.step_description().into();
                                }
                                Err(e) => {
                                    self.status_message = format!("Error: {}", e);
                                    self.add_output(format!("Key generation failed: {}", e));
                                    self.is_error = true;
                                }
                            }
                        }

                        SetupStep::DidDocument => {
                            self.add_output("Creating DID document...".into());
                            match self.coordinator.proceed().await {
                                Ok(_) => {
                                    self.add_output("DID document created successfully.".into());
                                    self.status_message =
                                        self.coordinator.step_description().into();
                                }
                                Err(e) => {
                                    self.status_message = format!("Error: {}", e);
                                    self.add_output(format!("DID document creation failed: {}", e));
                                    self.is_error = true;
                                }
                            }
                        }

                        SetupStep::ServiceAuth => {
                            self.add_output("Generating service authentication...".into());
                            match self.coordinator.proceed().await {
                                Ok(_) => {
                                    self.add_output(
                                        "Service authentication generated successfully.".into(),
                                    );
                                    self.status_message =
                                        self.coordinator.step_description().into();
                                    self.input_prompt = self.coordinator.step_help().into();
                                }
                                Err(e) => {
                                    self.status_message = format!("Error: {}", e);
                                    self.add_output(format!(
                                        "Service auth generation failed: {}",
                                        e
                                    ));
                                    self.is_error = true;
                                }
                            }
                        }

                        SetupStep::Account => {
                            if self.account_field.is_none() {
                                self.start_account_setup();
                                continue;
                            }

                            if self.current_input.is_empty()
                                && !matches!(self.account_field, Some(AccountField::Email))
                            {
                                self.status_message = "Input cannot be empty".into();
                                self.is_error = true;
                                continue;
                            }

                            match self.handle_account_input()? {
                                true => {
                                    self.add_output("Configuring account...".into());
                                    match self.coordinator.proceed().await {
                                        Ok(_) => {
                                            self.account_field = None;
                                            self.add_output(
                                                "Account setup completed successfully.".into(),
                                            );
                                            self.add_output(
                                                "Verifying DID document configuration...".into(),
                                            );

                                            // After account setup succeeds, verify the configuration
                                            if let Some(domain) = self.coordinator.domain() {
                                                match self
                                                    .coordinator
                                                    .atp_client
                                                    .resolve_identifier(domain)
                                                    .await
                                                {
                                                    Ok(doc) => {
                                                        self.add_output(format!("Successfully verified DID document at {}", doc.id));
                                                        self.add_output("Your DID Web configuration is complete and working correctly.".into());
                                                        self.status_message = self
                                                            .coordinator
                                                            .step_description()
                                                            .into();
                                                        self.is_error = false;
                                                    }
                                                    Err(e) => {
                                                        self.add_output(format!("Warning: Could not verify DID document: {}", e));
                                                        self.add_output("Setup is complete but your web server may need additional configuration.".into());
                                                        self.status_message =
                                                            "Setup completed with warnings".into();
                                                        self.is_error = true;
                                                    }
                                                }
                                            }

                                            self.input_prompt.clear();
                                            self.current_input.clear();
                                        }
                                        Err(e) => {
                                            self.status_message = format!("Error: {}", e);
                                            self.add_output(format!("Account setup failed: {}", e));
                                            self.is_error = true;
                                        }
                                    }
                                }
                                false => {
                                    // Update the input prompt based on the next account field
                                    self.input_prompt = match self.account_field {
                                        Some(AccountField::Handle) => "Enter your password".into(),
                                        Some(AccountField::Password) => {
                                            "Enter your email (optional, press Enter to skip)"
                                                .into()
                                        }
                                        Some(AccountField::Email) => {
                                            "Enter your invite code".into()
                                        }
                                        Some(AccountField::InviteCode) => String::new(),
                                        None => String::new(),
                                    };
                                    self.current_input.clear();
                                }
                            }
                        }

                        SetupStep::Complete => {
                            self.status_message = "Setup completed successfully!".into();
                            self.add_output(
                                "All setup steps completed. Your did:web is ready :)".into(),
                            );
                            return Ok(());
                        }

                        _ => {
                            if !self.coordinator.can_proceed() {
                                self.status_message = "Required information is missing".into();
                                self.is_error = true;
                            }
                        }
                    },
                    KeyCode::Char(c) => {
                        self.current_input.push(c);
                    }
                    KeyCode::Backspace => {
                        self.current_input.pop();
                    }
                    KeyCode::Esc => {
                        self.add_output("Setup cancelled by user.".into());
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    fn draw(&mut self) -> io::Result<()> {
        self.terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(7), // Logo
                    Constraint::Length(3), // Status
                    Constraint::Length(3), // Input
                    Constraint::Length(3), // Step Help
                    Constraint::Min(5),    // Output Area
                    Constraint::Length(3), // Controls
                ])
                .split(f.area());

            // Logo
            let logo = Paragraph::new(Text::from(LOGO)).style(Style::default().fg(Color::Cyan));
            f.render_widget(logo, chunks[0]);

            // Status Message
            let status_style = if self.is_error {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };
            let status = Paragraph::new(Text::from(self.status_message.clone()))
                .style(status_style)
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(status, chunks[1]);

            // Input Field
            if !matches!(
                self.coordinator.current_step(),
                SetupStep::Keys
                    | SetupStep::DidDocument
                    | SetupStep::ServiceAuth
                    | SetupStep::Complete
            ) {
                let input = Paragraph::new(Text::from(Line::from(vec![
                    Span::raw(&self.input_prompt),
                    Span::raw(" "),
                    Span::styled(&self.current_input, Style::default().fg(Color::Yellow)),
                ])))
                .block(Block::default().borders(Borders::ALL));
                f.render_widget(input, chunks[2]);
            }

            // Step-specific help text
            let help_text = Paragraph::new(Text::from(self.coordinator.step_help()))
                .style(Style::default().fg(Color::Magenta))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(help_text, chunks[3]);

            // Output Area
            let output_text = if self.output_buffer.len() > 10 {
                Text::from(
                    self.output_buffer
                        .iter()
                        .skip(self.output_buffer.len() - 10)
                        .map(|s| Line::from(s.clone()))
                        .collect::<Vec<Line>>(),
                )
            } else {
                Text::from(
                    self.output_buffer
                        .iter()
                        .map(|s| Line::from(s.clone()))
                        .collect::<Vec<Line>>(),
                )
            };

            let output = Paragraph::new(output_text)
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL).title("Output"))
                .wrap(Wrap { trim: true })
                .scroll((0, 0));
            f.render_widget(output, chunks[4]);

            // Controls
            let controls = Paragraph::new(Text::from(vec![Line::from(vec![
                Span::styled("ENTER", Style::default().fg(Color::Blue)),
                Span::raw(" Continue  |  "),
                Span::styled("ESC", Style::default().fg(Color::Blue)),
                Span::raw(" Exit"),
            ])]))
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(controls, chunks[5]);
        })?;
        Ok(())
    }
}
