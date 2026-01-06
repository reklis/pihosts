use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pihosts")]
#[command(about = "Manage Pi-hole DNS hosts via the v6 API")]
struct Cli {
    /// Pi-hole server URL (e.g., https://pihole.example.com)
    #[arg(short, long, env = "PIHOLE_URL")]
    server: Option<String>,

    /// Pi-hole admin password
    #[arg(short, long, env = "PIHOLE_PASSWORD")]
    password: Option<String>,

    /// Enable colored output
    #[arg(short, long)]
    color: bool,

    /// Tabular output
    #[arg(short, long)]
    table: bool,

    /// JSON output
    #[arg(short, long)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Save server URL and password to config file
    Login {
        /// Pi-hole server URL
        server: String,
        /// Pi-hole admin password
        password: String,
    },
    /// List all DNS host entries
    List,
    /// Add a DNS host entry
    Add {
        /// IP address
        ip: String,
        /// Hostname
        hostname: String,
    },
    /// Remove a DNS host entry
    Remove {
        /// IP address
        ip: String,
        /// Hostname
        hostname: String,
    },
}

#[derive(Serialize, Deserialize, Default)]
struct ConfigFile {
    server: Option<String>,
    password: Option<String>,
}

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir()
        .context("Could not determine config directory")
        .map(|p| p.join("pihosts"))
}

impl ConfigFile {
    fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("config.json"))
    }

    fn load() -> Result<Self> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }
        let contents = serde_json::to_string_pretty(self)?;
        fs::write(&path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        Ok(())
    }
}

struct SessionCache;

impl SessionCache {
    fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("sid"))
    }

    fn load() -> Result<Option<String>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let sid = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read session file: {}", path.display()))?;
        let sid = sid.trim();
        if sid.is_empty() {
            Ok(None)
        } else {
            Ok(Some(sid.to_string()))
        }
    }

    fn save(sid: &str) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }
        fs::write(&path, sid)
            .with_context(|| format!("Failed to write session file: {}", path.display()))?;
        Ok(())
    }

    fn clear() -> Result<()> {
        let path = Self::path()?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove session file: {}", path.display()))?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AuthRequest {
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    session: Option<Session>,
    error: Option<AuthError>,
}

#[derive(Deserialize)]
struct AuthError {
    key: Option<String>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct Session {
    valid: bool,
    sid: String,
}

#[derive(Deserialize)]
struct HostsResponse {
    config: Config,
}

#[derive(Deserialize)]
struct Config {
    dns: Dns,
}

#[derive(Deserialize)]
struct Dns {
    hosts: Vec<String>,
}

struct PiholeClient {
    client: Client,
    base_url: String,
    password: String,
    sid: String,
}

impl PiholeClient {
    async fn new(base_url: &str, password: &str) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let base_url = base_url.trim_end_matches('/').to_string();

        // Try to use cached session first
        if let Ok(Some(cached_sid)) = SessionCache::load() {
            let mut pihole = Self {
                client,
                base_url,
                password: password.to_string(),
                sid: cached_sid,
            };

            // Test if session is still valid
            if pihole.test_session().await {
                return Ok(pihole);
            }

            // Session expired, need to re-authenticate
            pihole.authenticate().await?;
            return Ok(pihole);
        }

        // No cached session, authenticate
        let mut pihole = Self {
            client,
            base_url,
            password: password.to_string(),
            sid: String::new(),
        };
        pihole.authenticate().await?;
        Ok(pihole)
    }

    async fn authenticate(&mut self) -> Result<()> {
        let auth_url = format!("{}/api/auth", self.base_url);
        let auth_req = AuthRequest {
            password: self.password.clone(),
        };

        let resp = self
            .client
            .post(&auth_url)
            .json(&auth_req)
            .send()
            .await
            .context("Failed to connect to Pi-hole")?;

        let status = resp.status();
        let body = resp.text().await.context("Failed to read auth response")?;

        let auth: AuthResponse = serde_json::from_str(&body)
            .with_context(|| format!("Failed to parse auth response: {}", body))?;

        if let Some(err) = auth.error {
            let msg = err.message.unwrap_or_else(|| "Unknown error".to_string());
            anyhow::bail!("Authentication failed: {}", msg);
        }

        let session = auth.session.context("Authentication failed: no session returned")?;

        if !session.valid {
            anyhow::bail!("Authentication failed: invalid password");
        }

        if !status.is_success() {
            anyhow::bail!("Authentication failed: HTTP {}", status);
        }

        self.sid = session.sid.clone();
        SessionCache::save(&session.sid)?;
        Ok(())
    }

    async fn test_session(&self) -> bool {
        let url = format!("{}/api/auth", self.base_url);
        let resp = self
            .client
            .get(&url)
            .header("Sid", &self.sid)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                // Check if session is actually valid in response
                if let Ok(body) = r.text().await {
                    if let Ok(auth) = serde_json::from_str::<AuthResponse>(&body) {
                        return auth.session.map(|s| s.valid).unwrap_or(false);
                    }
                }
                false
            }
            _ => false,
        }
    }

    async fn list_hosts(&self) -> Result<Vec<String>> {
        let url = format!("{}/api/config/dns/hosts", self.base_url);

        let resp = self
            .client
            .get(&url)
            .header("Sid", &self.sid)
            .send()
            .await
            .context("Failed to fetch hosts")?;

        let hosts_resp: HostsResponse = resp
            .json()
            .await
            .context("Failed to parse hosts response")?;

        Ok(hosts_resp.config.dns.hosts)
    }

    async fn add_host(&self, ip: &str, hostname: &str) -> Result<()> {
        let entry = format!("{} {}", ip, hostname);
        let encoded = urlencoding::encode(&entry);
        let url = format!("{}/api/config/dns/hosts/{}", self.base_url, encoded);

        let resp = self
            .client
            .put(&url)
            .header("Sid", &self.sid)
            .send()
            .await
            .context("Failed to add host")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Failed to add host: {} - {}", status, body);
        }

        Ok(())
    }

    async fn remove_host(&self, ip: &str, hostname: &str) -> Result<()> {
        let entry = format!("{} {}", ip, hostname);
        let encoded = urlencoding::encode(&entry);
        let url = format!("{}/api/config/dns/hosts/{}", self.base_url, encoded);

        let resp = self
            .client
            .delete(&url)
            .header("Sid", &self.sid)
            .send()
            .await
            .context("Failed to remove host")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Failed to remove host: {} - {}", status, body);
        }

        Ok(())
    }
}

fn format_hostname_colored(hostname: &str) -> String {
    // Split hostname into subdomain and root domain (last two parts)
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() >= 2 {
        let root_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        if parts.len() > 2 {
            let subdomain = parts[..parts.len() - 2].join(".");
            format!("{}.{}", subdomain.cyan(), root_domain.white())
        } else {
            root_domain.white().to_string()
        }
    } else {
        hostname.cyan().to_string()
    }
}

fn resolve_credentials(cli: &Cli) -> Result<(String, String)> {
    let config = ConfigFile::load()?;

    let server = cli
        .server
        .clone()
        .or(config.server)
        .context("Server URL not provided. Use --server, PIHOLE_URL env var, or run 'pihosts login' first")?;

    let password = cli
        .password
        .clone()
        .or(config.password)
        .context("Password not provided. Use --password, PIHOLE_PASSWORD env var, or run 'pihosts login' first")?;

    Ok((server, password))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Login { server, password } => {
            // Clear any existing session first
            SessionCache::clear()?;

            // Verify credentials work before saving (this also caches the session)
            print!("Verifying credentials... ");
            PiholeClient::new(server, password).await?;
            println!("OK");

            let config = ConfigFile {
                server: Some(server.clone()),
                password: Some(password.clone()),
            };
            config.save()?;
            println!("Saved config to {}", ConfigFile::path()?.display());
            println!("Saved session to {}", SessionCache::path()?.display());
        }
        Commands::List => {
            let (server, password) = resolve_credentials(&cli)?;
            let client = PiholeClient::new(&server, &password).await?;
            let hosts = client.list_hosts().await?;

            if cli.json {
                let entries: Vec<_> = hosts
                    .iter()
                    .filter_map(|h| {
                        h.split_once(' ')
                            .map(|(ip, hostname)| serde_json::json!({"ip": ip, "hostname": hostname}))
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if cli.table {
                let ip_width = hosts
                    .iter()
                    .filter_map(|h| h.split_once(' ').map(|(ip, _)| ip.len()))
                    .max()
                    .unwrap_or(15);
                if cli.color {
                    println!("{:<ip_width$}  {}", "IP".purple().bold(), "HOSTNAME".cyan().bold());
                    println!("{}", "-".repeat(ip_width + 2 + 40));
                    for host in hosts {
                        if let Some((ip, hostname)) = host.split_once(' ') {
                            println!("{:<ip_width$}  {}", ip.purple(), format_hostname_colored(hostname));
                        }
                    }
                } else {
                    println!("{:<ip_width$}  HOSTNAME", "IP");
                    println!("{}", "-".repeat(ip_width + 2 + 40));
                    for host in hosts {
                        if let Some((ip, hostname)) = host.split_once(' ') {
                            println!("{:<ip_width$}  {}", ip, hostname);
                        }
                    }
                }
            } else {
                for host in hosts {
                    if cli.color {
                        if let Some((ip, hostname)) = host.split_once(' ') {
                            println!("{} {}", ip.purple(), format_hostname_colored(hostname));
                        } else {
                            println!("{}", host);
                        }
                    } else {
                        println!("{}", host);
                    }
                }
            }
        }
        Commands::Add { ip, hostname } => {
            let (server, password) = resolve_credentials(&cli)?;
            let client = PiholeClient::new(&server, &password).await?;
            client.add_host(ip, hostname).await?;
            if cli.color {
                println!("{} {} {}", "Added:".green(), ip.purple(), format_hostname_colored(hostname));
            } else {
                println!("Added: {} {}", ip, hostname);
            }
        }
        Commands::Remove { ip, hostname } => {
            let (server, password) = resolve_credentials(&cli)?;
            let client = PiholeClient::new(&server, &password).await?;
            client.remove_host(ip, hostname).await?;
            if cli.color {
                println!("{} {} {}", "Removed:".red(), ip.purple(), format_hostname_colored(hostname));
            } else {
                println!("Removed: {} {}", ip, hostname);
            }
        }
    }

    Ok(())
}
