//! Portal server: JSON API, static SPA and every hosted bridge, one process.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use portal::auth::Sessions;
use portal::env::PortalEnv;
use portal::importer::{Importer, ImporterIo};
use portal::manager::BridgeManager;
use portal::server::{AppState, app};

/// Resident memory in MB, from /proc (Linux only; 0 elsewhere).
fn rss_mb() -> u64 {
    let page = 4096;
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * page / (1 << 20))
}

fn memory_line(manager: &BridgeManager, importer: &Importer) -> String {
    format!(
        "memory rss={}MB bridges={} imports={} communities={}",
        rss_mb(),
        manager.live_count(),
        importer.active_count(),
        manager.communities()
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge::tls::install();
    let fd_limit = bridge::fdlimit::raise();
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tokio_postgres=warn".into()))
        .init();
    match fd_limit {
        Ok(n) => tracing::info!(open_files = n, "file descriptor limit"),
        Err(error) => tracing::warn!(%error, "could not raise the file descriptor limit"),
    }
    let env = PortalEnv::load()?;
    let pool = bridge::db::connect(&env.database_url, 16)?;
    let applied = bridge::db::migrate(&pool).await.context("migrations")?;
    if !applied.is_empty() {
        tracing::info!("migrations applied: {}", applied.join(", "));
    }
    let sessions = Arc::new(Sessions::new(pool.clone(), env.seal_key_hex.clone(), env.base_url.starts_with("https:")));
    let manager = BridgeManager::new(pool.clone(), env.clone());
    let io = ImporterIo::production(env.discord_bot_token.clone(), &env.blossom_server)?;
    let importer = Importer::new(pool.clone(), env.clone(), manager.clone(), io);

    // Deliberately NOT awaited. `init` resumes every active bridge, and each
    // resume folds its community over relays — so a single unreachable relay
    // once left the process with the gateway connected and the HTTP port never
    // bound. The API comes up regardless; bridges go live as they finish.
    {
        let (manager, importer) = (manager.clone(), importer.clone());
        tokio::spawn(async move {
            if let Err(error) = manager.init().await {
                tracing::error!(error = %format!("{error:#}"), "bridge resume failed");
            }
            // After the bridges, whatever became of them: a resumed import's
            // wiring and history stages route through the live bridges.
            if let Err(error) = importer.resume_interrupted().await {
                tracing::error!(error = %format!("{error:#}"), "import resume failed");
            }
        });
    }

    // One line every ten minutes on where the memory is. The 2026-09-23 OOM
    // left nothing to tell a leak from a baseline; with this, the journal
    // before any kill says what grew and alongside what. SIGUSR2 logs it now.
    {
        let (manager, importer) = (manager.clone(), importer.clone());
        tokio::spawn(async move {
            let mut usr2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2()).expect("SIGUSR2 handler");
            let mut tick = tokio::time::interval(Duration::from_secs(10 * 60));
            loop {
                tokio::select! { _ = tick.tick() => {}, _ = usr2.recv() => {} }
                tracing::info!("{}", memory_line(&manager, &importer));
            }
        });
    }

    // Expired sessions were excluded from every lookup but never deleted, and
    // anyone can create a pre-auth row by hitting /api/auth/discord — so the
    // table only grew. Sweep at boot, then hourly.
    {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
            loop {
                tick.tick().await;
                if let Err(error) = sessions.sweep().await {
                    tracing::warn!(error = %format!("{error:#}"), "session sweep failed");
                }
            }
        });
    }

    let web_dir = std::env::var("PORTAL_WEB_DIR").unwrap_or_else(|_| "web/dist".into());
    let addr = format!("{}:{}", env.host, env.port);
    let base_url = env.base_url.clone();
    let state = AppState { pool, env: Arc::new(env), sessions, manager, importer, rest: portal::discord_rest::DiscordRest::new() };
    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("binding {addr}"))?;
    tracing::info!("listening on {base_url} (bound to {addr})");
    axum::serve(listener, app(state, &web_dir)?).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    tracing::info!("shutting down");
}
