//! Postgres connection pool and the forward-only migration runner.
//!
//! The migrations are the same files the TypeScript runner applied, recorded
//! under the same names in `schema_migrations`, so a database either runtime
//! brought up is current for the other. Each runs inside a transaction on
//! every boot, so one that fails takes the service down with it: a migration
//! adding a constraint must resolve violating rows first (see 017).

use std::str::FromStr;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

/// Every migration, in order, under the name `schema_migrations` records.
pub const MIGRATIONS: &[(&str, &str)] = &[
    ("schema.sql", include_str!("../db/schema.sql")),
    ("migrations/001_portal.sql", include_str!("../db/migrations/001_portal.sql")),
    ("migrations/002_reactions.sql", include_str!("../db/migrations/002_reactions.sql")),
    ("migrations/003_shared_puppet_secret.sql", include_str!("../db/migrations/003_shared_puppet_secret.sql")),
    ("migrations/004_channel_names.sql", include_str!("../db/migrations/004_channel_names.sql")),
    ("migrations/005_guild_name.sql", include_str!("../db/migrations/005_guild_name.sql")),
    ("migrations/006_imports.sql", include_str!("../db/migrations/006_imports.sql")),
    ("migrations/007_import_owner_sign.sql", include_str!("../db/migrations/007_import_owner_sign.sql")),
    ("migrations/008_history_claims.sql", include_str!("../db/migrations/008_history_claims.sql")),
    ("migrations/009_claims_bot_command.sql", include_str!("../db/migrations/009_claims_bot_command.sql")),
    ("migrations/010_claim_codes.sql", include_str!("../db/migrations/010_claim_codes.sql")),
    ("migrations/011_bridge_announced.sql", include_str!("../db/migrations/011_bridge_announced.sql")),
    ("migrations/012_bridge_perm_alerted.sql", include_str!("../db/migrations/012_bridge_perm_alerted.sql")),
    ("migrations/013_secrets_at_rest.sql", include_str!("../db/migrations/013_secrets_at_rest.sql")),
    ("migrations/014_session_lookup_indexes.sql", include_str!("../db/migrations/014_session_lookup_indexes.sql")),
    ("migrations/015_retire_claims.sql", include_str!("../db/migrations/015_retire_claims.sql")),
    ("migrations/016_popup_handoff_approval.sql", include_str!("../db/migrations/016_popup_handoff_approval.sql")),
    ("migrations/017_one_bridge_per_discord_channel.sql", include_str!("../db/migrations/017_one_bridge_per_discord_channel.sql")),
    ("migrations/018_import_history_progress.sql", include_str!("../db/migrations/018_import_history_progress.sql")),
];

pub fn connect(database_url: &str, max_size: usize) -> anyhow::Result<Pool> {
    let config = tokio_postgres::Config::from_str(database_url)?;
    let manager = Manager::from_config(config, NoTls, ManagerConfig { recycling_method: RecyclingMethod::Fast });
    Ok(Pool::builder(manager).max_size(max_size).build()?)
}

/// Key of the advisory lock that serializes [`migrate`] across processes.
const MIGRATE_LOCK: i64 = 0x6172_6d61_6461_6d67; // "armadamg"

/// Apply every migration not yet recorded; returns the names applied.
///
/// Holds an advisory lock for the duration: two migrators (a portal and a
/// load probe, or parallel test binaries) each saw the same migration as
/// pending, and the second failed on the `schema_migrations` key, or on DDL
/// the first had already run. Callers wait instead.
pub async fn migrate(pool: &Pool) -> anyhow::Result<Vec<String>> {
    let mut db = pool.get().await?;
    db.execute("SELECT pg_advisory_lock($1)", &[&MIGRATE_LOCK]).await?;
    let result = migrate_locked(&mut db).await;
    // The lock belongs to this session, and the connection goes back to the
    // pool: release it here, on success or failure. A failed migration's
    // transaction was rolled back when it dropped.
    db.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATE_LOCK]).await?;
    result
}

async fn migrate_locked(db: &mut deadpool_postgres::Object) -> anyhow::Result<Vec<String>> {
    db.batch_execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
        .await?;
    let mut applied = Vec::new();
    for (name, body) in MIGRATIONS {
        if db.query_opt("SELECT 1 FROM schema_migrations WHERE name = $1", &[name]).await?.is_some() {
            continue;
        }
        let tx = db.transaction().await?;
        tx.batch_execute(body).await.map_err(|e| anyhow::anyhow!("migration {name}: {e}"))?;
        tx.execute("INSERT INTO schema_migrations (name) VALUES ($1)", &[name]).await?;
        tx.commit().await?;
        applied.push((*name).to_owned());
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    /// A migration file added to the directory but not to the list would never
    /// run; this is the reminder.
    #[test]
    fn every_migration_file_is_listed() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/db/migrations");
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|f| f.ends_with(".sql"))
            .map(|f| format!("migrations/{f}"))
            .collect();
        files.sort();
        let listed: Vec<&str> = MIGRATIONS.iter().skip(1).map(|(n, _)| *n).collect();
        assert_eq!(listed, files);
    }
}
