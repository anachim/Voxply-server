use sqlx::SqlitePool;

/// Shared state for the discovery seed service.
pub struct SeedState {
    /// SQLite connection pool for seed.db.
    pub db: SqlitePool,
    /// Shared HTTP client for outbound farm verification calls.
    pub http_client: reqwest::Client,
}

impl SeedState {
    pub fn new(db: SqlitePool) -> Self {
        Self {
            db,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build reqwest client"),
        }
    }
}
