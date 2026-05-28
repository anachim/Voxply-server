use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::SeedState;

pub fn create_router(state: Arc<SeedState>) -> Router {
    Router::new()
        // Info endpoint — lets operators verify what they are running.
        .route("/info", get(routes::health::info))
        // Farm registration / deregistration — unauthenticated, ownership proved by signature.
        .route("/farms/register", post(routes::farms::register))
        .route("/farms/register", delete(routes::farms::deregister))
        // Public farm catalog with optional filters.
        .route("/farms", get(routes::farms::list_farms))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
