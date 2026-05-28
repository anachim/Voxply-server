use std::sync::Arc;

use axum::routing::{any, delete, get, patch, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::FarmState;

pub fn create_router(state: Arc<FarmState>) -> Router {
    Router::new()
        // Public probe endpoint — the hub fetches this on startup to cache the pubkey.
        .route("/farm/info", get(routes::health::farm_info))
        // Auth endpoints — same wire shape as the hub's existing auth routes.
        .route("/auth/challenge", post(routes::auth::challenge))
        .route("/auth/verify", post(routes::auth::verify))
        .route("/auth/renew", post(routes::auth::renew))
        // Belt-and-braces revocation check for hubs.
        .route("/farm/auth/revoke-check", post(routes::revoke::revoke_check))
        // Hub management routes.
        .route(
            "/farm/hubs",
            get(routes::hubs::list_hubs).post(routes::hubs::create_hub),
        )
        .route("/farm/hubs/{hub_id}", get(routes::hubs::get_hub))
        .route(
            "/farm/hubs/{hub_id}/suspend",
            patch(routes::hubs::suspend_hub),
        )
        .route("/farm/hubs/{hub_id}", delete(routes::hubs::delete_hub))
        // Phase 3 — farm settings (admin).
        .route(
            "/farm/settings",
            get(routes::admin::get_settings).patch(routes::admin::patch_settings),
        )
        // Phase 3 — per-user quota (authenticated).
        .route("/farm/me/hub-quota", get(routes::admin::me_hub_quota))
        // Phase 3 — farm user index and session revocation (admin).
        .route("/farm/users", get(routes::admin::list_users))
        .route(
            "/farm/users/{pubkey}/revoke-sessions",
            post(routes::admin::revoke_user_sessions),
        )
        // Phase 3 — public discovery probe (unauthenticated).
        .route("/farm/public-info", get(routes::admin::public_info))
        // Proxy catch-all — must be last (fallback for all /hub/<id>/... requests).
        .route(
            "/hub/{hub_id}/{*path}",
            any(crate::proxy::proxy_handler),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
