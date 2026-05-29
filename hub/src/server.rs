use std::sync::Arc;

use axum::middleware::from_fn;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::federation;
use crate::rate_limit::{self, Config, RateLimiter};
use crate::routes;
use crate::state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let auth_limiter = RateLimiter::new(Config::AUTH);
    let write_limiter = RateLimiter::new(Config::WRITE);

    // Rate-limited auth sub-router (strict, because anyone can hit these).
    let auth_routes = Router::new()
        .route("/auth/challenge", post(auth::handlers::challenge))
        .route("/auth/verify", post(auth::handlers::verify))
        .route("/auth/renew", post(auth::handlers::renew))
        .layer(from_fn(move |req, next| {
            let l = auth_limiter.clone();
            async move { rate_limit::enforce(l, req, next).await }
        }));

    // Rate-limited write sub-router (channels, messages, DMs, etc.).
    let write_routes = Router::new()
        .route("/channels", post(routes::channels::create_channel))
        .route("/channels/{channel_id}/messages", post(routes::messages::send_message))
        .route("/conversations", post(routes::dms::create_conversation))
        .route(
            "/conversations/{conversation_id}/messages",
            post(routes::dms::send_dm),
        )
        .layer(from_fn(move |req, next| {
            let l = write_limiter.clone();
            async move { rate_limit::enforce(l, req, next).await }
        }));

    Router::new()
        .route("/health", get(routes::health::health))
        .route("/info", get(routes::health::info))
        .route("/hub", axum::routing::patch(routes::hub::update_hub))
        .route("/hub/members", get(routes::hub::list_members))
        .route("/hub/settings", get(routes::hub::get_hub_settings))
        .route("/hub/pending", get(routes::hub::list_pending))
        .route("/hub/pending/{target_key}/approve", post(routes::hub::approve_user))
        .route("/hub/icons", get(routes::hub_icons::list_icons).post(routes::hub_icons::create_icon))
        .route(
            "/hub/icons/{icon_id}",
            axum::routing::patch(routes::hub_icons::rename_icon)
                .delete(routes::hub_icons::delete_icon),
        )
        .route("/admin/settings/pow", get(routes::hub::get_pow_settings).patch(routes::hub::patch_pow_settings))
        .route("/admin/settings/channel-depth", get(routes::hub::get_channel_depth).patch(routes::hub::patch_channel_depth))
        .route("/admin/settings/tags", get(routes::tags::get_tags).patch(routes::tags::patch_tags))
        .route("/admin/directory-sign", post(routes::directory::sign_for_directory))
        .route("/profile/{pubkey}", get(routes::profile::get_profile).put(routes::profile::put_profile))
        .merge(auth_routes)
        .merge(write_routes)
        .route("/me", get(routes::me::me).patch(routes::me::update_me))
        .route("/channels", get(routes::channels::list_channels))
        .route(
            "/channels/{channel_id}",
            axum::routing::patch(routes::channels::update_channel)
                .delete(routes::channels::delete_channel),
        )
        .route("/channels/reorder", post(routes::channels::reorder_channels))
        .route("/channels/{channel_id}/messages", get(routes::messages::get_messages))
        .route(
            "/channels/{channel_id}/messages/{message_id}",
            axum::routing::patch(routes::messages::edit_message)
                .delete(routes::messages::delete_message),
        )
        .route(
            "/channels/{channel_id}/messages/{message_id}/reactions",
            post(routes::messages::add_reaction),
        )
        .route(
            "/channels/{channel_id}/messages/{message_id}/reactions/{emoji}",
            axum::routing::delete(routes::messages::remove_reaction),
        )
        // ---- Admin bot management (internal service accounts) ----
        .route("/admin/bots", get(routes::bots::admin_list_bots).post(routes::bots::admin_create_bot))
        .route("/admin/bots/{pubkey}", get(routes::bots::admin_get_bot).delete(routes::bots::admin_delete_bot))
        .route("/admin/bots/{pubkey}/webhook", put(routes::bots::admin_set_webhook))
        .route("/admin/audit-log", get(routes::bots::admin_audit_log))
        // ---- Bot API (token auth, internal service accounts) ----
        .route("/bot/commands", put(routes::bots::bot_set_commands))
        .route("/bot/send", post(routes::bots::bot_send_message))
        .route("/bot/poll", get(routes::bots::bot_poll))
        .route("/bot/events", axum::routing::delete(routes::bots::bot_ack_events))
        // ---- External bot system ----
        // /bots/me, /bots/me/profile, /bots/me/commands, /bots/me/subscriptions
        // must be registered before /bots/{pubkey} so axum doesn't match "me"
        // as a path parameter.
        .route("/bots/me", get(routes::bots::ext_bot_me))
        .route("/bots/me/profile", put(routes::bots::ext_update_bot_profile))
        .route("/bots/me/commands", put(routes::bots::ext_update_bot_commands))
        .route("/bots/me/subscriptions", put(routes::bots::ext_update_bot_subscriptions))
        .route("/bots/accept-invite", post(routes::bots::ext_accept_invite))
        .route("/bots", get(routes::bots::ext_list_bots).post(routes::bots::ext_invite_bot))
        .route("/bots/{pubkey}", delete(routes::bots::ext_remove_bot))
        // ---- Incoming webhooks ----
        .route("/admin/webhooks", post(routes::webhooks::create_webhook))
        .route("/admin/webhooks/{id}", delete(routes::webhooks::delete_webhook))
        .route("/webhooks/{id}/{token}", post(routes::webhooks::post_webhook_message))
        .route("/users", get(routes::users::list_users))
        .route("/channels/{channel_id}/members", get(routes::users::channel_members))
        .route("/voice/populations", get(routes::channels::voice_populations))
        .route("/voice/active-users", get(routes::channels::voice_active_users))
        .route("/voice/participants", get(routes::channels::voice_channel_participants))
        .route("/ws", get(routes::ws::ws_handler))
        .route("/conversations", get(routes::dms::list_conversations))
        .route(
            "/conversations/{conversation_id}/messages",
            get(routes::dms::list_dm_messages),
        )
        .route("/federation/dm", post(routes::dms::receive_federated_dm))
        .route("/federation/badge-offer", post(federation::handlers::receive_badge_offer))
        .route("/friends", get(routes::friends::list_friends).post(routes::friends::send_friend_request))
        .route("/friends/pending", get(routes::friends::list_pending_requests))
        .route("/friends/{public_key}/accept", post(routes::friends::accept_friend_request))
        .route("/friends/{public_key}", axum::routing::delete(routes::friends::remove_friend))
        .route("/roles", get(routes::roles::list_roles).post(routes::roles::create_role))
        .route("/roles/{role_id}", axum::routing::patch(routes::roles::update_role).delete(routes::roles::delete_role))
        .route("/roles/{role_id}/members", get(routes::roles::list_role_members))
        .route("/users/{public_key}/roles", get(routes::roles::get_user_roles))
        .route("/users/{public_key}/roles/{role_id}", put(routes::roles::assign_role).delete(routes::roles::remove_role))
        .route("/invites", get(routes::invites::list_invites).post(routes::invites::create_invite))
        .route("/invites/{code}", axum::routing::delete(routes::invites::revoke_invite))
        .route("/moderation/bans", get(routes::moderation::list_bans).post(routes::moderation::ban_user))
        .route("/moderation/bans/{target_key}", axum::routing::delete(routes::moderation::unban_user))
        .route("/moderation/mutes", get(routes::moderation::list_mutes).post(routes::moderation::mute_user))
        .route("/moderation/mutes/{target_key}", axum::routing::delete(routes::moderation::unmute_user))
        .route("/moderation/timeout", post(routes::moderation::timeout_user))
        .route("/moderation/kick", post(routes::moderation::kick_user))
        .route("/moderation/channels/{channel_id}/bans", get(routes::moderation::list_channel_bans).post(routes::moderation::channel_ban))
        .route("/moderation/channels/{channel_id}/bans/{target_key}", axum::routing::delete(routes::moderation::channel_unban))
        .route("/moderation/voice-mutes", get(routes::moderation::list_voice_mutes).post(routes::moderation::voice_mute))
        .route("/moderation/voice-mutes/{target_key}", axum::routing::delete(routes::moderation::voice_unmute))
        .route("/channels/{channel_id}/talk-power", get(routes::moderation::get_talk_power).post(routes::moderation::set_talk_power))
        // ---- Channel-scoped moderation (pubkey field, task #6/#7/#8) ----
        .route("/channels/{channel_id}/bans", get(routes::moderation::list_channel_bans_v2).post(routes::moderation::channel_ban_v2))
        .route("/channels/{channel_id}/bans/{pubkey}", axum::routing::delete(routes::moderation::channel_unban_v2))
        .route("/channels/{channel_id}/voice-mutes", get(routes::moderation::list_channel_voice_mutes).post(routes::moderation::channel_voice_mute))
        .route("/channels/{channel_id}/voice-mutes/{pubkey}", axum::routing::delete(routes::moderation::channel_voice_unmute))
        .route("/channels/{channel_id}/raise-hand", post(routes::moderation::raise_hand))
        .route("/channels/{channel_id}/raise-hand/{pubkey}", axum::routing::delete(routes::moderation::lower_hand))
        .route("/channels/{channel_id}/raise-hands", get(routes::moderation::list_raise_hands))
        .route("/alliances", get(routes::alliances::list_alliances).post(routes::alliances::create_alliance))
        .route("/alliances/join", post(routes::alliances::join_alliance_local))
        .route("/alliances/pending-invites", get(routes::alliances::list_pending_invites))
        .route("/alliances/pending-invites/{invite_id}/accept", post(routes::alliances::accept_pending_invite))
        .route("/alliances/pending-invites/{invite_id}", axum::routing::delete(routes::alliances::decline_pending_invite))
        .route("/alliances/{alliance_id}", get(routes::alliances::get_alliance))
        .route("/alliances/{alliance_id}/invite", post(routes::alliances::create_invite))
        .route("/alliances/{alliance_id}/push-invite", post(routes::alliances::push_invite_handler))
        .route("/alliances/{alliance_id}/join", post(routes::alliances::join_alliance))
        .route("/alliances/{alliance_id}/leave", axum::routing::delete(routes::alliances::leave_alliance))
        .route("/alliances/{alliance_id}/channels", get(routes::alliances::list_shared_channels)
            .post(routes::alliances::share_channel))
        .route("/alliances/{alliance_id}/channels/{channel_id}", axum::routing::delete(routes::alliances::unshare_channel))
        .route("/alliances/{alliance_id}/channels/{channel_id}/messages", get(routes::alliances::get_alliance_channel_messages).post(routes::alliances::post_alliance_channel_message))
        .route("/federation/alliance-invite", post(routes::alliances::receive_federation_alliance_invite))
        .route(
            "/identity/{master}/designation",
            get(routes::identity::get_designation).post(routes::identity::put_designation),
        )
        .route(
            "/identity/{master}/devices",
            get(routes::identity::list_devices).post(routes::identity::post_device),
        )
        .route(
            "/identity/{master}/revocations",
            get(routes::identity::list_revocations).post(routes::identity::post_revocation),
        )
        .route(
            "/identity/{master}/prefs",
            get(routes::identity::get_prefs).put(routes::identity::put_prefs),
        )
        .route(
            "/identity/{pubkey}/dh-key",
            get(routes::dh_keys::get_dh_key).put(routes::dh_keys::put_dh_key),
        )
        .route("/identity/pairing/offer", post(routes::pairing::post_offer))
        .route("/identity/pairing/claim", post(routes::pairing::post_claim))
        .route("/identity/pairing/complete", post(routes::pairing::post_complete))
        .route("/identity/pairing/status/{token}", get(routes::pairing::get_status))
        // ---- Badge admin routes ----
        .route("/badges/pending", get(routes::badges::list_pending))
        .route("/badges/pending/{id}/accept", post(routes::badges::accept_pending))
        .route("/badges/pending/{id}/decline", post(routes::badges::decline_pending))
        .route("/badges", get(routes::badges::list_badges))
        .route("/badges/{id}", delete(routes::badges::delete_badge))
        .route("/admin/badges/issue", post(routes::badges::issue_badge))
        .route("/admin/badges/issued", get(routes::badges::list_issued))
        .route("/federation/peers", get(federation::handlers::list_peers))
        .route("/federation/peers", post(federation::handlers::add_peer))
        .route("/federation/peers/{peer_key}/channels", get(federation::handlers::peer_channels))
        .route("/federation/channels", get(federation::handlers::all_federated_channels))
        .route("/federation/channels/{fed_channel_id}/messages", get(federation::handlers::federated_messages)
            .post(federation::handlers::send_federated_message))
        // ---- Lobby ----
        .route("/lobby/status", get(routes::lobby::get_status))
        .route("/lobby/submit-pow", post(routes::lobby::submit_pow))
        .route("/lobby/welcome", get(routes::lobby::get_welcome))
        .route("/hub/settings/lobby", put(routes::lobby::update_lobby_settings))
        // ---- Bot Challenge ----
        .route("/challenge/new", get(routes::challenge::new_challenge))
        .route("/challenge/verify", post(routes::challenge::verify_challenge))
        .route("/hub/settings/challenge", put(routes::challenge::update_challenge_settings))
        // ---- Survey ----
        .route("/survey/current", get(routes::survey::get_current))
        .route("/survey/submit", post(routes::survey::submit_survey))
        .route("/admin/survey", get(routes::survey::admin_get_survey).put(routes::survey::admin_put_survey))
        .route("/admin/survey/responses", get(routes::survey::admin_list_responses))
        .route("/admin/survey/responses/{pubkey}", get(routes::survey::admin_get_response_for_pubkey))
        // ---- Forum ----
        // Search must be registered before /:post_id so axum doesn't match "search"
        // as a path parameter.
        .route(
            "/channels/{channel_id}/posts/search",
            get(routes::posts::search_posts),
        )
        .route(
            "/channels/{channel_id}/posts",
            get(routes::posts::list_posts).post(routes::posts::create_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}",
            get(routes::posts::get_post)
                .patch(routes::posts::edit_post)
                .delete(routes::posts::delete_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/replies",
            post(routes::posts::create_reply),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}",
            patch(routes::posts::edit_reply).delete(routes::posts::delete_reply),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/pin",
            post(routes::posts::pin_post).delete(routes::posts::unpin_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/lock",
            post(routes::posts::lock_post).delete(routes::posts::unlock_post),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
