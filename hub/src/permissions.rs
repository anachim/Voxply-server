use std::collections::HashSet;

use axum::http::StatusCode;
use sqlx::SqlitePool;

pub const SEND_MESSAGES: &str = "send_messages";
pub const READ_MESSAGES: &str = "read_messages";
pub const MANAGE_CHANNELS: &str = "manage_channels";
pub const MANAGE_MESSAGES: &str = "manage_messages";
pub const MANAGE_ROLES: &str = "manage_roles";
pub const KICK_MEMBERS: &str = "kick_members";
pub const BAN_MEMBERS: &str = "ban_members";
pub const MUTE_MEMBERS: &str = "mute_members";
pub const TIMEOUT_MEMBERS: &str = "timeout_members";
pub const MANAGE_GAMES: &str = "manage_games";
pub const MANAGE_HUB_ICONS: &str = "manage_hub_icons";
pub const MANAGE_CHANNEL_ICONS: &str = "manage_channel_icons";
pub const ADMIN: &str = "admin";
pub const CREATE_POSTS: &str = "create_posts";
pub const MANAGE_POSTS: &str = "manage_posts";
pub const START_GAME: &str = "start_game";

#[derive(sqlx::FromRow)]
pub struct RoleRow {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub created_at: i64,
}

pub struct UserPermissions {
    pub roles: Vec<RoleRow>,
    pub effective: HashSet<String>,
    pub max_priority: i64,
}

impl UserPermissions {
    pub fn has(&self, permission: &str) -> bool {
        self.effective.contains(ADMIN) || self.effective.contains(permission)
    }

    pub fn require(&self, permission: &str) -> Result<(), (StatusCode, String)> {
        if self.has(permission) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!("Missing permission: {permission}"),
            ))
        }
    }
}

pub async fn user_permissions(
    db: &SqlitePool,
    public_key: &str,
) -> Result<UserPermissions, (StatusCode, String)> {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.priority, r.created_at
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = ?",
    )
    .bind(public_key)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let role_ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    let effective = fetch_permissions(db, &role_ids).await?;
    let max_priority = roles.iter().map(|r| r.priority).max().unwrap_or(0);

    Ok(UserPermissions {
        roles,
        effective,
        max_priority,
    })
}

async fn fetch_permissions(
    db: &SqlitePool,
    role_ids: &[&str],
) -> Result<HashSet<String>, (StatusCode, String)> {
    if role_ids.is_empty() {
        return Ok(HashSet::new());
    }

    // Build a query with placeholders for each role_id
    let placeholders: Vec<&str> = role_ids.iter().map(|_| "?").collect();
    let query = format!(
        "SELECT DISTINCT permission FROM role_permissions WHERE role_id IN ({})",
        placeholders.join(",")
    );

    let mut q = sqlx::query_scalar::<_, String>(&query);
    for id in role_ids {
        q = q.bind(id);
    }

    let permissions: Vec<String> = q
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(permissions.into_iter().collect())
}
