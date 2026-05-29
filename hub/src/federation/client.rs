use anyhow::{Context, Result};

use crate::auth::models::{ChallengeResponse, VerifyResponse};
use crate::routes::alliance_models::{AllianceDetailResponse, SharedChannelResponse};
use crate::routes::chat_models::{ChannelResponse, MessageResponse};
use crate::routes::dm_models::FederatedDmRequest;
use crate::routes::health::InfoResponse;
use voxply_identity::Identity;

pub struct FederationClient {
    http: reqwest::Client,
}

impl FederationClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    pub async fn get_info(&self, base_url: &str) -> Result<InfoResponse> {
        self.http
            .get(format!("{base_url}/info"))
            .send()
            .await
            .context("Failed to connect to peer")?
            .json()
            .await
            .context("Invalid info response")
    }

    pub async fn authenticate(&self, base_url: &str, identity: &Identity) -> Result<String> {
        let pub_key = identity.public_key_hex();

        let challenge: ChallengeResponse = self
            .http
            .post(format!("{base_url}/auth/challenge"))
            .json(&serde_json::json!({ "public_key": pub_key }))
            .send()
            .await
            .context("Failed to request challenge from peer")?
            .json()
            .await
            .context("Invalid challenge response")?;

        let challenge_bytes = hex::decode(&challenge.challenge)
            .context("Invalid challenge hex from peer")?;
        let signature = identity.sign(&challenge_bytes);

        let verify: VerifyResponse = self
            .http
            .post(format!("{base_url}/auth/verify"))
            .json(&serde_json::json!({
                "public_key": pub_key,
                "challenge": challenge.challenge,
                "signature": hex::encode(signature.to_bytes()),
            }))
            .send()
            .await
            .context("Failed to verify with peer")?
            .json()
            .await
            .context("Invalid verify response")?;

        Ok(verify.token)
    }

    pub async fn get_channels(&self, base_url: &str, token: &str) -> Result<Vec<ChannelResponse>> {
        self.http
            .get(format!("{base_url}/channels"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch channels from peer")?
            .json()
            .await
            .context("Invalid channels response")
    }

    pub async fn send_message(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
        content: &str,
    ) -> Result<MessageResponse> {
        self.http
            .post(format!("{base_url}/channels/{channel_id}/messages"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "content": content }))
            .send()
            .await
            .context("Failed to send message to peer")?
            .json()
            .await
            .context("Invalid message response")
    }

    pub async fn get_messages(
        &self,
        base_url: &str,
        token: &str,
        channel_id: &str,
    ) -> Result<Vec<MessageResponse>> {
        self.http
            .get(format!("{base_url}/channels/{channel_id}/messages"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch messages from peer")?
            .json()
            .await
            .context("Invalid messages response")
    }

    pub async fn post_alliance_join(
        &self,
        base_url: &str,
        token: &str,
        alliance_id: &str,
        invite_token: &str,
        own_hub_url: &str,
    ) -> Result<reqwest::Response> {
        self.http
            .post(format!("{base_url}/alliances/{alliance_id}/join"))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "invite_token": invite_token,
                "hub_url": own_hub_url,
            }))
            .send()
            .await
            .context("Failed to call alliance join endpoint")
    }

    pub async fn get_alliance_detail(
        &self,
        base_url: &str,
        token: &str,
        alliance_id: &str,
    ) -> Result<AllianceDetailResponse> {
        self.http
            .get(format!("{base_url}/alliances/{alliance_id}"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch alliance detail")?
            .json()
            .await
            .context("Invalid alliance detail response")
    }

    pub async fn get_alliance_shared_channels(
        &self,
        base_url: &str,
        token: &str,
        alliance_id: &str,
    ) -> Result<Vec<SharedChannelResponse>> {
        self.http
            .get(format!("{base_url}/alliances/{alliance_id}/channels"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to fetch alliance channels from peer")?
            .json()
            .await
            .context("Invalid alliance channels response")
    }

    pub async fn post_federated_dm(
        &self,
        base_url: &str,
        token: &str,
        envelope: &FederatedDmRequest,
    ) -> Result<reqwest::Response> {
        self.http
            .post(format!("{base_url}/federation/dm"))
            .bearer_auth(token)
            .json(envelope)
            .send()
            .await
            .context("Failed to deliver DM to peer")
    }

    /// POST a badge offer to a remote hub's unauthenticated
    /// `/federation/badge-offer` endpoint.
    #[allow(clippy::too_many_arguments)]
    pub async fn post_badge_offer(
        &self,
        base_url: &str,
        from_hub_pubkey: &str,
        from_hub_url: &str,
        label: &str,
        note: Option<&str>,
        payload: &str,
        signature: &str,
    ) -> Result<()> {
        let resp = self
            .http
            .post(format!("{base_url}/federation/badge-offer"))
            .json(&serde_json::json!({
                "from_hub_pubkey": from_hub_pubkey,
                "from_hub_url": from_hub_url,
                "label": label,
                "note": note,
                "payload": payload,
                "signature": signature,
            }))
            .send()
            .await
            .context("Failed to reach recipient hub")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Recipient returned HTTP {status}: {body}");
        }

        Ok(())
    }
}
