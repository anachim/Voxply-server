use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

async fn setup() -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let (chat_tx, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
                voice_addr_map: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),    });
    let app = server::create_router(state);
    TestServer::new(app)
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

fn sample_survey(survey_id: &str, enabled: bool) -> Value {
    json!({
        "id": survey_id,
        "enabled": enabled,
        "questions": [
            {
                "id": "q1",
                "prompt": "How did you find us?",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "Search engine", "display_order": 1, "role_ids": [] },
                    { "id": "c2", "label": "Friend", "display_order": 2, "role_ids": [] },
                ]
            },
            {
                "id": "q2",
                "prompt": "Anything else?",
                "kind": "text",
                "required": false,
                "display_order": 2,
            }
        ]
    })
}

#[tokio::test]
async fn survey_current_returns_null_when_no_survey() {
    let server = setup().await;
    let user = Identity::generate();
    let token = authenticate(&server, &user).await;

    let resp = server
        .get("/survey/current")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body.is_null());
}

#[tokio::test]
async fn admin_can_create_and_retrieve_survey() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-001";
    let survey = sample_survey(survey_id, true);

    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await;
    resp.assert_status_ok();

    // GET /survey/current should now return the survey
    let resp = server
        .get("/survey/current")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"], survey_id);
    let questions = body["questions"].as_array().unwrap();
    assert_eq!(questions.len(), 2);

    // Role mappings should NOT appear in /survey/current (public view)
    let first_q = &questions[0];
    let first_choice = &first_q["choices"][0];
    assert!(
        first_choice.get("role_ids").is_none(),
        "role_ids should be absent from public survey view"
    );
}

#[tokio::test]
async fn admin_get_survey_includes_role_ids() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-admin-001";
    let survey = json!({
        "id": survey_id,
        "enabled": true,
        "questions": [
            {
                "id": "q1",
                "prompt": "Choose your role",
                "kind": "choice",
                "required": true,
                "display_order": 1,
                "choices": [
                    { "id": "c1", "label": "Developer", "display_order": 1, "role_ids": ["builtin-everyone"] },
                ]
            }
        ]
    });

    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&survey)
        .await
        .assert_status_ok();

    // Admin GET should include role_ids
    let resp = server
        .get("/admin/survey")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(!body.is_null());
    let choices = &body["questions"][0]["choices"];
    let role_ids = choices[0]["role_ids"].as_array().unwrap();
    assert_eq!(role_ids.len(), 1);
    assert_eq!(role_ids[0], "builtin-everyone");
}

#[tokio::test]
async fn survey_submit_happy_path_choice_only() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-submit-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [
                { "question_id": "q1", "choice_id": "c1" }
            ]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // No text answers → should be approved
    assert_eq!(body["next_state"], "approved");
    let applied: &Vec<Value> = body["applied_roles"].as_array().unwrap();
    assert!(applied.is_empty()); // c1 has no role_ids in sample_survey
}

#[tokio::test]
async fn survey_submit_text_answer_sets_pending() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-text-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [
                { "question_id": "q1", "choice_id": "c1" },
                { "question_id": "q2", "text_answer": "I found you via a forum post" }
            ]
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // Has text answer → should be pending
    assert_eq!(body["next_state"], "pending");
}

#[tokio::test]
async fn survey_submit_required_question_missing_returns_error() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-req-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    // q1 is required but not answered
    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": []
        }))
        .await;
    // Should be 422 Unprocessable Entity
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn survey_cannot_be_submitted_twice() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-dedup-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    let answers = json!({
        "survey_id": survey_id,
        "answers": [{ "question_id": "q1", "choice_id": "c1" }]
    });

    server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&answers)
        .await
        .assert_status_ok();

    // Second attempt should fail
    let resp = server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&answers)
        .await;
    assert!(!resp.status_code().is_success());
}

#[tokio::test]
async fn admin_can_list_survey_responses() {
    let server = setup().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&server, &owner).await;

    let survey_id = "survey-resp-1";
    server
        .put("/admin/survey")
        .authorization_bearer(&owner_token)
        .json(&sample_survey(survey_id, true))
        .await
        .assert_status_ok();

    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    server
        .post("/survey/submit")
        .authorization_bearer(&user_token)
        .json(&json!({
            "survey_id": survey_id,
            "answers": [{ "question_id": "q1", "choice_id": "c1" }]
        }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/survey/responses")
        .authorization_bearer(&owner_token)
        .add_query_param("status", "all")
        .await;
    resp.assert_status_ok();
    let responses: Value = resp.json();
    let arr = responses.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["pubkey"], user.public_key_hex());
}

#[tokio::test]
async fn non_admin_cannot_access_admin_survey_routes() {
    let server = setup().await;
    let owner = Identity::generate();
    let _owner_token = authenticate(&server, &owner).await;
    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    // PUT /admin/survey requires admin
    let resp = server
        .put("/admin/survey")
        .authorization_bearer(&user_token)
        .json(&sample_survey("x", true))
        .await;
    resp.assert_status_forbidden();

    // GET /admin/survey requires admin
    let resp = server
        .get("/admin/survey")
        .authorization_bearer(&user_token)
        .await;
    resp.assert_status_forbidden();

    // GET /admin/survey/responses requires admin
    let resp = server
        .get("/admin/survey/responses")
        .authorization_bearer(&user_token)
        .await;
    resp.assert_status_forbidden();
}
