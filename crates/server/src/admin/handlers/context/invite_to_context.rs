use std::sync::Arc;

use axum::response::IntoResponse;
use axum::{Extension, Json};
use calimero_server_primitives::admin::{InviteToContextRequest, InviteToContextResponse};
use reqwest::StatusCode;

use crate::admin::service::{parse_api_error, ApiError, ApiResponse};
use crate::AdminState;

pub async fn handler(
    Extension(state): Extension<Arc<AdminState>>,
    Json(req): Json<InviteToContextRequest>,
) -> impl IntoResponse {
    let has_permission = state
        .ctx_manager
        .has_invite_permission(req.context_id, req.inviter_id)
        .await
        .map_err(parse_api_error);

    match has_permission {
        Ok(false) => {
            return ApiError {
                status_code: StatusCode::FORBIDDEN,
                message: "User does not have permission to invite".to_string(),
            }
            .into_response()
        }
        Err(err) => return err.into_response(),
        _ => (),
    }

    let result = state
        .ctx_manager
        .invite_to_context(req.context_id, req.inviter_id, req.invitee_id)
        .await
        .map_err(parse_api_error);

    match result {
        Ok(invitation_payload) => ApiResponse {
            payload: InviteToContextResponse::new(invitation_payload),
        }
        .into_response(),
        Err(err) => err.into_response(),
    }
}
