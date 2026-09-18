import { timingSafeEqual } from "node:crypto";
import env from "../config/env.js";
import AppError from "../utils/app-error.js";

const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const MAX_ERROR_DESCRIPTION_LENGTH = 180;

const GOOGLE_OAUTH_ERROR_MESSAGES = {
	access_denied: "Google authorization was denied",
	invalid_request: "Google authorization request was invalid",
	unauthorized_client: "This application is not authorized to request Google sign-in",
	unsupported_response_type: "Google authorization request was invalid",
	invalid_scope: "Google authorization request used an invalid scope",
	server_error: "Google authorization failed due to a server error",
	temporarily_unavailable: "Google authorization is temporarily unavailable",
};

export function buildGoogleAuthorizationUrl(state) {
	if (!env.googleClientId || !env.googleClientSecret || !env.googleRedirectUri) {
		throw new AppError("Google OAuth configuration is incomplete", 500);
	}

	if (!state) {
		throw new AppError("OAuth state is required", 500);
	}

	const authorizationUrl = new URL(GOOGLE_AUTHORIZATION_ENDPOINT);
	authorizationUrl.search = new URLSearchParams({
		client_id: env.googleClientId,
		redirect_uri: env.googleRedirectUri,
		response_type: "code",
		scope: "openid email profile",
		state,
	}).toString();

	return authorizationUrl.toString();
}

export function validateGoogleAuthorizationCallback(query, storedState) {
	const code = asQueryString(query.code);
	const returnedState = asQueryString(query.state);
	const error = asQueryString(query.error);
	const errorDescription = asQueryString(query.error_description);

	if (!returnedState || !storedState) {
		throw new AppError("OAuth state is missing", 400);
	}

	if (!oauthStatesMatch(returnedState, storedState)) {
		throw new AppError("OAuth state mismatch", 403);
	}

	if (error) {
		throw new AppError(buildGoogleOAuthErrorMessage(error, errorDescription), 400);
	}

	if (!code) {
		throw new AppError("Authorization code is missing", 400);
	}
}

function asQueryString(value) {
	return typeof value === "string" ? value : "";
}

function oauthStatesMatch(returnedState, storedState) {
	const returnedBuffer = Buffer.from(returnedState);
	const storedBuffer = Buffer.from(storedState);

	if (returnedBuffer.length !== storedBuffer.length) {
		return false;
	}

	return timingSafeEqual(returnedBuffer, storedBuffer);
}

function buildGoogleOAuthErrorMessage(error, errorDescription) {
	const safeDescription = sanitizeErrorDescription(errorDescription);

	if (safeDescription) {
		return safeDescription;
	}

	return GOOGLE_OAUTH_ERROR_MESSAGES[error] || "Google authorization failed";
}

function sanitizeErrorDescription(errorDescription) {
	const trimmed = errorDescription.trim();

	if (!trimmed || trimmed.length > MAX_ERROR_DESCRIPTION_LENGTH) {
		return "";
	}

	if (/code=|token=|secret/i.test(trimmed)) {
		return "";
	}

	return trimmed;
}
