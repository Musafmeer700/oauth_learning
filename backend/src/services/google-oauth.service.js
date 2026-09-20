import { timingSafeEqual } from "node:crypto";
import env from "../config/env.js";
import AppError from "../utils/app-error.js";

const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const GOOGLE_TOKEN_TIMEOUT_MS = 10_000;
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

const GOOGLE_TOKEN_ERROR_MESSAGES = {
	invalid_request: "Google token request was invalid",
	invalid_client: "Google client authentication failed",
	invalid_grant: "Authorization code is invalid or has expired",
	unauthorized_client: "This application is not authorized to exchange Google authorization codes",
	unsupported_grant_type: "Google token request used an unsupported grant type",
	invalid_scope: "Google token request used an invalid scope",
};

export function buildGoogleAuthorizationUrl(state) {
	assertGoogleOAuthConfigured();

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

	return code;
}

export async function exchangeAuthorizationCode(code) {
	assertGoogleOAuthConfigured();

	if (!code || typeof code !== "string") {
		throw new AppError("Authorization code is missing", 400);
	}

	let response;

	try {
		response = await fetch(GOOGLE_TOKEN_ENDPOINT, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				code,
				client_id: env.googleClientId,
				client_secret: env.googleClientSecret,
				redirect_uri: env.googleRedirectUri,
				grant_type: "authorization_code",
			}),
			signal: AbortSignal.timeout(GOOGLE_TOKEN_TIMEOUT_MS),
		});
	} catch {
		throw new AppError("Failed to reach Google token endpoint", 502);
	}

	const payload = await readGoogleJsonResponse(response);

	if (!response.ok) {
		throw new AppError(buildGoogleTokenErrorMessage(payload), mapGoogleTokenStatus(response.status));
	}

	return extractGoogleIdToken(payload);
}

function assertGoogleOAuthConfigured() {
	if (!env.googleClientId || !env.googleClientSecret || !env.googleRedirectUri) {
		throw new AppError("Google OAuth configuration is incomplete", 500);
	}
}

function asQueryString(value) {
	return typeof value === "string" ? value : "";
}

async function readGoogleJsonResponse(response) {
	try {
		return await response.json();
	} catch {
		throw new AppError("Google token response was invalid", 502);
	}
}

function extractGoogleIdToken(payload) {
	const accessToken = asQueryString(payload?.access_token);
	const idToken = asQueryString(payload?.id_token);

	if (!accessToken || !idToken) {
		throw new AppError("Google token response was incomplete", 502);
	}

	return { idToken };
}

function buildGoogleTokenErrorMessage(payload) {
	const error = asQueryString(payload?.error);
	const safeDescription = sanitizeErrorDescription(asQueryString(payload?.error_description));

	if (containsSensitiveValue(safeDescription)) {
		return GOOGLE_TOKEN_ERROR_MESSAGES[error] || "Google token exchange failed";
	}

	if (safeDescription) {
		return safeDescription;
	}

	return GOOGLE_TOKEN_ERROR_MESSAGES[error] || "Google token exchange failed";
}

function mapGoogleTokenStatus(status) {
	if (status === 401 || status === 403) {
		return status;
	}

	if (status >= 400 && status < 500) {
		return 400;
	}

	return 502;
}

function containsSensitiveValue(value) {
	if (!value) {
		return false;
	}

	return Boolean(
		env.googleClientSecret && value.includes(env.googleClientSecret)
	);
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
