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
	const code = typeof query.code === "string" ? query.code : "";
	const returnedState = typeof query.state === "string" ? query.state : "";
	const error = typeof query.error === "string" ? query.error : "";
	const errorDescription = typeof query.error_description === "string" ? query.error_description : "";

	if (!returnedState || !storedState) {
		throw new AppError("OAuth state is missing", 400);
	}

	const returnedStateBuffer = Buffer.from(returnedState);
	const storedStateBuffer = Buffer.from(storedState);

	if (
		returnedStateBuffer.length !== storedStateBuffer.length ||
		!timingSafeEqual(returnedStateBuffer, storedStateBuffer)
	) {
		throw new AppError("OAuth state mismatch", 403);
	}

	if (error) {
		let safeDescription = errorDescription.trim();

		if (!safeDescription || safeDescription.length > MAX_ERROR_DESCRIPTION_LENGTH) {
			safeDescription = "";
		}

		if (/code=|token=|secret/i.test(safeDescription)) {
			safeDescription = "";
		}

		throw new AppError(safeDescription || GOOGLE_OAUTH_ERROR_MESSAGES[error] || "Google authorization failed", 400);
	}

	if (!code) {
		throw new AppError("Authorization code is missing", 400);
	}

	return code;
}

export async function exchangeAuthorizationCode(code) {
	if (!env.googleClientId || !env.googleClientSecret || !env.googleRedirectUri) {
		throw new AppError("Google OAuth configuration is incomplete", 500);
	}

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

	let payload;

	try {
		payload = await response.json();
	} catch {
		throw new AppError("Google token response was invalid", 502);
	}

	if (!response.ok) {
		const tokenError = typeof payload?.error === "string" ? payload.error : "";
		let safeDescription = typeof payload?.error_description === "string" ? payload.error_description.trim() : "";

		if (!safeDescription || safeDescription.length > MAX_ERROR_DESCRIPTION_LENGTH) {
			safeDescription = "";
		}

		if (/code=|token=|secret/i.test(safeDescription)) {
			safeDescription = "";
		}

		if (env.googleClientSecret && safeDescription.includes(env.googleClientSecret)) {
			safeDescription = "";
		}

		let statusCode = 502;

		if (response.status === 401 || response.status === 403) {
			statusCode = response.status;
		} else if (response.status >= 400 && response.status < 500) {
			statusCode = 400;
		}

		throw new AppError(
			safeDescription || GOOGLE_TOKEN_ERROR_MESSAGES[tokenError] || "Google token exchange failed",
			statusCode
		);
	}

	const accessToken = typeof payload?.access_token === "string" ? payload.access_token : "";
	const idToken = typeof payload?.id_token === "string" ? payload.id_token : "";

	if (!accessToken || !idToken) {
		throw new AppError("Google token response was incomplete", 502);
	}

	return { idToken };
}
