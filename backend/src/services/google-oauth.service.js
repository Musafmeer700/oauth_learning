import env from "../config/env.js";
import AppError from "../utils/app-error.js";

const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";

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
