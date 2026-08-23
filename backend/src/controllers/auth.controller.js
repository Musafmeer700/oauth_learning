import { randomBytes } from "node:crypto";
import { buildGoogleAuthorizationUrl } from "../services/google-oauth.service.js";

const GOOGLE_STATE_COOKIE = "google_oauth_state";
const GOOGLE_STATE_MAX_AGE = 10 * 60 * 1000;

export async function googleAuthorization(req, res) {
	const state = randomBytes(32).toString("hex");
	const authorizationUrl = buildGoogleAuthorizationUrl(state);

	res.cookie(GOOGLE_STATE_COOKIE, state, {
		httpOnly: true,
		sameSite: "lax",
		secure: false,
		maxAge: GOOGLE_STATE_MAX_AGE,
	});

	return res.redirect(302, authorizationUrl);
}
