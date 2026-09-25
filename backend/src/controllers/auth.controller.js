import { randomBytes } from "node:crypto";
import {
	buildGoogleAuthorizationUrl,
	exchangeAuthorizationCode,
	validateGoogleAuthorizationCallback,
} from "../services/google-oauth.service.js";
import { verifyGoogleIdToken } from "../services/google-oidc.service.js";
import { findOrCreateGoogleUser } from "../services/auth.service.js";

const GOOGLE_STATE_COOKIE = "google_oauth_state";
const GOOGLE_STATE_MAX_AGE = 10 * 60 * 1000;

const GOOGLE_STATE_COOKIE_OPTIONS = {
	httpOnly: true,
	sameSite: "lax",
	secure: false,
	path: "/",
};

export async function googleAuthorization(req, res) {
	const state = randomBytes(32).toString("hex");
	const authorizationUrl = buildGoogleAuthorizationUrl(state);

	res.cookie(GOOGLE_STATE_COOKIE, state, {
		...GOOGLE_STATE_COOKIE_OPTIONS,
		maxAge: GOOGLE_STATE_MAX_AGE,
	});

	return res.redirect(302, authorizationUrl);
}

export async function googleCallback(req, res) {
	const { code, state, error, error_description } = req.query;
	const storedState = readCookie(req, GOOGLE_STATE_COOKIE);

	res.clearCookie(GOOGLE_STATE_COOKIE, GOOGLE_STATE_COOKIE_OPTIONS);

	const authorizationCode = validateGoogleAuthorizationCallback(
		{ code, state, error, error_description },
		storedState
	);

	const { idToken } = await exchangeAuthorizationCode(authorizationCode);

	const identity = await verifyGoogleIdToken(idToken);
	
	const user = await findOrCreateGoogleUser(identity);

	return res.json({
		success: true,
		message: "Google authentication successful",
		data: {
			user,
		},
	});
}

function readCookie(req, name) {
	const header = req.headers.cookie;

	if (!header) {
		return "";
	}

	const cookies = header.split(";");

	for (const cookie of cookies) {
		const separatorIndex = cookie.indexOf("=");

		if (separatorIndex === -1) {
			continue;
		}

		const key = cookie.slice(0, separatorIndex).trim();

		if (key !== name) {
			continue;
		}

		const value = cookie.slice(separatorIndex + 1).trim();

		try {
			return decodeURIComponent(value);
		} catch {
			return value;
		}
	}

	return "";
}
