import { createRemoteJWKSet, errors as joseErrors, jwtVerify } from "jose";
import env from "../config/env.js";
import AppError from "../utils/app-error.js";

const GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration";
const GOOGLE_ISSUER = "https://accounts.google.com";
const DISCOVERY_TIMEOUT_MS = 10_000;
const DEFAULT_DISCOVERY_CACHE_MS = 60 * 60 * 1000;
const MAX_DISCOVERY_CACHE_MS = 24 * 60 * 60 * 1000;
const CLOCK_TOLERANCE_SECONDS = 60;
const MAX_TOKEN_AGE_SECONDS = 3600;

const ALLOWED_JWKS_HOSTS = new Set(["www.googleapis.com", "googleapis.com"]);

let discoveryCache = {
	expiresAt: 0,
	jwks: null,
	jwksUri: "",
};

export async function verifyGoogleIdToken(idToken) {
	if (!env.googleClientId) {
		throw new AppError("Google OAuth configuration is incomplete", 500);
	}

	if (!idToken || typeof idToken !== "string") {
		throw new AppError("Google ID token is missing", 401);
	}

	let jwks = discoveryCache.jwks;

	if (!jwks || discoveryCache.expiresAt <= Date.now()) {
		let discoveryResponse;

		try {
			discoveryResponse = await fetch(GOOGLE_DISCOVERY_URL, {
				signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
			});
		} catch {
			throw new AppError("Failed to reach Google OpenID configuration", 502);
		}

		if (!discoveryResponse.ok) {
			throw new AppError("Failed to load Google OpenID configuration", 502);
		}

		let metadata;

		try {
			metadata = await discoveryResponse.json();
		} catch {
			throw new AppError("Google OpenID configuration was invalid", 502);
		}

		if (metadata.issuer !== GOOGLE_ISSUER) {
			throw new AppError("Google OpenID configuration is invalid", 502);
		}

		if (typeof metadata.jwks_uri !== "string") {
			throw new AppError("Google OpenID configuration is invalid", 502);
		}

		let jwksUrl;

		try {
			jwksUrl = new URL(metadata.jwks_uri);
		} catch {
			throw new AppError("Google OpenID configuration is invalid", 502);
		}

		if (jwksUrl.protocol !== "https:" || !ALLOWED_JWKS_HOSTS.has(jwksUrl.hostname)) {
			throw new AppError("Google OpenID configuration is invalid", 502);
		}

		const jwksUri = jwksUrl.toString();

		if (discoveryCache.jwks && discoveryCache.jwksUri === jwksUri) {
			jwks = discoveryCache.jwks;
		} else {
			jwks = createRemoteJWKSet(jwksUrl, { timeoutDuration: DISCOVERY_TIMEOUT_MS });
		}

		const cacheControl = discoveryResponse.headers.get("cache-control");
		const maxAgeMatch = typeof cacheControl === "string" ? /max-age=(\d+)/i.exec(cacheControl) : null;
		const maxAgeSeconds = maxAgeMatch ? Number(maxAgeMatch[1]) : NaN;
		let cacheMaxAgeMs = DEFAULT_DISCOVERY_CACHE_MS;

		if (Number.isFinite(maxAgeSeconds) && maxAgeSeconds > 0) {
			cacheMaxAgeMs = Math.min(maxAgeSeconds * 1000, MAX_DISCOVERY_CACHE_MS);
		}

		discoveryCache = {
			expiresAt: Date.now() + cacheMaxAgeMs,
			jwks,
			jwksUri,
		};
	}

	let payload;

	try {
		({ payload } = await jwtVerify(idToken, jwks, {
			issuer: GOOGLE_ISSUER,
			audience: env.googleClientId,
			algorithms: ["RS256"],
			clockTolerance: CLOCK_TOLERANCE_SECONDS,
			maxTokenAge: MAX_TOKEN_AGE_SECONDS,
			requiredClaims: ["sub", "exp", "iat"],
		}));
	} catch (error) {
		if (error instanceof AppError) {
			throw error;
		}

		if (error instanceof joseErrors.JWTExpired) {
			if (error.claim === "iat") {
				throw new AppError("Google ID token issued-at claim is invalid", 401);
			}

			throw new AppError("Google ID token has expired", 401);
		}

		if (error instanceof joseErrors.JWTClaimValidationFailed) {
			if (error.claim === "iss") {
				throw new AppError("Google ID token issuer is invalid", 401);
			}

			if (error.claim === "aud") {
				throw new AppError("Google ID token audience is invalid", 401);
			}

			if (error.claim === "sub") {
				throw new AppError("Google ID token is missing a subject", 401);
			}

			if (error.claim === "iat") {
				throw new AppError("Google ID token issued-at claim is invalid", 401);
			}

			if (error.claim === "exp") {
				throw new AppError("Google ID token has expired", 401);
			}

			throw new AppError("Google ID token claims are invalid", 401);
		}

		if (
			error instanceof joseErrors.JWSSignatureVerificationFailed ||
			error instanceof joseErrors.JWKSNoMatchingKey
		) {
			throw new AppError("Google ID token signature is invalid", 401);
		}

		if (error instanceof joseErrors.JWKSTimeout) {
			throw new AppError("Failed to reach Google signing keys", 502);
		}

		if (error instanceof joseErrors.JWTInvalid || error instanceof joseErrors.JWSInvalid) {
			throw new AppError("Google ID token is invalid", 401);
		}

		throw new AppError("Google ID token verification failed", 401);
	}

	const googleId = typeof payload.sub === "string" ? payload.sub : "";

	if (!googleId) {
		throw new AppError("Google ID token is missing a subject", 401);
	}

	return {
		googleId,
		email: typeof payload.email === "string" ? payload.email : "",
		emailVerified: payload.email_verified === true || payload.email_verified === "true",
		name: typeof payload.name === "string" ? payload.name : "",
		picture: typeof payload.picture === "string" ? payload.picture : "",
	};
}
