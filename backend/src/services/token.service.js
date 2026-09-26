import { SignJWT, jwtVerify, errors as joseErrors } from "jose";
import env from "../config/env.js";
import AppError from "../utils/app-error.js";

const ACCESS_TOKEN_TYPE = "access";
const REFRESH_TOKEN_TYPE = "refresh";
const JWT_ALGORITHM = "HS256";
const MIN_SECRET_LENGTH = 32;

function encodeSecret(secret) {
	return new TextEncoder().encode(secret);
}

function getApplicationUserId(user) {
	if (!user || typeof user !== "object") {
		throw new AppError("User is required to generate a token", 500);
	}

	const userId = user._id ?? user.id;

	if (userId == null || userId === "") {
		throw new AppError("User id is required to generate a token", 500);
	}

	return String(userId);
}

function assertJwtConfiguration() {
	if (!env.jwtAccessSecret || !env.jwtRefreshSecret) {
		throw new AppError("Application JWT configuration is incomplete", 500);
	}

	if (
		env.jwtAccessSecret.length < MIN_SECRET_LENGTH ||
		env.jwtRefreshSecret.length < MIN_SECRET_LENGTH
	) {
		throw new AppError("Application JWT secrets must be at least 32 characters", 500);
	}

	if (env.jwtAccessSecret === env.jwtRefreshSecret) {
		throw new AppError("Access and refresh token secrets must be different", 500);
	}

	if (
		env.googleClientSecret &&
		(env.jwtAccessSecret === env.googleClientSecret ||
			env.jwtRefreshSecret === env.googleClientSecret)
	) {
		throw new AppError("Application JWT secrets must not reuse Google OAuth secrets", 500);
	}
}

async function generateApplicationToken({ user, type, secret, expiresIn }) {
	assertJwtConfiguration();

	const userId = getApplicationUserId(user);

	try {
		return await new SignJWT({ type })
			.setProtectedHeader({ alg: JWT_ALGORITHM })
			.setSubject(userId)
			.setIssuedAt()
			.setExpirationTime(expiresIn)
			.sign(encodeSecret(secret));
	} catch (error) {
		if (error instanceof AppError) {
			throw error;
		}

		throw new AppError(`Failed to generate ${type} token`, 500);
	}
}

async function verifyApplicationToken({ token, secret, expectedType, typeLabel }) {
	assertJwtConfiguration();

	if (!token || typeof token !== "string") {
		throw new AppError(`${typeLabel} token is missing`, 401);
	}

	let payload;

	try {
		({ payload } = await jwtVerify(token, encodeSecret(secret), {
			algorithms: [JWT_ALGORITHM],
			requiredClaims: ["sub", "exp", "iat", "type"],
		}));
	} catch (error) {
		if (error instanceof AppError) {
			throw error;
		}

		if (error instanceof joseErrors.JWTExpired) {
			throw new AppError(`${typeLabel} token has expired`, 401);
		}

		if (error instanceof joseErrors.JWSSignatureVerificationFailed) {
			throw new AppError(`${typeLabel} token signature is invalid`, 401);
		}

		if (error instanceof joseErrors.JWTClaimValidationFailed) {
			if (error.claim === "sub") {
				throw new AppError(`${typeLabel} token is missing a subject`, 401);
			}

			if (error.claim === "exp") {
				throw new AppError(`${typeLabel} token has expired`, 401);
			}

			throw new AppError(`${typeLabel} token claims are invalid`, 401);
		}

		if (error instanceof joseErrors.JWTInvalid || error instanceof joseErrors.JWSInvalid) {
			throw new AppError(`${typeLabel} token is invalid`, 401);
		}

		throw new AppError(`${typeLabel} token verification failed`, 401);
	}

	if (payload.type !== expectedType) {
		throw new AppError(`Token is not ${expectedType === ACCESS_TOKEN_TYPE ? "an access" : "a refresh"} token`, 401);
	}

	const userId = typeof payload.sub === "string" ? payload.sub : "";

	if (!userId) {
		throw new AppError(`${typeLabel} token is missing a subject`, 401);
	}

	return {
		userId,
		type: payload.type,
	};
}

export async function generateAccessToken(user) {
	return generateApplicationToken({
		user,
		type: ACCESS_TOKEN_TYPE,
		secret: env.jwtAccessSecret,
		expiresIn: env.jwtAccessExpiresIn,
	});
}

export async function generateRefreshToken(user) {
	return generateApplicationToken({
		user,
		type: REFRESH_TOKEN_TYPE,
		secret: env.jwtRefreshSecret,
		expiresIn: env.jwtRefreshExpiresIn,
	});
}

export async function verifyAccessToken(token) {
	return verifyApplicationToken({
		token,
		secret: env.jwtAccessSecret,
		expectedType: ACCESS_TOKEN_TYPE,
		typeLabel: "Access",
	});
}

export async function verifyRefreshToken(token) {
	return verifyApplicationToken({
		token,
		secret: env.jwtRefreshSecret,
		expectedType: REFRESH_TOKEN_TYPE,
		typeLabel: "Refresh",
	});
}
