import { randomBytes } from "node:crypto";
import mongoose from "mongoose";
import {
    buildGoogleAuthorizationUrl,
    exchangeAuthorizationCode,
    validateGoogleAuthorizationCallback,
} from "../services/google-oauth.service.js";
import { verifyGoogleIdToken } from "../services/google-oidc.service.js";
import { findOrCreateGoogleUser } from "../services/auth.service.js";
import {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
} from "../services/token.service.js";
import User from "../models/user.model.js";
import env from "../config/env.js";
import AppError from "../utils/app-error.js";
import { expiresInToMs } from "../utils/expires-in.js";

const GOOGLE_STATE_COOKIE = "google_oauth_state";
const GOOGLE_STATE_MAX_AGE = 10 * 60 * 1000;

const GOOGLE_STATE_COOKIE_OPTIONS = {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    path: "/",
};

const ACCESS_TOKEN_COOKIE = "access_token";
const REFRESH_TOKEN_COOKIE = "refresh_token";

const APPLICATION_AUTH_COOKIE_OPTIONS = {
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
        storedState,
    );

    const { idToken } = await exchangeAuthorizationCode(authorizationCode);

    const identity = await verifyGoogleIdToken(idToken);

    const user = await findOrCreateGoogleUser(identity);

    const accessToken = await generateAccessToken(user);
    const refreshToken = await generateRefreshToken(user);

    setApplicationAuthCookies(res, { accessToken, refreshToken });

    return res.json({
        success: true,
        message: "Google authentication successful",
        data: {
            user,
        },
    });
}

export function getMe(req, res) {
    return res.json({
        success: true,
        data: {
            user: {
                id: String(req.user._id),
                email: req.user.email,
                name: req.user.name,
                avatar: req.user.avatar,
            },
        },
    });
}

export async function refreshAccessToken(req, res) {
    const refreshToken = req.cookies?.[REFRESH_TOKEN_COOKIE];

    if (!refreshToken) {
        throw new AppError("Refresh token is missing", 401);
    }

    const decoded = await verifyRefreshToken(refreshToken);
    const userId = decoded.sub;

    if (!userId || !mongoose.isValidObjectId(userId)) {
        throw new AppError("Refresh token is invalid", 401);
    }

    const user = await User.findById(userId);

    if (!user) {
        throw new AppError("User was not found", 401);
    }

    const accessToken = await generateAccessToken(user);

    setAccessTokenCookie(res, accessToken);

    return res.json({
        success: true,
        message: "Access token refreshed",
    });
}

function setAccessTokenCookie(res, accessToken) {
    res.cookie(ACCESS_TOKEN_COOKIE, accessToken, {
        ...APPLICATION_AUTH_COOKIE_OPTIONS,
        maxAge: expiresInToMs(env.jwtAccessExpiresIn),
    });
}

function setApplicationAuthCookies(res, { accessToken, refreshToken }) {
    setAccessTokenCookie(res, accessToken);

    res.cookie(REFRESH_TOKEN_COOKIE, refreshToken, {
        ...APPLICATION_AUTH_COOKIE_OPTIONS,
        maxAge: expiresInToMs(env.jwtRefreshExpiresIn),
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
