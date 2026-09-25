import User from "../models/user.model.js";
import OAuthAccount from "../models/oauth-account.model.js";
import AppError from "../utils/app-error.js";

const GOOGLE_PROVIDER = "google";

export async function findOrCreateGoogleUser(identity) {
    const googleId =
        typeof identity?.googleId === "string" ? identity.googleId : "";
    const email =
        typeof identity?.email === "string"
            ? identity.email.trim().toLowerCase()
            : "";
    const emailVerified = identity?.emailVerified === true;
    const name = typeof identity?.name === "string" ? identity.name : "";
    const avatar =
        typeof identity?.picture === "string" ? identity.picture : "";

    if (!googleId) {
        throw new AppError("Google account identifier is missing", 401);
    }

    const existingAccount = await OAuthAccount.findOne({
        provider: GOOGLE_PROVIDER,
        providerAccountId: googleId,
    });

    if (existingAccount) {
        const user = await User.findById(existingAccount.userId);

        if (!user) {
            throw new AppError("Linked user was not found", 500);
        }

        return {
            id: String(user._id),
            email: user.email,
            name: user.name,
            avatar: user.avatar,
        };
    }

    if (!email) {
        throw new AppError("Google account email is required", 400);
    }

    let user = await User.findOne({ email });

    if (user) {
        if (!emailVerified) {
            throw new AppError(
                "Google email is not verified, so this account cannot be linked",
                403,
            );
        }
    } else {
        if (!emailVerified) {
            throw new AppError("Google email is not verified", 403);
        }
        user = await User.create({
            email,
            name,
            avatar,
        });
    }
    await OAuthAccount.create({
        userId: user._id,
        provider: GOOGLE_PROVIDER,
        providerAccountId: googleId,
    });

    return {
        id: String(user._id),
        email: user.email,
        name: user.name,
        avatar: user.avatar,
    };
}
