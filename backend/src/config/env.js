import dotenv from "dotenv";

dotenv.config();

const env = {
	port: Number(process.env.PORT) || 3000,
	nodeEnv: process.env.NODE_ENV || "development",
	mongoDbUri: process.env.MONGODB_URI || "",
	clientUrl: process.env.CLIENT_URL || "http://localhost:3000",
	googleClientId: process.env.GOOGLE_CLIENT_ID || "",
	googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
	googleRedirectUri: process.env.GOOGLE_REDIRECT_URI || "",
	jwtAccessSecret: process.env.JWT_ACCESS_SECRET || "",
	jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || "",
	jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || "15m",
	jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
};

export default env;
