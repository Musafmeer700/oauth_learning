import mongoose from "mongoose";
import dns from "dns";
import env from "./env.js";

const connectDatabase = async () => {
	if (!env.mongoDbUri) {
		throw new Error("MONGODB_URI is not configured");
	}

	dns.setServers(["8.8.8.8", "8.8.4.4"]);

	await mongoose.connect(env.mongoDbUri);
	console.log("MongoDB connected");
};

export default connectDatabase;
