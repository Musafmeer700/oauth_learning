import mongoose from "mongoose";
import env from "./env.js";

const connectDatabase = async () => {
	if (!env.mongoDbUri) {
		return;
	}

	await mongoose.connect(env.mongoDbUri);
	console.log("MongoDB connected");
};

export default connectDatabase;
