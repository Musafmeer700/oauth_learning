import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
	{
		email: {
			type: String,
			required: true,
			unique: true,
			lowercase: true,
			trim: true,
		},
		name: {
			type: String,
			default: "",
		},
		avatar: {
			type: String,
			default: "",
		},
	},
	{ timestamps: true }
);

const User = mongoose.model("User", userSchema);
export default User;
