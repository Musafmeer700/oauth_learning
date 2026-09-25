import mongoose from "mongoose";

const oauthAccountSchema = new mongoose.Schema(
	{
		userId: {
			type: mongoose.Schema.Types.ObjectId,
			ref: "User",
			required: true,
			index: true,
		},
		provider: {
			type: String,
			required: true,
		},
		providerAccountId: {
			type: String,
			required: true,
		},
	},
	{ timestamps: true }
);

oauthAccountSchema.index({ provider: 1, providerAccountId: 1 }, { unique: true });

const OAuthAccount =  mongoose.model("OAuthAccount", oauthAccountSchema);
export default OAuthAccount
