import AppError from "./app-error.js";

const UNIT_MS = {
	s: 1000,
	m: 60 * 1000,
	h: 60 * 60 * 1000,
	d: 24 * 60 * 60 * 1000,
	w: 7 * 24 * 60 * 60 * 1000,
};

export function expiresInToMs(expiresIn) {
	if (typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0) {
		return expiresIn * 1000;
	}

	if (typeof expiresIn !== "string") {
		throw new AppError("Application JWT expiration is invalid", 500);
	}

	const trimmed = expiresIn.trim();

	if (/^\d+$/.test(trimmed)) {
		const seconds = Number(trimmed);

		if (!Number.isFinite(seconds) || seconds <= 0) {
			throw new AppError("Application JWT expiration is invalid", 500);
		}

		return seconds * 1000;
	}

	const match = /^(\d+)\s*([smhdw])$/i.exec(trimmed);

	if (!match) {
		throw new AppError("Application JWT expiration is invalid", 500);
	}

	const amount = Number(match[1]);
	const unit = match[2].toLowerCase();

	if (!Number.isFinite(amount) || amount <= 0) {
		throw new AppError("Application JWT expiration is invalid", 500);
	}

	return amount * UNIT_MS[unit];
}
