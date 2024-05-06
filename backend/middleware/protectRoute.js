import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

export const protectRoute = async (req, res, next) => {
	try {
		console.log("Request cookies:", req.cookies); // Log cookies for debugging
		const token = req.cookies.jwt;
		if (!token) {
			return res.status(401).json({ error: "Unauthorized: No Token Provided" });
		}

		const tokenParts = token.split(' ');
		if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
			return res.status(401).json({ error: "Unauthorized: Invalid Token Format" });
		}
		const decoded = jwt.verify(tokenParts[1], process.env.JWT_SECRET);

		if (!decoded) {
			return res.status(401).json({ error: "Unauthorized: Invalid Token" });
		}

		const user = await User.findById(decoded.userId).select("-password");

		if (!user) {
			return res.status(404).json({ error: "User not found" });
		}

		req.user = user;
		next();
	} catch (err) {
		console.log("Error in protectRoute middleware:", err.message);
		return res.status(500).json({ error: "Internal Server Error" });
	}
};
