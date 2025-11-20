import { Router } from "express";

import {
  registerUser,
  login,
  logoutUser,
  refreshAccessToken,
} from "../controllers/auth.controller.js";

import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// Auth Routes
router.post("/register", registerUser);
router.post("/login", login);

// Refresh Token Route
router.post("/refresh-token", refreshAccessToken);

// Logout Route (Protected)
router.post("/logout", verifyJWT, logoutUser);

export default router;
