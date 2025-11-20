import { Router } from "express";

// Validators
import {
  userForgotPasswordValidator,
  userResetPasswordValidator,
  userChangeValidator,
  validate,
} from "../validators/auth.validators.js";

// Controllers
import {
  resetForgotPassword,
  registerUser,
  login,
  logoutUser,
  refreshAccessToken,
  verifyEmail,
  forgotPasswordRequest,
  getCurrentUser,
  changeCurrentPassword,
  resendEmailVerification,
} from "../controllers/auth.controller.js";

import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// Auth Routes
router.post("/register", registerUser);
router.post("/login", login);

// Verify email
router.get("/verify-email/:verificationToken", verifyEmail);

// Forgot password request
router.post(
  "/forgot-password",
  userForgotPasswordValidator,
  validate,
  forgotPasswordRequest,
);

// Reset password
router.post(
  "/reset-password/:resetToken",
  userResetPasswordValidator,
  validate,
  resetForgotPassword,
);

// Refresh Token
router.post("/refresh-token", refreshAccessToken);

// Logout Route (Protected)
router.post("/logout", verifyJWT, logoutUser);
router.post("/current-user", verifyJWT, getCurrentUser);

// Resend email verification (Protected)
router.post("/resend-email-verification", verifyJWT, resendEmailVerification);

// Change password (Protected)
router.post(
  "/change-password",
  verifyJWT,
  userChangeValidator,
  validate,
  changeCurrentPassword,
);

export default router;
