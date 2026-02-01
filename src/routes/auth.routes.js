import { Router } from "express";
import { registerUser, login, logout, verifyEmail, resendEmailVerification, refreshAccessToken, getCurrentUser, forgotPasswordReset, resetForgotPassword, changeCurrentPassword } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
  userChangePasswordValidator,
} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

//Unsecure routes
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(userForgotPasswordValidator(), validate, forgotPasswordReset);
router.route("/reset-password/:verificationToken").post(userResetForgotPasswordValidator(), validate, resetForgotPassword);

//secure routes
router.route("/logout").post(verifyJWT, logout);
router.route("/current-user").get(verifyJWT, getCurrentUser);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);
router.route("/change-password").post(verifyJWT, userChangePasswordValidator(), validate, changeCurrentPassword);

export default router;
