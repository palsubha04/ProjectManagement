/**
 * Authentication Middleware
 *
 * This middleware handles JWT token verification for protected routes.
 * It extracts the access token from cookies or Authorization header,
 * verifies it, and attaches the authenticated user to the request object.
 */

import { User } from "../models/user.models.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import jwt from "jsonwebtoken";

/**
 * Verify JWT Middleware
 *
 * Validates the JWT token from the request and authenticates the user.
 * Token can be provided via cookies (accessToken) or Authorization header (Bearer token).
 * On successful verification, attaches the user object to req.user.
 *
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @throws {ApiError} - Throws 401 error if token is missing or invalid
 */
export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const decodedToken = jwt.verify(token, process.env.accessTokenSecret);
    const user = await User.findById(decodedToken.id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
    );
    if (!user) {
      throw new ApiError(401, "Invalid access token");
    }
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, "Invalid access token");
  }
});
