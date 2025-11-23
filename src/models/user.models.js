import mongoose, { Schema } from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";

/**
 * Mongoose schema for the User collection.
 *
 * Fields:
 * - avatar: object containing `url` (public URL) and `localPath` (server file path).
 * - username: unique identifier for the user (lowercased and trimmed).
 * - email: user's email (unique and lowercased).
 * - fullname: optional display name.
 * - password: hashed password string (required).
 * - isEmailVerified: flag indicating whether email was verified.
 * - refreshToken: stored refresh token (if using refresh token strategy).
 * - forgotPasswordToken / forgotPasswordExpiry: token and expiry for password resets.
 * - emailVerificationToken / emailVerificationExpiry: token and expiry for email verification.
 *
 * Timestamps (`createdAt`, `updatedAt`) are enabled.
 */
const userSchema = new Schema(
  {
    avatar: {
      type: {
        url: String,
        localPath: String,
      },
      default: {
        url: `https://placehold.co/200x200`,
        localPath: "",
      },
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    fullname: {
      type: String,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    refreshToken: {
      type: String,
    },
    forgotPasswordToken: {
      type: String,
    },
    forgotPasswordExpiry: {
      type: Date,
    },
    emailVerificationToken: {
      type: String,
    },
    emailVerificationExpiry: {
      type: Date,
    },
  },
  {
    timestamps: true,
  },
);

/**
 * Pre-save hook - hashes the password before saving the document.
 * Only runs when the `password` field has been modified (or is new).
 */
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

/**
 * Compare a plaintext password with the stored hashed password.
 * @param {string} password - Plaintext password to verify.
 * @returns {Promise<boolean>} - Resolves `true` if the password matches.
 */
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

/**
 * Generate a JWT access token for the user.
 * Payload includes `_id`, `email`, and `username`.
 * Uses `process.env.ACCESS_TOKEN_SECRET` and `ACCESS_TOKEN_EXPIRY`.
 * @returns {string} Signed JWT access token.
 */
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    },
  );
};

/**
 * Generate a JWT refresh token for the user.
 * Payload contains only `_id` to keep token small.
 * Uses `process.env.REFRESH_TOKEN_SECRET` and `REFRESH_TOKEN_EXPIRY`.
 * @returns {string} Signed JWT refresh token.
 */
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    },
  );
};

/**
 * Generate a temporary token used for actions like password reset or
 * email verification.
 * Returns the unhashed token (to be sent to user), the hashed token
 * (to be stored in DB), and an expiry timestamp (ms since epoch).
 *
 * Note: the hashing algorithm name used below is `sha256` as in the
 * original code; if you expect `sha256`, update the algorithm accordingly.
 *
 * @returns {{unHashedToken: string, hashedToken: string, tokenExpiry: number}}
 */
userSchema.methods.generateTemporaryToken = function () {
  const unHashedToken = crypto.randomBytes(20).toString("hex");

  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex");

  const tokenExpiry = Date.now() + 20 * 60 * 1000; // 20 mins

  return { unHashedToken, hashedToken, tokenExpiry };
};

export const User = mongoose.model("User", userSchema);
