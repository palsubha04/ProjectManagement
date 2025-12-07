/**
 * @file Validator middleware for user registration
 * @description Contains validation rules and schemas for user registration using express-validator
 */

import { body } from "express-validator";

/**
 * Validates user registration data
 * @function userRegisterValidator
 * @returns {Array} Array of validation middleware chains for express-validator
 * @description Validates the following fields:
 *   - email: Required, must be a valid email format
 *   - username: Required, lowercase only, minimum 3 characters
 *   - password: Required, cannot be empty
 *   - fullname: Optional field
 */
const userRegisterValidator = () => {
  return [
    // Email field validation
    body("email")
      .trim() // Remove leading/trailing whitespace
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),

    // Username field validation
    body("username")
      .trim() // Remove leading/trailing whitespace
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username must be in lower case")
      .isLength({ min: 3 })
      .withMessage("Username must be atleast 3 characters long"),

    // Password field validation
    body("password")
      .trim() // Remove leading/trailing whitespace
      .notEmpty()
      .withMessage("Password is required"),

    // Full name field validation (optional)
    body("fullname").optional().trim(),
  ];
};

export { userRegisterValidator };
