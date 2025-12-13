/**
 * Validator Middleware
 *
 * This middleware handles validation of request data using express-validator.
 * It checks for validation errors and throws an ApiError if any are found.
 */

import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

/**
 * Validate middleware function
 *
 * Extracts validation errors from the request and throws an ApiError if validation fails.
 * This middleware should be used after validation chains in routes.
 *
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @throws {ApiError} - Throws a 422 status error with validation details if errors exist
 */
export const validate = (req, res, next) => {
  // Get validation results from express-validator
  const errors = validationResult(req);

  // If no errors found, proceed to the next middleware
  if (errors.isEmpty()) {
    return next();
  }

  // Extract and format validation errors into an array of objects
  // Each error object contains the field path as key and error message as value
  const extractedErrors = [];
  errors.array().map((err) => extractedErrors.push({ [err.path]: err.msg }));

  // Throw an ApiError with 422 (Unprocessable Entity) status code
  // and include the formatted validation errors
  throw new ApiError(422, "Received data is not valid", extractedErrors);
};
