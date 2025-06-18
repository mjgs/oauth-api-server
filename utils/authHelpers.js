// utils/authHelpers.js
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); // Import jwt here for generateAccessToken

/**
 * Checks if a JWT verification error is due to expiration or invalid signature/format.
 * @param {Error} err - The error object from jwt.verify.
 * @returns {boolean} True if the error is a TokenExpiredError or JsonWebTokenError.
 */
const isInvalidOrExpiredTokenError = (err) => {
  return err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError';
};

/**
 * Validates if the request has a valid authenticated principal and if they have the required roles.
 * @param {Object} auth - The decoded JWT payload (req.auth).
 * @param {string} requiredRole - The role string to check against.
 * @returns {boolean} True if the principal is valid and has the required role.
 */
const authHasRequiredRole = (auth, requiredRole) => {
  return auth && auth.roles && Array.isArray(auth.roles) && auth.roles.includes(requiredRole);
};

/**
 * Validates the required parameters for the OAuth Authorization Code Grant with PKCE.
 * @param {Object} query - The query parameters from the request.
 * @returns {boolean} True if all required parameters are present and valid.
 */
const isValidAuthCodeRequest = (query) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method } = query;
  return response_type === 'code' && client_id && redirect_uri && code_challenge && code_challenge_method === 'S256';
};

/**
 * Validates the required parameters for the OAuth Token Endpoint's Authorization Code Grant.
 * @param {Object} body - The request body parameters.
 * @returns {boolean} True if all required parameters are present.
 */
const isValidAuthCodeTokenRequest = (body) => {
  const { code, client_id, redirect_uri, code_verifier } = body;
  return code && client_id && redirect_uri && code_verifier;
};

/**
 * Validates a stored authorization code against client details and expiration.
 * @param {Object} storedAuthCode - The authorization code retrieved from storage.
 * @param {Object} client - The client object from the clients Map.
 * @param {string} redirectUri - The redirect URI from the request.
 * @returns {boolean} True if the stored code is valid and matches.
 */
const isValidStoredAuthCode = (storedAuthCode, client, redirectUri) => {
  return storedAuthCode &&
         storedAuthCode.clientId === client.id && // Use client.id for consistency
         client.redirectUris.includes(redirectUri) &&
         storedAuthCode.expiresAt > Date.now();
};

/**
 * Validates the required parameters for the OAuth Token Endpoint's Refresh Token Grant.
 * @param {Object} body - The request body parameters.
 * @returns {boolean} True if all required parameters are present.
 */
const isValidRefreshTokenRequest = (body) => {
  const { refresh_token, client_id } = body;
  return refresh_token && client_id;
};

/**
 * Validates a stored refresh token against client details and expiration.
 * @param {Object} storedRefreshToken - The refresh token retrieved from storage.
 * @param {string} clientId - The client ID from the request.
 * @returns {boolean} True if the stored token is valid and matches.
 */
const isValidStoredRefreshToken = (storedRefreshToken, clientId) => {
  return storedRefreshToken &&
         storedRefreshToken.expiresAt > Date.now() &&
         storedRefreshToken.clientId === clientId;
};

/**
 * Validates the required parameters for the OAuth Token Endpoint's Client Credentials Grant.
 * @param {Object} body - The request body parameters.
 * @returns {boolean} True if all required parameters are present.
 */
const isValidClientCredentialsRequest = (body) => {
  const { client_id, client_secret } = body;
  return client_id && client_secret;
};

/**
 * Validates a client's credentials.
 * @param {Object} client - The client retrieved from storage.
 * @param {string} clientSecret - The client secret from the request (plain text, will be hashed for comparison).
 * @returns {boolean} True if the client exists and the hashed secret matches.
 */
const isValidClientCredentials = (client, clientSecret) => {
  // Hash the provided clientSecret and compare it with the stored hash
  return client && client.secret === sha256(clientSecret);
};

/**
 * Generates a signed JWT access token.
 * @param {Object} payload - The payload to include in the JWT.
 * @param {string} expiresIn - Token expiration time (e.g., '1h', '30m', '7d').
 * @param {string} type - A custom type to identify the token's purpose (e.g., 'OAUTH', 'PAT', 'API_KEY', 'MOCK_LOGIN').
 * @param {string} privateKey - The RSA private key for signing.
 * @param {string} issuer - The issuer (iss) claim for the JWT.
 * @returns {string} The signed JWT string.
 */
const generateAccessToken = (payload, expiresIn, type, privateKey, issuer) => {
  // Add jti (JWT ID) claim for potential revocation
  const jti = crypto.randomBytes(16).toString('hex');
  const tokenPayload = { ...payload, jti, iss: issuer, type }; // Add issuer and type claim
  return jwt.sign(tokenPayload, privateKey, { algorithm: 'RS256', expiresIn });
};

/**
 * Generates a cryptographically secure random string for refresh token or authorization code.
 * @returns {string} A random hex string.
 */
const generateSecureTokenString = () => crypto.randomBytes(32).toString('hex');

/**
 * Generates a PKCE code challenge from a code verifier (S256 method).
 * @param {string} verifier - The code verifier string.
 * @returns {string} The base64url encoded SHA256 hash of the verifier.
 */
const generateCodeChallenge = (verifier) => {
  const sha256Hash = crypto.createHash('sha256').update(verifier).digest();
  return sha256Hash.toString('base64url');
};

/**
 * Calculates a SHA256 hash in hex format.
 * Used for password hashing.
 * @param {string} input - The input string.
 * @returns {string} The SHA256 hash in hex format.
 */
const sha256 = (input) => crypto.createHash('sha256').update(input).digest('hex');

module.exports = {
  isInvalidOrExpiredTokenError,
  authHasRequiredRole,
  isValidAuthCodeRequest,
  isValidAuthCodeTokenRequest,
  isValidStoredAuthCode,
  isValidRefreshTokenRequest,
  isValidStoredRefreshToken,
  isValidClientCredentialsRequest,
  isValidClientCredentials,
  generateAccessToken,
  generateSecureTokenString,
  generateCodeChallenge,
  sha256
};