// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bodyParser = require('body-parser');

// Import helper functions
const {
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
} = require('./utils/authHelpers');

const app = express();
const port = 3000;

// JWT Signing Algorithm: RS256
//
// Instructions for generating private.pem and public.pem:
// Open a terminal and run the following commands in the root directory of this project:
// a) Generate a private key (2048-bit RSA key):
//    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
// b) Extract the public key from the private key:
//    openssl rsa -pubout -in private.pem -out public.pem
// Ensure these two files (private.pem, public.pem) are in the same directory as server.js.
try {
  const privateKeyPath = path.join(__dirname, 'private.pem');
  const publicKeyPath = path.join(__dirname, 'public.pem');

  if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
    console.warn('WARNING: private.pem or public.pem not found. Please generate them using the OpenSSL commands in the comments.');
    console.warn('Application will start, but token signing/verification will fail until keys are present.');
  }

  app.locals.privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  app.locals.publicKey = fs.readFileSync(publicKeyPath, 'utf8');

} catch (error) {
  console.error('Error loading private/public keys:', error.message);
  console.error('Please ensure private.pem and public.pem exist in the root directory.');
  return process.exit(1); // Exit if keys are critical for startup
}

// The issuer (iss) claim identifies the principal that issued the JWT.
// In a production environment, this would typically be your authentication server's domain.
// For local development, it defaults to the local server address.
// To set this, use: export JWT_ISSUER="https://your.auth.domain.com"
const JWT_ISSUER = process.env.JWT_ISSUER || `http://localhost:${port}`;

// JWT Token Types
// Using an object with Object.freeze() to create an immutable enum-like structure
const TOKEN_TYPES = Object.freeze({
  MOCK_LOGIN: 'MOCK_LOGIN',
  OAUTH: 'OAUTH',
  API_KEY: 'API_KEY',
  PAT: 'PAT',
});

// Data Stores (will reset when the server restarts)
//
// - users: User accounts ({ id, username, passwordHash, roles })
// - clients: Client applications ({ id, secret, redirectUris, scope })
// - authorizationCodes: Temporary OAuth authorization codes
//   ({ code, clientId, userId, redirectUri, codeChallenge, codeChallengeMethod, scopes, expiresAt })
// - refreshTokens: OAuth refresh tokens
//   ({ token, userId, clientId, scopes, expiresAt })
// - personalAccessTokens: Personal Access Tokens (PATs) for revocation tracking
//   ({ jti, userId, scopes, expiresAt })
const users = new Map();
const clients = new Map();
const authorizationCodes = new Map();
const refreshTokens = new Map();
const personalAccessTokens = new Map();

app.use(bodyParser.json()); // To parse JSON request bodies
app.use(bodyParser.urlencoded({ extended: true })); // To parse URL-encoded request bodies
app.use(express.static(path.join(__dirname, 'public'))); // Serve static HTML files from the 'public' directory

// Middleware

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'unauthorized',
      message: 'No bearer token provided.'
    });
  }

  const token = authHeader.split(' ')[1]; // Extract the token part

  jwt.verify(token, app.locals.publicKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      console.error("JWT verification error:", err.message);
      // Specific error messages for clarity
      if (isInvalidOrExpiredTokenError(err)) {
        const errorMessage = err.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token signature or malformed token.';
        return res.status(401).json({ error: 'unauthorized', message: errorMessage });
      }
      return res.status(401).json({
        error: 'unauthorized', 
        message: 'Invalid token.'
      });
    }
    // Check for PAT revocation (if jti exists and is in blacklist/not in active map)
    if (decoded.type === TOKEN_TYPES.PAT && decoded.jti && !personalAccessTokens.has(decoded.jti)) {
      console.log(`Attempt to use revoked PAT: ${decoded.jti}`);
      return res.status(401).json({ 
        error: 'unauthorized', 
        message: 'Personal Access Token has been revoked.'
      });
    }

    req.auth = decoded;
    return next();
  });
};

const authorizeRole = (requiredRole) => (req, res, next) => {
  // Ensure req.auth and req.auth.roles exist before checking
  if (!authHasRequiredRole(req.auth, requiredRole)) {
    return res.status(403).json({
      error: 'forbidden',
      message: `Requires '${requiredRole}' role.`
    });
  }
  return next();
};

// In-Memory Data Initialization (Hardcoded for Demo)

users.set('testuser', { 
  id: 'user1',
  username: 'testuser', 
  passwordHash: sha256('password123'), 
  roles: ['user']
});
users.set('adminuser', { 
  id: 'user2',
  username: 'adminuser',
  passwordHash: sha256('adminpass'),
  roles: ['user', 'admin']
});

clients.set('web-client-1', {
  id: 'web-client-1',
  secret: sha256('web-client-secret-1'), // Hashed secret
  redirectUris: ['http://localhost:8080/oauth/callback/', 'http://localhost:8080/oauth/alt-callback/'], // Now an array
  scopes: ['profile', 'read:data', 'write:data'],
});
clients.set('cli-client-1', {
  id: 'cli-client-1',
  secret: null, // This is a public client, secret is not used in PKCE flow
  redirectUris: ['http://localhost:8080/cli/callback/'],
  scopes: ['profile', 'read:data'],
});
clients.set('internal-service-client', {
  id: 'internal-service-client',
  secret: sha256('its-a-secret'), // Hashed secret
  redirectUris: [], // M2M clients typically don't have redirect URIs
  scopes: ['read:internal', 'write:internal'],
});


// API Endpoints

app.get('/api/data/public', (req, res) => {
  return res.json({ message: 'This is public data. Anyone can access it!' });
});

app.get('/api/data/protected', authenticateJWT, (req, res) => {
  return res.json({
    message: 'This is protected data!',
    data: `Accessed by ${req.auth.sub || req.auth.clientId} (sub or clientId from token)`,
    tokenInfo: req.auth // Echoes the decoded JWT payload
  });
});

app.get('/api/data/admin', authenticateJWT, authorizeRole('admin'), (req, res) => {
  return res.json({
    message: 'Welcome, Admin! This is highly sensitive administrative data.',
    data: `Accessed by ${req.auth.sub} (user ID from token)`,
    tokenInfo: req.auth // Echoes the decoded JWT payload
  });
});

app.post('/api/pat/generate', authenticateJWT, (req, res) => {
  const userId = req.auth.sub; // Comes from the decoded JWT provided by `mock-login` (in the demo UI context).
  const { scope, expiresIn = '30d' } = req.body; // Default PAT validity is 30 days

  // Ensure an authentication context exists from the middleware
  if (!userId) {
    return res.status(401).json({
      error: 'unauthenticated_principal',
      message: 'An authenticated principal is required to generate PATs.'
    });
  }

  // PAT payload includes user ID as subject and a 'type' for differentiation.
  const patPayload = {
    sub: userId,
    type: TOKEN_TYPES.PAT,
    scopes: scope ? scope.split(' ') : [],
    roles: req.auth.roles
  };
  const patToken = generateAccessToken(
    patPayload,
    expiresIn,
    TOKEN_TYPES.PAT,
    app.locals.privateKey,
    JWT_ISSUER
  );

  // Store the PAT's jti (JWT ID) in our in-memory map for later revocation checks.
  const decodedPat = jwt.decode(patToken);
  if (decodedPat && decodedPat.jti) {
    personalAccessTokens.set(decodedPat.jti, {
      userId,
      scopes: patPayload.scopes,
      expiresAt: decodedPat.exp * 1000 // Convert JWT exp (seconds) to milliseconds
    });
  }

  return res.json({
    message: 'Personal Access Token generated successfully.', 
    pat: patToken
  });
});

app.delete('/api/pat/revoke/:patId', authenticateJWT, (req, res) => {
  const userId = req.auth.sub; // User ID of the currently authenticated principal
  const patIdToRevoke = req.params.patId; // The JTI (JWT ID) of the PAT to be revoked

  if (!userId) {
    return res.status(401).json({
      error: 'unauthenticated_principal',
      message: 'An authenticated principal is required to revoke PATs.'
    });
  }

  const patEntry = personalAccessTokens.get(patIdToRevoke);

  // Check if PAT exists and if it belongs to the requesting principal
  if (!patEntry) {
    return res.status(404).json({
      error: 'not_found',
      message: 'Personal Access Token not found.'
    });
  }

  // Prevent principals from revoking other principals' PATs
  if (patEntry.userId !== userId) {
    return res.status(403).json({ error: 'forbidden', message: 'You do not have permission to revoke this Personal Access Token.' });
  }

  // Remove the PAT from the active list, effectively revoking it
  personalAccessTokens.delete(patIdToRevoke);
  return res.json({
    message: `Personal Access Token with ID ${patIdToRevoke} revoked successfully.`
  });
});

// OAuth 2.0 Endpoints

app.get('/oauth/authorize', (req, res) => {
  const { query } = req;
  const { scope: requestedScopeString } = query; // Extract requested scope string

  // Validate required parameters for Authorization Code Grant with PKCE
  if (!isValidAuthCodeRequest(query)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing or invalid required parameters for Authorization Code Grant with PKCE.'
    });
  }

  // Validate client and redirect URI
  const client = clients.get(query.client_id);
  if (!client || !client.redirectUris.includes(query.redirect_uri)) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Invalid client_id or redirect_uri.'
    });
  }

  // Validate requested scopes against client's registered scopes
  const requestedScopes = requestedScopeString ? requestedScopeString.split(' ') : [];
  const invalidScopes = requestedScopes.filter(s => !client.scopes.includes(s));
  if (invalidScopes.length > 0) {
    return res.status(400).json({
      error: 'invalid_scope',
      error_description: `One or more requested scopes are invalid or not allowed for this client: ${invalidScopes.join(', ')}`
    });
  }

  // --- DEMO SIMPLIFICATION: Auto-approve for 'testuser' ---
  // In a real application, this would redirect the user to a login page if not authenticated,
  // and then to a consent page where the user explicitly grants permissions (scopes).
  // For this demo, we auto-authenticate 'testuser' and auto-approve the request.
  const userId = 'user1'; // Using 'testuser' for automatic demonstration
  const user = users.get(userId);
  if (!user) {
    return res.status(500).json({
      error: 'server_error',
      error_description: 'Demo user (user1) not found in in-memory store.'
    });
  }

  // Generate a unique, short-lived authorization code
  const authCode = generateSecureTokenString();
  const expiresAt = Date.now() + 5 * 60 * 1000; // Code valid for 5 minutes (300 seconds)

  // Store the authorization code with its associated details, including PKCE challenge
  // Store the exact redirect_uri and the *validated* scopes that were used in this request for later validation
  authorizationCodes.set(authCode, {
    clientId: query.client_id,
    userId: userId,
    redirectUri: query.redirect_uri, // Store the specific redirect_uri used
    codeChallenge: query.code_challenge,
    codeChallengeMethod: query.code_challenge_method,
    scopes: requestedScopes, // Store the VALIDATED requested scopes
    expiresAt: expiresAt
  });

  // Redirect the user's browser back to the client's registered redirect URI
  const redirectUrl = new URL(query.redirect_uri);
  redirectUrl.searchParams.append('code', authCode);
  if (query.state) {
    redirectUrl.searchParams.append('state', query.state); // Include the state parameter if provided
  }
  console.log(`Authorization success. Redirecting to client: ${redirectUrl.toString()}`);
  return res.redirect(redirectUrl.toString());
});

app.post('/oauth/token', (req, res) => {
  const { grant_type, client_id, client_secret, redirect_uri, code, code_verifier, refresh_token: requestedRefreshToken } = req.body;

  /*
   * Grant Type Explanations:
   *
   * grant_type === 'authorization_code':
   * Use Case: User-delegated authorization for web, mobile, and desktop applications.
   * This flow is particularly important for public clients (e.g., SPAs, mobile apps, CLIs)
   * that cannot securely store a client_secret.
   * Details: This flow utilizes PKCE (Proof Key for Code Exchange) for client authentication
   * at the token exchange. Instead of a static client_secret, the client generates a
   * disposable, single-use code_verifier/code_challenge pair for each authorization attempt.
   * The server validates this pair during the token exchange. It explicitly does NOT
   * require or use a traditional client_secret for the client at this token endpoint.
   *
   * grant_type === 'refresh_token':
   * Use Case: Obtaining a new access token without re-authentication when the current
   * access token expires. Improves user experience and security by allowing
   * short-lived access tokens.
   * Details: This flow relies on the validity of the refresh token itself and the client_id.
   * It does not require or use a client_secret in our implementation.
   *
   * grant_type === 'client_credentials':
   * Use Case: Machine-to-machine (M2M) communication, where a client application
   * accesses its own protected resources, not on behalf of an end-user.
   * Often used for API Key concepts.
   * Details: The client_secret is essential here. It's used to authenticate the
   * client application directly for M2M access.
   */
  if (grant_type === 'authorization_code') { // (with PKCE)
    // Used by web, CLI, and desktop applications for user-delegated access.
    if (!isValidAuthCodeTokenRequest(req.body)) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing parameters for authorization_code grant.' });
    }

    const client = clients.get(client_id);
    const storedAuthCode = authorizationCodes.get(code);

    // Invalidate the code immediately if it's invalid or expired to prevent replay attacks
    if (!isValidStoredAuthCode(storedAuthCode, client, redirect_uri)) {
      if (storedAuthCode) authorizationCodes.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid, expired, or previously used authorization code or redirect_uri mismatch.'
      });
    }

    // PKCE validation: Verify the code_verifier against the stored code_challenge
    // Invalidate the authorization code on PKCE mismatch for security
    const calculatedCodeChallenge = generateCodeChallenge(code_verifier);
    if (calculatedCodeChallenge !== storedAuthCode.codeChallenge) {
      authorizationCodes.delete(code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'PKCE code_verifier mismatch.'
      });
    }

    // Code consumed, remove it to ensure single-use
    authorizationCodes.delete(code);

    const user = users.get(storedAuthCode.userId);
    if (!user) {
      return res.status(500).json({
        error: 'server_error',
        error_description: 'User associated with authorization code not found.'
      });
    }

    const newAccessToken = generateAccessToken(
      { sub: user.id, roles: user.roles, scopes: storedAuthCode.scopes },
      '1h',
      TOKEN_TYPES.OAUTH,
      app.locals.privateKey,
      JWT_ISSUER
    );
    const newRefreshToken = generateSecureTokenString();

    // Store the new refresh token with its associated details
    refreshTokens.set(newRefreshToken, {
      userId: user.id,
      clientId: client_id,
      scopes: storedAuthCode.scopes,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // valid for 7 days
    });

    return res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 3600, // valid for 1 hour (in seconds)
      refresh_token: newRefreshToken,
      scope: storedAuthCode.scopes.join(' ') // Return granted scopes
    });
  }
  else if (grant_type === 'refresh_token') {
    // Used by applications to obtain a new access token without re-authentication.
    if (!isValidRefreshTokenRequest(req.body)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing refresh_token or client_id for refresh_token grant.'
      });
    }

    const storedRefreshToken = refreshTokens.get(requestedRefreshToken);

    // Validate refresh token and its expiration, and ensure it belongs to the requesting client
    // Invalidate the token if invalid or expired
    if (!isValidStoredRefreshToken(storedRefreshToken, client_id)) {
      if (storedRefreshToken) refreshTokens.delete(requestedRefreshToken);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired refresh token.'
      });
    }

    refreshTokens.delete(requestedRefreshToken); // Invalidate the old refresh token

    const user = users.get(storedRefreshToken.userId);
    if (!user) {
      return res.status(500).json({
        error: 'server_error',
        error_description: 'User associated with refresh token not found.'
      });
    }

    const newAccessToken = generateAccessToken(
      { sub: user.id, roles: user.roles, scopes: storedRefreshToken.scopes },
      '1h',
      TOKEN_TYPES.OAUTH,
      app.locals.privateKey,
      JWT_ISSUER
    );
    const newRefreshToken = generateSecureTokenString();

    // Store the new refresh token
    refreshTokens.set(newRefreshToken, {
      userId: user.id,
      clientId: client_id,
      scopes: storedRefreshToken.scopes,
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // valid for 7 days
    });

    return res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 3600, // valid for 1 hour
      refresh_token: newRefreshToken,
      scope: storedRefreshToken.scopes.join(' ') // Return granted scopes
    });
  }
  else if (grant_type === 'client_credentials') { // (for API Keys / M2M communication) ---
    // Used by applications or services to obtain a JWT access token directly, without user involvement.
    if (!isValidClientCredentialsRequest(req.body)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing client_id or client_secret for client_credentials grant.'
      });
    }

    // Validate client credentials
    const client = clients.get(client_id);
    if (!isValidClientCredentials(client, client_secret)) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials.'
      });
    }

    // Generate an access token for the client (representing the API Key concept).
    // The 'sub' claim will be the client's ID, indicating it's an application token.
    const newAccessToken = generateAccessToken(
      { sub: client.id, clientId: client.id, scopes: client.scopes },
      '24h',
      TOKEN_TYPES.API_KEY,
      app.locals.privateKey,
      JWT_ISSUER
    );
    return res.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 86400, // 24 hours (in seconds)
      scope: client.scopes.join(' ') // Return granted scopes
    });
  }
  else {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'The requested grant type is not supported.'
    });
  }
});

// Admin pages

app.get('/admin-panel', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'admin-panel.html'));
});

app.get('/admin/register-client', authenticateJWT, authorizeRole('admin'), (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'register-client.html'));
});

app.post('/admin/register-client', authenticateJWT, authorizeRole('admin'), (req, res) => {
  const { client_name, redirect_uris, scopes, client_type } = req.body;

  // Basic validation
  if (!client_name || !redirect_uris || !scopes || !client_type) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Missing required client registration fields.'
    });
  }

  if (!['public', 'confidential'].includes(client_type)) {
    return res.status(400).json({ 
      error: 'invalid_client_type',
      message: 'Client type must be "public" or "confidential".'
    });
  }

  const parsedRedirectUris = redirect_uris.split(/[\s,]+/).filter(uri => uri.length > 0);
  const parsedScopes = scopes.split(/[\s,]+/).filter(scope => scope.length > 0);

  if (parsedRedirectUris.length === 0) {
    return res.status(400).json({
      error: 'invalid_redirect_uris',
      message: 'At least one redirect URI is required.'
    });
  }

  if (parsedScopes.length === 0) {
    return res.status(400).json({
      error: 'invalid_scopes',
      message: 'At least one scope is required.'
    });
  }

  // Generate unique client ID
  const clientId = `client-${crypto.randomBytes(8).toString('hex')}`;
  let clientSecret = null;

  if (client_type === 'confidential') {
    clientSecret = crypto.randomBytes(16).toString('hex'); // Generate a plain-text secret
    clients.set(clientId, {
      id: clientId,
      secret: sha256(clientSecret), // Store hashed secret
      redirectUris: parsedRedirectUris,
      scopes: parsedScopes,
      name: client_name, // Store client name for display
      type: client_type
    });
  }
  else { // public client
    clients.set(clientId, {
      id: clientId,
      secret: null, // Public clients do not have a secret
      redirectUris: parsedRedirectUris, // Fixed typo here
      scopes: parsedScopes,
      name: client_name,
      type: client_type
    });
  }

  console.log(`New client registered: ${clientId}, Type: ${client_type}`);
  return res.status(201).json({
    message: 'Client registered successfully.',
    client_id: clientId,
    client_secret: clientSecret, // Only return if confidential, otherwise null
    client_type: client_type,
    redirect_uris: parsedRedirectUris,
    scopes: parsedScopes
  });
});

// Main pages

app.get('/', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/pat-management', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'pat-management.html'));
});

// Mock Login Endpoint for UI (for PAT generation demo on public/index.html)
// This is a simplified endpoint for the demo UI to simulate a user login
// and provide a short-lived user token, which can then be used to generate PATs.
// It is NOT part of the standard OAuth flow.
app.post('/mock-login', (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);

  // Verify user credentials
  if (user && user.passwordHash === sha256(password)) {
    // Generate a basic JWT for the 'logged-in' user.
    // This token is just for the context of managing PATs within the demo UI.
    const userJwt = generateAccessToken(
      { sub: user.id, roles: user.roles },
      '15m',
      TOKEN_TYPES.MOCK_LOGIN,
      app.locals.privateKey,
      JWT_ISSUER
    );
    return res.json({
      message: 'Mock login successful!',
      userToken: userJwt,
      userId: user.id
    });
  }
  else {
    return res.status(401).json({
      error: 'invalid_credentials',
      message: 'Invalid username or password.'
    });
  }
});

// Start the server and provide initial setup instructions.
app.listen(port, () => {
  console.log(`Unified JWT Authentication Demo API listening at http://localhost:${port}`);
  console.log(`
    --- Setup Instructions ---
    1. Ensure 'private.pem' and 'public.pem' are in the same directory as server.js.
       If they don't exist, generate them using OpenSSL commands in your terminal:
       - Generate a private key:
         openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
       - Extract the public key:
         openssl rsa -pubout -in private.pem -out public.pem
    2. Run the server: node server.js
    3. Visit http://localhost:${port} in your browser to start the demo.
    4. The mock-login uses 'testuser'/'password123' and 'adminuser'/'adminpass' for demo purposes.
    5. To set a custom issuer (e.g., for production): export JWT_ISSUER="https://your.auth.domain.com"
    `);
});