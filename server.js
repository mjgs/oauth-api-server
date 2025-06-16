const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const url = require('url');
const querystring = require('querystring');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-super-secret-refresh-key';

// In-memory data stores
const users = [
  {
    id: '1',
    username: 'john_doe',
    email: 'john@example.com',
    password: bcrypt.hashSync('password123', 10),
    name: 'John Doe'
  },
  {
    id: '2',
    username: 'jane_smith',
    email: 'jane@example.com',
    password: bcrypt.hashSync('password123', 10),
    name: 'Jane Smith'
  }
];

const books = [
  { id: '1', title: '1984', author: 'George Orwell', userId: '1' },
  { id: '2', title: 'To Kill a Mockingbird', author: 'Harper Lee', userId: '1' },
  { id: '3', title: 'Pride and Prejudice', author: 'Jane Austen', userId: '2' }
];

// OAuth 2.0 stores
const clients = new Map();
const authorizationCodes = new Map();
const accessTokens = new Map();
const refreshTokens = new Map();

// Available scopes
const SCOPES = {
  'read:profile': 'Read user profile',
  'write:profile': 'Write user profile',
  'read:books': 'Read books',
  'write:books': 'Write books'
};

// Helper Functions
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function validateScope(requestedScopes, clientScopes) {
  const requested = requestedScopes ? requestedScopes.split(' ') : [];
  const allowed = clientScopes || [];
  return requested.every(scope => allowed.includes(scope));
}

function hasScope(token, requiredScope) {
  const tokenData = accessTokens.get(token);
  if (!tokenData) return false;
  return tokenData.scopes.includes(requiredScope);
}

// Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  const tokenData = accessTokens.get(token);
  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = tokenData.user;
  req.scopes = tokenData.scopes;
  next();
}

function requireScope(scope) {
  return (req, res, next) => {
    if (!req.scopes || !req.scopes.includes(scope)) {
      return res.status(403).json({ error: `Insufficient scope. Required: ${scope}` });
    }
    next();
  };
}

// Client admin endpoints
app.get('/admin/clients', (req, res) => {
  // We only send the client IDs (keys of the map), not the secrets.
  const clientIds = Array.from(clients.keys());
  res.status(200).json(clientIds);
});

app.delete('/admin/clients/:clientId', (req, res) => {
  const clientIdToDelete = req.params.clientId;

  // Delete the client from the 'clients' Map
  const wasDeleted = clients.delete(clientIdToDelete);

  if (wasDeleted) {
    console.log(`Deleted credentials for Client ID: ${clientIdToDelete}`);
    res.status(204).send(); // No Content, successful deletion
  } else {
    console.log(`Client ID not found for deletion: ${clientIdToDelete}`);
    res.status(404).json({ message: 'Client ID not found.' });
  }
});

// Client Registration Endpoints
app.post('/oauth/clients', (req, res) => {
  const { name, redirectUris, scopes } = req.body;

  if (!name || !redirectUris || !Array.isArray(redirectUris)) {
    return res.status(400).json({ error: 'Invalid client registration' });
  }

  const clientId = uuidv4();
  const clientSecret = generateToken();

  const client = {
    id: clientId,
    secret: clientSecret,
    name,
    redirectUris,
    scopes: scopes || Object.keys(SCOPES),
    createdAt: new Date().toISOString()
  };

  clients.set(clientId, client);

  res.json({
    client_id: clientId,
    client_secret: clientSecret,
    name,
    redirect_uris: redirectUris,
    scopes: client.scopes
  });
});

app.get('/oauth/clients', (req, res) => {
  const clientList = Array.from(clients.values()).map(client => ({
    client_id: client.id,
    name: client.name,
    redirect_uris: client.redirectUris,
    scopes: client.scopes,
    created_at: client.createdAt
  }));
  res.json(clientList);
});

// OAuth 2.0 Authorization Endpoint
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  // Validate required parameters
  if (!client_id || !redirect_uri || response_type !== 'code') {
    return res.status(400).json({ error: 'Invalid authorization request' });
  }

  // Validate client
  const client = clients.get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'Invalid client' });
  }

  // Validate redirect URI
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid redirect URI' });
  }

  // Validate scopes
  if (!validateScope(scope, client.scopes)) {
    return res.status(400).json({ error: 'Invalid scope' });
  }

  // In a real app, you'd redirect to a login page
  // For demo purposes, we'll return a simple HTML form
  const scopeList = scope ? scope.split(' ') : [];

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Authorize Application</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 500px;
          margin: 50px auto;
          padding: 20px;
        }

        .form-group {
          margin-bottom: 15px;
        }

        label {
          display: block;
          margin-bottom: 5px;
        }

        input,
        button {
          padding: 8px;
          width: 100%;
        }

        button {
          background: #007bff;
          color: white;
          border: none;
          cursor: pointer;
        }

        button:hover {
          background: #0056b3;
        }

        .scopes {
          background: #f8f9fa;
          padding: 15px;
          border-radius: 5px;
        }
      </style>
    </head>
    <body>
      <h2>Authorize ${client.name}</h2>
      <p>This application is requesting access to your account.</p>

      <div class="scopes">
        <h3>Requested Permissions:</h3>
        <ul>
          ${scopeList.map(s => `<li>${SCOPES[s] || s}</li>`).join('')}
        </ul>
      </div>

      <form method="POST" action="/oauth/authorize">
        <input type="hidden" name="client_id" value="${client_id}">
        <input type="hidden" name="redirect_uri" value="${redirect_uri}">
        <input type="hidden" name="response_type" value="${response_type}">
        <input type="hidden" name="scope" value="${scope || ''}">
        <input type="hidden" name="state" value="${state || ''}">

        <div class="form-group">
          <label for="username">Username:</label>
          <input type="text" id="username" name="username" required>
        </div>

        <div class="form-group">
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" required>
        </div>

        <button type="submit" name="action" value="authorize">Authorize</button>
        <button type="submit" name="action" value="deny" style="background: #dc3545; margin-top: 10px;">Deny</button>
      </form>
    </body>
    </html>
  `);
});

// OAuth 2.0 Authorization POST Handler
app.post('/oauth/authorize', async (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, username, password, action } = req.body;

  if (action === 'deny') {
    const errorUrl = `${redirect_uri}?error=access_denied&state=${state || ''}`;
    return res.redirect(errorUrl);
  }

  // Authenticate user
  const user = users.find(u => u.username === username);
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).send('Invalid credentials');
  }

  // Generate authorization code
  const code = generateToken();
  const codeData = {
    clientId: client_id,
    userId: user.id,
    redirectUri: redirect_uri,
    scopes: scope ? scope.split(' ') : [],
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  };

  authorizationCodes.set(code, codeData);

  // Redirect with authorization code
  const redirectUrl = `${redirect_uri}?code=${code}&state=${state || ''}`;
  res.redirect(redirectUrl);
});

// OAuth 2.0 Token Endpoint
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
    // Validate client
    const client = clients.get(client_id);
    if (!client || client.secret !== client_secret) {
      return res.status(401).json({ error: 'Invalid client credentials' });
    }

    // Validate authorization code
    const codeData = authorizationCodes.get(code);
    if (!codeData || codeData.expiresAt < Date.now() || codeData.clientId !== client_id || codeData.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: 'Invalid authorization code' });
    }

    // Remove used code
    authorizationCodes.delete(code);

    // Get user
    const user = users.find(u => u.id === codeData.userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate tokens
    const accessToken = generateToken();
    const refreshTokenValue = generateToken();

    // Store tokens
    accessTokens.set(accessToken, {
      user: { id: user.id, username: user.username, email: user.email, name: user.name },
      scopes: codeData.scopes,
      expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
    });

    refreshTokens.set(refreshTokenValue, {
      userId: user.id,
      clientId: client_id,
      scopes: codeData.scopes,
      expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshTokenValue,
      scope: codeData.scopes.join(' ')
    });

  } else if (grant_type === 'refresh_token') {
    const refreshData = refreshTokens.get(refresh_token);
    if (!refreshData || refreshData.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Invalid refresh token' });
    }

    // Validate client
    const client = clients.get(client_id);
    if (!client || client.secret !== client_secret || refreshData.clientId !== client_id) {
      return res.status(401).json({ error: 'Invalid client credentials' });
    }

    // Get user
    const user = users.find(u => u.id === refreshData.userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Generate new access token
    const accessToken = generateToken();
    accessTokens.set(accessToken, {
      user: { id: user.id, username: user.username, email: user.email, name: user.name },
      scopes: refreshData.scopes,
      expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: refreshData.scopes.join(' ')
    });

  } else {
    res.status(400).json({ error: 'Unsupported grant type' });
  }
});

// OAuth 2.0 Token Introspection Endpoint
app.post('/oauth/introspect', (req, res) => {
  const { token } = req.body;

  const tokenData = accessTokens.get(token);
  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.json({ active: false });
  }

  res.json({
    active: true,
    client_id: 'unknown', // We'd need to track this
    username: tokenData.user.username,
    scope: tokenData.scopes.join(' '),
    exp: Math.floor(tokenData.expiresAt / 1000),
    sub: tokenData.user.id
  });
});

// Users API
app.get('/api/users', (req, res) => {
  const publicUsers = users.map(u => ({
    id: u.id,
    username: u.username,
    name: u.name
  }));
  res.json(publicUsers);
});

app.get('/api/users/:id', (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    username: user.username,
    name: user.name,
    email: user.email
  });
});

app.get('/api/me', authenticateToken, requireScope('read:profile'), (req, res) => {
  res.json(req.user);
});

app.put('/api/me', authenticateToken, requireScope('write:profile'), (req, res) => {
  const { name, email } = req.body;
  const user = users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (name) user.name = name;
  if (email) user.email = email;

  res.json({
    id: user.id,
    username: user.username,
    name: user.name,
    email: user.email
  });
});

// Books API
app.get('/api/books', (req, res) => {
  res.json(books);
});

app.get('/api/books/:id', (req, res) => {
  const book = books.find(b => b.id === req.params.id);
  if (!book) {
    return res.status(404).json({ error: 'Book not found' });
  }
  res.json(book);
});

app.get('/api/my-books', authenticateToken, requireScope('read:books'), (req, res) => {
  const userBooks = books.filter(b => b.userId === req.user.id);
  res.json(userBooks);
});

app.post('/api/books', authenticateToken, requireScope('write:books'), (req, res) => {
  const { title, author } = req.body;

  if (!title || !author) {
    return res.status(400).json({ error: 'Title and author are required' });
  }

  const book = {
    id: (books.length + 1).toString(),
    title,
    author,
    userId: req.user.id
  };

  books.push(book);
  res.status(201).json(book);
});

app.put('/api/books/:id', authenticateToken, requireScope('write:books'), (req, res) => {
  const bookIndex = books.findIndex(b => b.id === req.params.id);

  if (bookIndex === -1) {
    return res.status(404).json({ error: 'Book not found' });
  }

  // Users can only edit their own books
  if (books[bookIndex].userId !== req.user.id) {
    return res.status(403).json({ error: 'Not authorized to edit this book' });
  }

  const { title, author } = req.body;
  if (title) books[bookIndex].title = title;
  if (author) books[bookIndex].author = author;

  res.json(books[bookIndex]);
});

app.delete('/api/books/:id', authenticateToken, requireScope('write:books'), (req, res) => {
  const bookIndex = books.findIndex(b => b.id === req.params.id);

  if (bookIndex === -1) {
    return res.status(404).json({ error: 'Book not found' });
  }

  // Users can only delete their own books
  if (books[bookIndex].userId !== req.user.id) {
    return res.status(403).json({ error: 'Not authorized to delete this book' });
  }

  books.splice(bookIndex, 1);
  res.status(204).send();
});

// Admin interface for client registration
app.get('/admin', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>OAuth Client Credentials Manager</title>
      <!-- Tailwind CSS for styling -->
      <script src="https://cdn.tailwindcss.com"></script>
      <style>
        /* Custom styles for Inter font */
        body {
          font-family: "Inter", sans-serif;
        }
        /* Hide the success message after some time */
        .fade-out {
          opacity: 0;
          transition: opacity 0.5s ease-out;
        }
        /* Custom modal styles */
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.6);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
        }
        .modal-content {
          background: white;
          padding: 2rem;
          border-radius: 0.75rem;
          box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
          width: 90%;
          max-width: 400px;
          text-align: center;
        }
      </style>
    </head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
      <div class="bg-white rounded-lg shadow-xl p-8 w-full max-w-2xl">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 text-center">OAuth Client Credentials</h1>

        <!-- Generate Credentials Section -->
        <div class="mb-8 p-6 bg-blue-50 rounded-lg border border-blue-200">
          <h2 class="text-2xl font-semibold text-blue-800 mb-4">Generate New Credentials</h2>
          <p class="text-gray-700 mb-4">Enter client details below to generate new credentials.</p>

          <div class="mb-4">
            <label for="clientNameInput" class="block text-sm font-medium text-gray-700 mb-1">Client Name:</label>
            <input type="text" id="clientNameInput" placeholder="e.g., My Web App" class="w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
          </div>

          <div class="mb-6">
            <label for="redirectUrisInput" class="block text-sm font-medium text-gray-700 mb-1">Redirect URIs (comma-separated):</label>
            <textarea id="redirectUrisInput" rows="3" placeholder="e.g., https://myapp.com/callback, http://localhost:3000/auth" class="w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
          </div>

          <button id="generateCredsBtn" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 w-full">
            Generate Credentials
          </button>
        </div>

        <!-- Display Generated Credentials Section -->
        <div id="generatedCredsDisplay" class="mb-8 p-6 bg-green-50 rounded-lg border border-green-200 hidden">
          <h2 class="text-2xl font-semibold text-green-800 mb-4">Your New Credentials</h2>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label for="clientId" class="block text-sm font-medium text-gray-700 mb-1">Client ID:</label>
              <div class="flex items-center">
                <input type="text" id="clientId" readonly class="flex-grow p-2 border border-gray-300 rounded-md bg-gray-50 text-gray-800 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-green-500 mr-2">
                <button onclick="copyToClipboard('clientId')" class="bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 px-3 rounded-md text-sm font-medium transition duration-150">Copy</button>
              </div>
            </div>
            <div>
              <label for="clientSecret" class="block text-sm font-medium text-gray-700 mb-1">Client Secret:</label>
              <div class="flex items-center">
                <input type="text" id="clientSecret" readonly class="flex-grow p-2 border border-gray-300 rounded-md bg-gray-50 text-gray-800 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-green-500 mr-2">
                <button onclick="copyToClipboard('clientSecret')" class="bg-gray-200 hover:bg-gray-300 text-gray-700 py-2 px-3 rounded-md text-sm font-medium transition duration-150">Copy</button>
              </div>
            </div>
          </div>
          <div id="copySuccessMessage" class="text-green-600 text-sm mt-3 hidden">
            <span class="font-semibold">&#10003; Copied to clipboard!</span>
          </div>
        </div>

        <!-- List All Credentials Section -->
        <div class="p-6 bg-purple-50 rounded-lg border border-purple-200">
          <h2 class="text-2xl font-semibold text-purple-800 mb-4">Existing Credentials</h2>
          <p class="text-gray-700 mb-4">Below is a list of all Client IDs you have generated. Client Secrets are not displayed for security reasons.</p>
          <ul id="credentialsList" class="space-y-3">
            <!-- Credentials will be loaded here by JavaScript -->
          </ul>
          <p id="noCredsMessage" class="text-gray-500 text-center mt-4 hidden">No credentials generated yet.</p>
        </div>
      </div>

      <!-- Custom Confirmation Modal -->
      <div id="confirmationModal" class="modal-overlay hidden">
        <div class="modal-content">
          <p id="modalMessage" class="text-gray-800 text-lg mb-6"></p>
          <div class="flex justify-center space-x-4">
            <button id="confirmDeleteBtn" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-300">Delete</button>
            <button id="cancelDeleteBtn" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg shadow-md transition duration-300">Cancel</button>
          </div>
        </div>
      </div>

      <script>
        document.addEventListener('DOMContentLoaded', () => {
          const generateCredsBtn = document.getElementById('generateCredsBtn');
          const clientNameInput = document.getElementById('clientNameInput');
          const redirectUrisInput = document.getElementById('redirectUrisInput');
          const generatedCredsDisplay = document.getElementById('generatedCredsDisplay');
          const clientIdInput = document.getElementById('clientId');
          const clientSecretInput = document.getElementById('clientSecret');
          const credentialsList = document.getElementById('credentialsList');
          const noCredsMessage = document.getElementById('noCredsMessage');
          const copySuccessMessage = document.getElementById('copySuccessMessage');

          // Modal elements
          const confirmationModal = document.getElementById('confirmationModal');
          const modalMessage = document.getElementById('modalMessage');
          const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
          const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');

          let currentClientIdToDelete = null; // To hold the ID of the credential being considered for deletion

          // Function to show the custom confirmation modal
          function showConfirmationModal(message, clientId) {
            modalMessage.textContent = message;
            currentClientIdToDelete = clientId;
            confirmationModal.classList.remove('hidden');
          }

          // Function to hide the custom confirmation modal
          function hideConfirmationModal() {
            confirmationModal.classList.add('hidden');
            currentClientIdToDelete = null;
          }

          // Event listener for confirm button in modal
          confirmDeleteBtn.addEventListener('click', async () => {
            if (currentClientIdToDelete) {
              try {
                // Now using the new /admin/clients endpoint for deletion
                const response = await fetch(\`/admin/clients/\${currentClientIdToDelete}\`, {
                  method: 'DELETE'
                });

                if (response.ok) {
                  console.log('Credential deleted successfully on server.');
                  await fetchAndDisplayCredentials(); // Refresh the list
                } else if (response.status === 404) {
                  console.error('Credential not found on server.');
                  alert('Error: Credential not found.');
                } else {
                  console.error('Failed to delete credential on server.');
                  alert('Error: Failed to delete credential. Please try again.');
                }
              } catch (error) {
                console.error('Network error while deleting credential:', error);
                alert('Network error: Could not connect to the server.');
              } finally {
                hideConfirmationModal();
              }
            }
          });

          // Event listener for cancel button in modal
          cancelDeleteBtn.addEventListener('click', hideConfirmationModal);

          // Function to add a credential ID to the list
          function addCredentialToList(credId) {
            const listItem = document.createElement('li');
            listItem.className = 'bg-white p-3 rounded-md shadow-sm flex justify-between items-center border border-gray-200';
            listItem.innerHTML = \`
              <span class="font-mono text-gray-800 text-sm break-all">\${credId}</span>
              <button onclick="window.deleteCred('\${credId}')" class="text-red-500 hover:text-red-700 text-sm font-medium ml-4 shrink-0">Delete</button>
            \`;
            credentialsList.prepend(listItem); // Add to the top of the list
          }

          // Function to initiate deletion (called from onclick)
          window.deleteCred = function(credIdToDelete) {
            showConfirmationModal(\`Are you sure you want to delete credentials for: \${credIdToDelete}?\`, credIdToDelete);
          };

          // Function to update the visibility of the "No credentials" message
          function updateNoCredsMessage() {
            if (credentialsList.children.length === 0) {
              noCredsMessage.classList.remove('hidden');
            } else {
              noCredsMessage.classList.add('hidden');
            }
          }

          // Function to fetch and display all existing credentials
          async function fetchAndDisplayCredentials() {
            credentialsList.innerHTML = ''; // Clear current list
            try {
              // Now using the new /admin/clients endpoint for listing
              const response = await fetch('/admin/clients');
              if (!response.ok) {
                throw new Error(\`HTTP error! status: \${response.status}\`);
              }
              const data = await response.json(); // Expects an array of client IDs
              if (data.length > 0) {
                data.forEach(credId => addCredentialToList(credId));
              }
            } catch (error) {
              console.error('Error fetching credentials:', error);
              // Optionally display an error message to the user
            } finally {
              updateNoCredsMessage();
            }
          }

          // Fetch and display credentials on initial load
          fetchAndDisplayCredentials();

          // Event listener for the "Generate Credentials" button
          generateCredsBtn.addEventListener('click', async () => {
            const clientName = clientNameInput.value.trim();
            const redirectUrisString = redirectUrisInput.value.trim();
            const redirectUris = redirectUrisString ? redirectUrisString.split(',').map(uri => uri.trim()) : [];

            if (!clientName) {
              alert('Please enter a Client Name.');
              return;
            }

            try {
              // NOW HITTING YOUR EXISTING /oauth/clients endpoint for creation
              const response = await fetch('/oauth/clients', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                  name: clientName,
                  redirectUris: redirectUris
                })
              });

              if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
                throw new Error(\`HTTP error! status: \${response.status}, message: \${errorData.message || response.statusText}\`);
              }
              const data = await response.json(); 

              // Display the generated credentials
              // CRUCIAL CHANGE: Use data.client_id and data.client_secret
              clientIdInput.value = data.client_id;
              clientSecretInput.value = data.client_secret;
              generatedCredsDisplay.classList.remove('hidden');

              // Clear the input fields after successful generation
              clientNameInput.value = '';
              redirectUrisInput.value = '';

              // Refresh the list to include the newly generated credential
              await fetchAndDisplayCredentials();

              // Scroll to the top of the generated credentials display section for visibility
              generatedCredsDisplay.scrollIntoView({ behavior: 'smooth', block: 'start' });

            } catch (error) {
              console.error('Error generating credentials:', error);
              alert('Failed to generate credentials. Please try again. Error: ' + error.message);
            }
          });

          // Global function to copy text to clipboard
          window.copyToClipboard = function(elementId) {
            const element = document.getElementById(elementId);
            if (element) {
              element.select(); // Select the text in the input field
              element.setSelectionRange(0, 99999); // For mobile devices

              try {
                document.execCommand('copy'); // Execute the copy command
                copySuccessMessage.classList.remove('hidden');
                copySuccessMessage.classList.remove('fade-out'); // Ensure it's fully visible
                setTimeout(() => {
                  copySuccessMessage.classList.add('fade-out');
                  setTimeout(() => {
                    copySuccessMessage.classList.add('hidden'); // Hide after fade out
                  }, 500); // Match fade-out transition duration
                }, 2000); // Show message for 2 seconds
              } catch (err) {
                console.error('Failed to copy text: ', err);
                // Fallback: You could notify the user to copy manually
              }
            }
          };
        });
      </script>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`OAuth API Server running on port ${PORT}`);
  console.log(`Admin interface: http://localhost:${PORT}/admin`);
  console.log(`\nSample users:`);
  console.log(`- Username: john_doe, Password: password123`);
  console.log(`- Username: jane_smith, Password: password123`);
});