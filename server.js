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
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input, button { padding: 8px; width: 100%; }
            button { background: #007bff; color: white; border: none; cursor: pointer; }
            button:hover { background: #0056b3; }
            .scopes { background: #f8f9fa; padding: 15px; border-radius: 5px; }
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
    <html>
    <head>
        <title>OAuth Server Admin</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input, textarea, button { padding: 8px; width: 100%; }
            button { background: #007bff; color: white; border: none; cursor: pointer; }
            button:hover { background: #0056b3; }
            .client { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .scopes { display: flex; flex-wrap: wrap; gap: 10px; }
            .scope { display: flex; align-items: center; }
        </style>
    </head>
    <body>
        <h1>OAuth Server Administration</h1>
        
        <h2>Register New Client</h2>
        <form id="clientForm">
            <div class="form-group">
                <label for="name">Application Name:</label>
                <input type="text" id="name" name="name" required>
            </div>
            
            <div class="form-group">
                <label for="redirectUris">Redirect URIs (one per line):</label>
                <textarea id="redirectUris" name="redirectUris" rows="3" required placeholder="http://localhost:3001/auth/callback"></textarea>
            </div>
            
            <div class="form-group">
                <label>Scopes:</label>
                <div class="scopes">
                    ${Object.entries(SCOPES).map(([scope, desc]) => `
                        <div class="scope">
                            <input type="checkbox" id="${scope}" name="scopes" value="${scope}" checked>
                            <label for="${scope}">${desc}</label>
                        </div>
                    `).join('')}
                </div>
            </div>
            
            <button type="submit">Register Client</button>
        </form>

        <h2>Registered Clients</h2>
        <div id="clients"></div>

        <script>
            async function loadClients() {
                const response = await fetch('/oauth/clients');
                const clients = await response.json();
                const container = document.getElementById('clients');
                
                container.innerHTML = clients.map(client => \`
                    <div class="client">
                        <h3>\${client.name}</h3>
                        <p><strong>Client ID:</strong> \${client.client_id}</p>
                        <p><strong>Redirect URIs:</strong> \${client.redirect_uris.join(', ')}</p>
                        <p><strong>Scopes:</strong> \${client.scopes.join(', ')}</p>
                        <p><strong>Created:</strong> \${new Date(client.created_at).toLocaleString()}</p>
                    </div>
                \`).join('');
            }

            document.getElementById('clientForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const formData = new FormData(e.target);
                const scopes = Array.from(formData.getAll('scopes'));
                const redirectUris = formData.get('redirectUris').split('\\n').map(uri => uri.trim()).filter(uri => uri);
                
                const response = await fetch('/oauth/clients', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: formData.get('name'),
                        redirectUris,
                        scopes
                    })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    alert(\`Client registered successfully!\\n\\nClient ID: \${result.client_id}\\nClient Secret: \${result.client_secret}\\n\\nSave these credentials securely!\`);
                    e.target.reset();
                    loadClients();
                } else {
                    alert('Error: ' + result.error);
                }
            });

            loadClients();
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