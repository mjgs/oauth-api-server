# OAuth API Server - OAuth 2.0 Books API server Demo

A complete demonstration of OAuth 2.0 Authorization Code flow with a Books REST API server.

## Architecture

- **API Server (Port 3000)**: OAuth 2.0 Authorization Server + Books/Users REST API
- **Client App (Port 3001)**: Express app that acts as OAuth client with server-side credential handling (See [oauth-api-client](https://github.com/mjgs/oauth-api-client) repo)

## Features

### OAuth 2.0 Authorization Server
- ✅ Authorization Code flow with PKCE support
- ✅ Client registration and management
- ✅ Scope-based authorization (`read:profile`, `write:profile`, `read:books`, `write:books`)
- ✅ Access and refresh token management
- ✅ Token introspection endpoint
- ✅ Production-ready client credential system

### REST API
- ✅ Users CRUD operations
- ✅ Books CRUD operations (user-specific)
- ✅ Scope-based endpoint protection
- ✅ Public read endpoints, authenticated write endpoints

## Quick Start

### 1. Install Dependencies

**API Server:**
```bash
npm install
```

### 2. Start API Server
```bash
npm start
```
Server will run on http://localhost:3000

### 3. Register Client Application

1. Visit http://localhost:3000/admin
2. Register a new client with these details:
   - **Application Name**: Books Client App
   - **Redirect URI**: `http://localhost:3001/auth/callback`
   - **Scopes**: Select all available scopes
3. Save the generated `CLIENT_ID` and `CLIENT_SECRET`

### 4. Configure and Start Client App

See client repo [oauth-api-client](https://github.com/mjgs/oauth-api-client).

### 5. Test the Flow

1. Visit http://localhost:3001
2. Click "Login with OAuth"
3. Use sample credentials:
   - **Username**: `john_doe` or `jane_smith`
   - **Password**: `password123`
4. Authorize the application
5. Manage your profile and books!

## API Endpoints

### OAuth 2.0 Endpoints
- `POST /oauth/clients` - Register new client
- `GET /oauth/clients` - List registered clients
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/authorize` - Handle authorization
- `POST /oauth/token` - Token endpoint
- `POST /oauth/introspect` - Token introspection

### Users API
- `GET /api/users` - List all users (public)
- `GET /api/users/:id` - Get user by ID (public)
- `GET /api/me` - Get current user profile (requires `read:profile`)
- `PUT /api/me` - Update current user profile (requires `write:profile`)

### Books API
- `GET /api/books` - List all books (public)
- `GET /api/books/:id` - Get book by ID (public)
- `GET /api/my-books` - Get current user's books (requires `read:books`)
- `POST /api/books` - Create book (requires `write:books`)
- `PUT /api/books/:id` - Update book (requires `write:books`, own books only)
- `DELETE /api/books/:id` - Delete book (requires `write:books`, own books only)

## OAuth 2.0 Scopes

| Scope | Description |
|-------|-------------|
| `read:profile` | Read user profile information |
| `write:profile` | Modify user profile information |
| `read:books` | Read user's books |
| `write:books` | Create, update, delete user's books |

## Sample Users

| Username | Password | Name |
|----------|----------|------|
| `john_doe` | `password123` | John Doe |
| `jane_smith` | `password123` | Jane Smith |

## Security Features

- ✅ Server-side credential storage (client secrets never exposed to browser)
- ✅ CSRF protection with state parameter
- ✅ Token expiration and refresh
- ✅ Scope-based authorization
- ✅ User-specific data isolation
- ✅ Production-ready client registration system

## Development Notes

### Adding New Scopes
1. Add scope to `SCOPES` object in `server.js`
2. Update admin interface to include new scope
3. Add scope validation to relevant endpoints

### Extending the API
- Add new models to in-memory stores
- Create CRUD endpoints with appropriate scope requirements
- Update client UI to consume new endpoints

### Database Integration
The current implementation uses in-memory storage. To add database support:
1. Replace in-memory arrays with database models
2. Update CRUD operations to use database queries
3. Add proper error handling for database operations

## Production Considerations

- [ ] Use environment variables for secrets
- [ ] Implement database persistence
- [ ] Add rate limiting
- [ ] Add request logging
- [ ] Use HTTPS in production
- [ ] Implement proper session storage (Redis/database)
- [ ] Add input validation and sanitization
- [ ] Implement proper error handling and logging
- [ ] Add monitoring and health checks

## License

MIT License - Feel free to use this as a reference for your OAuth 2.0 implementations!