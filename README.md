# BullHorn Mock Server

A Node.js mock server that mimics the **actual Bullhorn REST API** authentication flow and endpoints for testing and development purposes. This server follows the official [Bullhorn REST API documentation](https://bullhorn.github.io/Getting-Started-with-REST/).

## Features

- **Complete OAuth 2.0 Flow**: Implements Bullhorn's actual OAuth 2.0 authorization code flow
- **Login Info Endpoint**: Data center discovery endpoint (`/rest-services/loginInfo`)
- **REST API Login**: BullHorn REST API login with BhRestToken and corpToken
- **Entity Management**: CRUD operations for Candidates, JobOrders, and ClientCorporations
- **Search & Query**: Search and query endpoints with filtering
- **Token Management**: Proper token expiration and refresh token rotation
- **Sample Data**: Pre-populated with sample candidates, jobs, and clients

## Installation

1. Clone the repository:
```bash
cd /path/to/bullHorn-server
```

2. Install dependencies:
```bash
npm install
```

3. Copy environment file:
```bash
cp env.example .env
```

4. Start the server:
```bash
npm start
```

For development with auto-restart:
```bash
npm run dev
```

## Bullhorn OAuth Authentication Flow

This server implements the **exact same authentication flow** that the real Bullhorn API uses:

### Step 1: Get Login Info (Determine Data Center)

First, determine the correct data center URLs for the user:

```bash
GET /rest-services/loginInfo?username={API_Username}
```

**Response:**
```json
{
  "oauthUrl": "http://localhost:3000/oauth",
  "restUrl": "http://localhost:3000/rest-services/",
  "username": "bullhorn_user",
  "dataCenter": "east"
}
```

### Step 2: Get Authorization Code

Get an authorization code by authenticating:

```bash
GET /oauth/authorize?client_id={client_id}&response_type=code&action=Login&username={username}&password={password}&redirect_uri={redirect_uri}&state={state}
```

This redirects to your `redirect_uri` with:
- `code`: The authorization code
- `state`: The state value you provided (for CSRF protection)

### Step 3: Exchange Authorization Code for Access Token

```bash
POST /oauth/token?grant_type=authorization_code&code={auth_code}&client_id={client_id}&client_secret={client_secret}&redirect_uri={redirect_uri}
```

**Response:**
```json
{
  "access_token": "at_abc123...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "rt_xyz789..."
}
```

> **Note:** Access tokens are valid for **10 minutes** (matching Bullhorn's actual behavior).

### Step 4: Use Refresh Token (When Access Token Expires)

```bash
POST /oauth/token?grant_type=refresh_token&refresh_token={refresh_token}&client_id={client_id}&client_secret={client_secret}
```

**Response:**
```json
{
  "access_token": "at_newtoken...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "rt_newrefresh..."
}
```

> **Note:** Bullhorn returns a **new refresh token** with every token refresh. The old refresh token is invalidated.

### Step 5: Login to REST API

```bash
POST /rest-services/login?version=*&access_token={access_token}
```

**Response:**
```json
{
  "BhRestToken": "1_1234567890_abc123...",
  "restUrl": "http://localhost:3000/rest-services/ABC123XY/"
}
```

> **Important:** Do NOT login before every API request. Reuse the `BhRestToken` until it expires (returns 401), then refresh your access token and login again.

### Step 6: Make REST API Calls

Use the `restUrl` from the login response and include `BhRestToken` as a query parameter:

```bash
GET {restUrl}entity/Candidate/123?BhRestToken={BhRestToken}&fields=firstName,lastName,address
```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/rest-services/loginInfo` | Get data center URLs |
| GET | `/oauth/authorize` | Get authorization code |
| POST | `/oauth/token` | Get/refresh access token |
| POST | `/rest-services/login` | Get BhRestToken |

### REST API Endpoints

All REST endpoints require `BhRestToken` query parameter and use the pattern:
`/rest-services/{corpToken}/...?BhRestToken={token}`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/rest-services/{corpToken}/entity/{entityType}` | Get all entities |
| GET | `/rest-services/{corpToken}/entity/{entityType}/{id}` | Get entity by ID |
| PUT | `/rest-services/{corpToken}/entity/{entityType}` | Create entity |
| POST | `/rest-services/{corpToken}/entity/{entityType}/{id}` | Update entity |
| DELETE | `/rest-services/{corpToken}/entity/{entityType}/{id}` | Delete entity |
| GET | `/rest-services/{corpToken}/search/{entityType}` | Search entities |
| GET | `/rest-services/{corpToken}/query/{entityType}` | Query entities |

### Supported Entity Types

- `Candidate`
- `JobOrder`
- `ClientCorporation`

### Health Check

```bash
GET /health
```

## Test Credentials

Default test credentials (can be changed via environment variables):

| Parameter | Value |
|-----------|-------|
| client_id | `bullhorn_client_123` |
| client_secret | `bullhorn_client_secret_123` |
| username | `bullhorn_user` |
| password | `bullhorn_pass_456` |

## API Testing Examples

### Complete Authentication Flow

```bash
# Step 1: Get login info
curl "http://localhost:3000/rest-services/loginInfo?username=bullhorn_user"

# Step 2: Get authorization code (this will redirect)
# Open in browser or follow redirect:
curl -L "http://localhost:3000/oauth/authorize?client_id=bullhorn_client_123&response_type=code&action=Login&username=bullhorn_user&password=bullhorn_pass_456&redirect_uri=https://staging.integrator.io/connection/oauth2callback&state=mystate123"

# Step 3: Exchange code for access token
curl -X POST "http://localhost:3000/oauth/token?grant_type=authorization_code&code={AUTH_CODE}&client_id=bullhorn_client_123&client_secret=bullhorn_client_secret_123"

# Step 4: Login to REST API
curl -X POST "http://localhost:3000/rest-services/login?version=*&access_token={ACCESS_TOKEN}"

# Step 5: Make REST calls
curl "http://localhost:3000/rest-services/{corpToken}/entity/Candidate?BhRestToken={BH_REST_TOKEN}&fields=firstName,lastName,email"
```

### Get Entity by ID

```bash
curl "http://localhost:3000/rest-services/{corpToken}/entity/Candidate/1?BhRestToken={token}&fields=firstName,lastName,address"
```

**Response:**
```json
{
  "data": {
  "firstName": "John",
  "lastName": "Doe",
    "address": {
      "address1": "123 Main St",
      "city": "Boston",
      "state": "MA",
      "zip": "02110",
      "countryID": 1
    }
  }
}
```

### Create Entity (PUT)

```bash
curl -X PUT "http://localhost:3000/rest-services/{corpToken}/entity/Candidate?BhRestToken={token}" \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Alice",
    "lastName": "Johnson",
    "name": "Alice Johnson",
    "email": "alice.johnson@example.com",
    "category": { "id": 1 }
  }'
```

**Response:**
```json
{
  "changedEntityType": "Candidate",
  "changedEntityId": 3,
  "changeType": "INSERT",
  "data": { ... }
}
```

### Update Entity (POST)

```bash
curl -X POST "http://localhost:3000/rest-services/{corpToken}/entity/Candidate/1?BhRestToken={token}" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.updated@example.com"
  }'
```

### Search Entities

```bash
curl "http://localhost:3000/rest-services/{corpToken}/search/Candidate?BhRestToken={token}&query=john&count=10"
```

### Refresh Token Flow

When your access token expires (401 response):

```bash
# Get new access token using refresh token
curl -X POST "http://localhost:3000/oauth/token?grant_type=refresh_token&refresh_token={REFRESH_TOKEN}&client_id=bullhorn_client_123&client_secret=bullhorn_client_secret_123"

# Login again with new access token
curl -X POST "http://localhost:3000/rest-services/login?version=*&access_token={NEW_ACCESS_TOKEN}"
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Server port | 3000 |
| OAUTH_CLIENT_ID | OAuth client ID | bullhorn_client_123 |
| OAUTH_CLIENT_SECRET | OAuth client secret | bullhorn_client_secret_123 |
| OAUTH_USERNAME | Test username | bullhorn_user |
| OAUTH_PASSWORD | Test password | bullhorn_pass_456 |
| OAUTH_REDIRECT_URIS | Comma-separated list of allowed redirect URIs (required outside test mode) | *(none; must be provided for production)* |
| BULLHORN_TEST_MODE | Set to `true` to relax redirect checks (used by automated tests) | *(unset)* |

### Test vs. Production Modes

- **Test Mode (`BULLHORN_TEST_MODE=true`)**
  - `redirect_uri` is optional when calling `/oauth/authorize`
  - Any provided `redirect_uri` is accepted (logged with a warning if not in the allowed list)
  - Designed for automated/local workflows where interactive redirects are impractical

- **Production Mode (default when `BULLHORN_TEST_MODE` is unset/false)**
  - `redirect_uri` **must** be present on every `/oauth/authorize` call
  - The value must match one of the entries configured via `OAUTH_REDIRECT_URIS`
  - Missing or unregistered redirect URIs result in an `invalid_request` error, matching Bullhorn's enforcement

## Token Expiration

| Token Type | Expiration |
|------------|------------|
| Authorization Code | 5 minutes |
| Access Token | 10 minutes |
| Refresh Token | Never (replaced on each use) |
| BhRestToken | 10 minutes |

## Sample Data

The server comes pre-populated with sample data:

### Sample Candidates
- John Doe (john.doe@example.com) - Engineering
- Jane Smith (jane.smith@example.com) - Sales

### Sample JobOrders
- Senior Software Engineer (Tech Corp) - $150,000
- Product Manager (Startup Inc) - $130,000

### Sample ClientCorporations
- Tech Corp (San Francisco, CA)
- Startup Inc (Austin, TX)

## Testing

Run tests:
```bash
npm test
```

## Key Differences from Generic OAuth

1. **Login Info Endpoint**: Bullhorn requires you to first call `/rest-services/loginInfo` to get the correct data center URLs
2. **REST Login**: After getting an access token, you must call `/rest-services/login` to get a `BhRestToken` for API calls
3. **Refresh Token Rotation**: Bullhorn returns a **new refresh token** with every token refresh
4. **PUT for Create**: Bullhorn uses PUT (not POST) to create entities
5. **POST for Update**: Bullhorn uses POST (not PUT) to update entities
6. **BhRestToken**: API calls use `BhRestToken` query parameter, not Bearer token header
7. **Redirect Validation**: Outside of test mode the `redirect_uri` parameter must be supplied and match one of the configured `OAUTH_REDIRECT_URIS`.

## References

- [Bullhorn REST API Getting Started](https://bullhorn.github.io/Getting-Started-with-REST/)
- [Bullhorn REST API Reference](https://bullhorn.github.io/rest-api-docs/)

## License

MIT 
