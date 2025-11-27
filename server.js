const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const dotenv = require('dotenv');
const { v4: uuidv4 } = require('uuid');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// OAuth constants - These would be configured per application
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || 'bullhorn_client_123';
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || 'bullhorn_client_secret_123';
const OAUTH_USERNAME = process.env.OAUTH_USERNAME || 'bullhorn_user';
const OAUTH_PASSWORD = process.env.OAUTH_PASSWORD || 'bullhorn_pass_456';
const DEFAULT_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI || 'https://staging.integrator.io/connection/oauth2callback';

// Simulated data center configuration (like Bullhorn's multi-datacenter setup)
const DATA_CENTER = 'east'; // Simulates regional data center

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory data store (in production, use a real database)
const dataStore = {
  candidates: [],
  jobs: [],
  clients: [],
  users: [],
  authTokens: new Map(),
  bhRestTokens: new Map(), // stores { token: { expiresAt, corpToken, userId } }
  accessTokens: new Map(), // stores { token: { userId, expiresAt, refreshToken } }
  refreshTokens: new Map(), // stores { token: { userId, createdAt } }
  authorizationCodes: new Map(), // stores { code: { expiresAt, clientId, userId, redirectUri } }
  registeredRedirectUris: new Set([DEFAULT_REDIRECT_URI]), // Registered redirect URIs for the OAuth app
  debug: {
    refreshTokenCount: 0
  }
};

// Token generation functions
function generateAccessToken() {
  return 'at_' + uuidv4().replaceAll('-', '');
}

function generateRefreshToken() {
  return 'rt_' + uuidv4().replaceAll('-', '');
}

function generateAuthorizationCode() {
  return 'ac_' + uuidv4().replaceAll('-', '').substring(0, 16);
}

function generateBhRestToken() {
  // Format: {userId}_{timestamp}_{uuid}
  const timestamp = Date.now();
  const uuid = uuidv4().replaceAll('-', '').substring(0, 32);
  return `1_${timestamp}_${uuid}`;
}

function generateCorpToken() {
  // Generate a random alphanumeric corp token
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Token expiration constants (matching Bullhorn's behavior)
const ACCESS_TOKEN_EXPIRES_IN = 10 * 60 * 1000; // 10 minutes (Bullhorn access tokens are valid for 10 minutes)
const AUTHORIZATION_CODE_EXPIRES_IN = 5 * 60 * 1000; // 5 minutes
const BH_REST_TOKEN_EXPIRES_IN = 10 * 60 * 1000; // 10 minutes (session timeout)

// Token validation helper
function isTokenExpired(expiresAt) {
  return Date.now() > expiresAt;
}

// Cleanup expired tokens and authorization codes
function cleanupExpiredTokens() {
  // Clean up expired access tokens
  for (const [token, tokenData] of dataStore.accessTokens.entries()) {
    if (isTokenExpired(tokenData.expiresAt)) {
      dataStore.accessTokens.delete(token);
      dataStore.authTokens.delete(token);
    }
  }

  // Clean up expired authorization codes
  for (const [code, codeData] of dataStore.authorizationCodes.entries()) {
    if (isTokenExpired(codeData.expiresAt)) {
      dataStore.authorizationCodes.delete(code);
    }
  }

  // Clean up expired bhRestTokens
  for (const [bhToken, bhTokenData] of dataStore.bhRestTokens.entries()) {
    if (isTokenExpired(bhTokenData.expiresAt)) {
      dataStore.bhRestTokens.delete(bhToken);
    }
  }
}

// Authentication middleware for REST API endpoints
const authenticateToken = (req, res, next) => {
  const bhRestToken = req.query.BhRestToken;
  const corpToken = req.params.corpToken;

  if (!bhRestToken) {
    return res.status(401).json({ 
      errorMessage: 'BhRestToken required',
      errorCode: 'BHREST_AUTH_REQUIRED'
    });
  }

  if (!corpToken) {
    return res.status(400).json({ 
      errorMessage: 'corpToken required in URL path',
      errorCode: 'CORP_TOKEN_REQUIRED'
    });
  }

    // Check if BhRestToken exists and is valid
    const tokenData = dataStore.bhRestTokens.get(bhRestToken);
    
    if (!tokenData) {
    return res.status(401).json({ 
      errorMessage: 'Invalid BhRestToken',
      errorCode: 'INVALID_BHREST_TOKEN'
    });
    }

    // Check if BhRestToken is expired
    if (isTokenExpired(tokenData.expiresAt)) {
      dataStore.bhRestTokens.delete(bhRestToken);
    return res.status(401).json({ 
      errorMessage: 'BhRestToken expired. Please re-authenticate.',
      errorCode: 'BHREST_TOKEN_EXPIRED'
    });
    }

    // Check if corpToken matches
    if (corpToken !== tokenData.corpToken) {
    return res.status(400).json({ 
      errorMessage: 'Invalid corpToken for this BhRestToken',
      errorCode: 'CORP_TOKEN_MISMATCH'
    });
    }
    
  req.user = { id: tokenData.userId, username: 'bh_user', role: 'admin' };
    return next();
};

// Helper to get base URL from request
function getBaseUrl(req) {
  const protocol = req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
}

// =====================================================
// BULLHORN LOGIN INFO ENDPOINT
// First step: Determine the correct data center for the user
// https://rest.bullhornstaffing.com/rest-services/loginInfo?username={API_Username}
// =====================================================
app.get('/rest-services/loginInfo', (req, res) => {
  const { username } = req.query;

  if (!username) {
    return res.status(400).json({
      errorMessage: 'Missing username parameter',
      errorCode: 'MISSING_USERNAME'
    });
  }

  const baseUrl = getBaseUrl(req);

  // Return the data center URLs for this user
  // In real Bullhorn, this returns URLs based on the user's data center
  res.json({
    oauthUrl: `${baseUrl}/oauth`,
    restUrl: `${baseUrl}/rest-services/`,
    // Additional URLs that real Bullhorn might return
    username: username,
    dataCenter: DATA_CENTER
  });
});

// =====================================================
// OAUTH AUTHORIZATION ENDPOINT
// Step 2: Get an authorization code
// https://auth-{datacenter}.bullhornstaffing.com/oauth/authorize
// =====================================================
app.get('/oauth/authorize', (req, res) => {
  const { 
    client_id, 
    response_type, 
    action, 
    username, 
    password, 
    redirect_uri,
    state 
  } = req.query;

  // Validate required parameters
  if (!client_id) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing client_id parameter'
    });
  }

  if (!response_type || response_type !== 'code') {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid or missing response_type parameter. Must be "code"'
    });
  }

  // Validate client_id
  if (client_id !== OAUTH_CLIENT_ID) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Invalid client_id'
    });
  }

  // Validate redirect_uri if provided (must match registered URIs)
  const effectiveRedirectUri = redirect_uri || DEFAULT_REDIRECT_URI;
  if (redirect_uri && !dataStore.registeredRedirectUris.has(redirect_uri)) {
    // For testing purposes, we'll accept any redirect_uri but log a warning
    console.warn(`Warning: redirect_uri "${redirect_uri}" not in registered URIs. Allowing for testing.`);
  }

  // If action=Login is provided with credentials, authenticate directly
  if (action === 'Login') {
    if (!username || !password) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing username or password parameter for Login action'
      });
    }

    // Validate credentials
    if (username !== OAUTH_USERNAME) {
      return res.status(401).json({
        error: 'access_denied',
        error_description: 'Invalid username'
      });
    }

    if (password !== OAUTH_PASSWORD) {
      return res.status(401).json({
        error: 'access_denied',
        error_description: 'Invalid password'
      });
    }

    // Generate authorization code
    const authorizationCode = generateAuthorizationCode();
    const now = Date.now();
    const expiresAt = now + AUTHORIZATION_CODE_EXPIRES_IN;

    // Store authorization code
    dataStore.authorizationCodes.set(authorizationCode, {
      expiresAt: expiresAt,
      clientId: client_id,
      userId: 1, // Mock user ID
      redirectUri: effectiveRedirectUri
    });

    // Build redirect URL with authorization code and state
    const redirectUrl = new URL(effectiveRedirectUri);
    redirectUrl.searchParams.append('code', authorizationCode);
    
    if (state) {
      redirectUrl.searchParams.append('state', state);
    }

    // Redirect to the redirect_uri with the authorization code
    return res.redirect(redirectUrl.toString());
  }

  // If no action=Login, would normally show login page
  // For this mock, we'll return an error indicating login page would be shown
  return res.status(400).json({
    error: 'login_required',
    error_description: 'action=Login with username and password required for programmatic access. Otherwise, a login page would be displayed.'
  });
});

// =====================================================
// OAUTH TOKEN ENDPOINT
// Step 3: Get an access token (or refresh it)
// https://auth-{datacenter}.bullhornstaffing.com/oauth/token
// =====================================================
app.post('/oauth/token', (req, res) => {
  // Combine URL params and body params for flexible parameter checking
  const params = { ...req.query, ...req.body };

  // Check if grant_type is provided
  if (!params.grant_type) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Missing grant_type parameter'
    });
  }

  // Check if client_id and client_secret are provided
  if (!params.client_id || !params.client_secret) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Missing client credentials'
    });
  }

  if (params.client_id !== OAUTH_CLIENT_ID || params.client_secret !== OAUTH_CLIENT_SECRET) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client credentials'
    });
  }

  // Handle authorization code flow
  if (params.grant_type === 'authorization_code') {
    if (!params.code) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing code parameter'
      });
    }

    // Validate authorization code
    const codeData = dataStore.authorizationCodes.get(params.code);
    
    if (!codeData) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid authorization code'
      });
    }

    // Check if authorization code is expired
    if (isTokenExpired(codeData.expiresAt)) {
      dataStore.authorizationCodes.delete(params.code);
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code expired'
      });
    }

    // Check if client_id matches
    if (codeData.clientId !== params.client_id) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Authorization code was issued to a different client'
      });
    }

    // Check if redirect_uri matches (if provided in token request)
    if (params.redirect_uri && params.redirect_uri !== codeData.redirectUri) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'redirect_uri does not match the one used in authorization request'
      });
    }

    // Generate new tokens
    const accessToken = generateAccessToken();
    const refreshToken = generateRefreshToken();
    const userId = codeData.userId;
    const now = Date.now();
    const expiresAt = now + ACCESS_TOKEN_EXPIRES_IN;

    // Store tokens
    dataStore.accessTokens.set(accessToken, {
      userId: userId,
      expiresAt: expiresAt,
      refreshToken: refreshToken
    });

    dataStore.refreshTokens.set(refreshToken, {
      userId: userId,
      createdAt: now,
      accessToken: accessToken
    });

    // Clear the authorization code (one-time use)
    dataStore.authorizationCodes.delete(params.code);

    // Return Bullhorn-style token response
    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: Math.floor(ACCESS_TOKEN_EXPIRES_IN / 1000), // 600 seconds (10 minutes)
      refresh_token: refreshToken
    });
  }

  // Handle refresh token flow
  if (params.grant_type === 'refresh_token') {
    dataStore.debug.refreshTokenCount++;
    
    if (!params.refresh_token) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing refresh_token parameter'
      });
    }

    // Validate refresh token
    const refreshTokenData = dataStore.refreshTokens.get(params.refresh_token);
    if (!refreshTokenData) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid refresh token'
      });
    }

    // Revoke old access token if it exists
    if (refreshTokenData.accessToken) {
      dataStore.accessTokens.delete(refreshTokenData.accessToken);
    }

    // Generate new access token (and new refresh token - Bullhorn returns new refresh token each time)
    const newAccessToken = generateAccessToken();
    const newRefreshToken = generateRefreshToken();
    const userId = refreshTokenData.userId;
    const now = Date.now();
    const expiresAt = now + ACCESS_TOKEN_EXPIRES_IN;

    console.log(`logName=refreshToken, token=${newAccessToken}, count=${dataStore.debug.refreshTokenCount}`);

    // Store new access token
    dataStore.accessTokens.set(newAccessToken, {
      userId: userId,
      expiresAt: expiresAt,
      refreshToken: newRefreshToken
    });

    // Delete old refresh token and store new one
    dataStore.refreshTokens.delete(params.refresh_token);
    dataStore.refreshTokens.set(newRefreshToken, {
        userId: userId,
        createdAt: now,
      accessToken: newAccessToken
    });

    // Return new tokens (Bullhorn returns new refresh token with every access token)
    return res.status(200).json({
      access_token: newAccessToken,
        token_type: 'Bearer',
      expires_in: Math.floor(ACCESS_TOKEN_EXPIRES_IN / 1000),
      refresh_token: newRefreshToken
      });
  }

  // Unsupported grant type
  return res.status(400).json({
    error: 'unsupported_grant_type',
    error_description: 'Grant type not supported. Use authorization_code or refresh_token.'
  });
});

// =====================================================
// BULLHORN REST API LOGIN ENDPOINT
// Step 4: Login to REST API to get BhRestToken
// https://rest-{datacenter}.bullhornstaffing.com/rest-services/login
// =====================================================
app.post('/rest-services/login', (req, res) => {
  const accessToken = req.query.access_token;
  const version = req.query.version;

  // Check if access_token is provided
  if (!accessToken) {
    return res.status(400).json({
      errorMessage: 'Missing access_token parameter',
      errorCode: 'MISSING_ACCESS_TOKEN'
    });
  }

  // Validate access_token
  const tokenData = dataStore.accessTokens.get(accessToken);
  if (!tokenData) {
    return res.status(401).json({ 
      errorMessage: 'Invalid access_token',
      errorCode: 'INVALID_ACCESS_TOKEN'
    });
  }

  // Check if access token is expired
  if (isTokenExpired(tokenData.expiresAt)) {
    dataStore.accessTokens.delete(accessToken);
    return res.status(401).json({ 
      errorMessage: 'Access token expired. Use refresh token to get a new access token.',
      errorCode: 'ACCESS_TOKEN_EXPIRED'
    });
  }

  // Validate version parameter (Bullhorn supports * for latest or specific version like 2.0)
  if (!version) {
    return res.status(400).json({
      errorMessage: 'Missing version parameter. Use version=* for latest or version=2.0',
      errorCode: 'MISSING_VERSION'
    });
  }

  if (version !== '*' && version !== '2.0') {
    return res.status(400).json({
      errorMessage: 'Invalid version parameter. Use version=* for latest or version=2.0',
      errorCode: 'INVALID_VERSION'
    });
  }

  // Generate BhRestToken and corpToken
  const corpToken = generateCorpToken();
  const bhRestToken = generateBhRestToken();
  const now = Date.now();
  const expiresAt = now + BH_REST_TOKEN_EXPIRES_IN;

  // Store bhRestToken
  dataStore.bhRestTokens.set(bhRestToken, {
    expiresAt: expiresAt,
    corpToken: corpToken,
    userId: tokenData.userId
  });

  const baseUrl = getBaseUrl(req);

  // Return Bullhorn-style login response
  res.status(200).json({
    BhRestToken: bhRestToken,
    restUrl: `${baseUrl}/rest-services/${corpToken}/`
  });
});

// =====================================================
// HEALTH CHECK ENDPOINT
// =====================================================
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    dataCenter: DATA_CENTER
  });
});

// =====================================================
// BULLHORN REST API ENDPOINTS
// All endpoints follow pattern: /rest-services/{corpToken}/...
// =====================================================

// GET Entity - Get all entities of a type
app.get('/rest-services/:corpToken/entity/:entityType', authenticateToken, (req, res) => {
  const { entityType } = req.params;
  const { start, count, fields, where, orderBy } = req.query;
  
  let data = [];
  
  switch (entityType) {
    case 'Candidate':
      data = [...dataStore.candidates];
      break;
    case 'JobOrder':
      data = [...dataStore.jobs];
      break;
    case 'ClientCorporation':
      data = [...dataStore.clients];
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  // Apply filters (simplified)
  if (where && entityType === 'Candidate') {
    data = data.filter(item => {
      if (where.includes('firstName')) {
        const match = where.match(/firstName='([^']+)'/);
        return match && item.firstName?.includes(match[1]);
      }
      return true;
    });
  }
  
  // Apply pagination
  const startIndex = Number.parseInt(start, 10) || 0;
  const limit = Number.parseInt(count, 10) || 25;
  const paginatedData = data.slice(startIndex, startIndex + limit);
  
  // Apply field filtering if specified
  let responseData = paginatedData;
  if (fields) {
    const fieldList = fields.split(',').map(f => f.trim());
    responseData = paginatedData.map(item => {
      const filtered = {};
      fieldList.forEach(field => {
        if (item[field] !== undefined) {
          filtered[field] = item[field];
        }
      });
      return filtered;
    });
  }
  
  res.json({
    data: responseData,
    start: startIndex,
    count: responseData.length,
    total: data.length
  });
});

// GET Entity by ID
app.get('/rest-services/:corpToken/entity/:entityType/:id', authenticateToken, (req, res) => {
  const { entityType, id } = req.params;
  const { fields } = req.query;
  
  let entity = null;
  
  switch (entityType) {
    case 'Candidate':
      entity = dataStore.candidates.find(c => c.id === Number.parseInt(id, 10));
      break;
    case 'JobOrder':
      entity = dataStore.jobs.find(j => j.id === Number.parseInt(id, 10));
      break;
    case 'ClientCorporation':
      entity = dataStore.clients.find(c => c.id === Number.parseInt(id, 10));
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  if (!entity) {
    return res.status(404).json({
      errorMessage: `${entityType} with id ${id} not found`,
      errorCode: 'RECORD_NOT_FOUND'
    });
  }
  
  // Apply field filtering if specified
  let responseData = entity;
  if (fields) {
    const fieldList = fields.split(',').map(f => f.trim());
    responseData = {};
    fieldList.forEach(field => {
      if (entity[field] !== undefined) {
        responseData[field] = entity[field];
      }
    });
  }
  
  res.json({ data: responseData });
});

// PUT Create Entity (Bullhorn uses PUT for create)
app.put('/rest-services/:corpToken/entity/:entityType', authenticateToken, (req, res) => {
  const { entityType } = req.params;
  const entityData = req.body;
  
  let newEntity;
  let dataArray;
  
  switch (entityType) {
    case 'Candidate':
      dataArray = dataStore.candidates;
      break;
    case 'JobOrder':
      dataArray = dataStore.jobs;
      break;
    case 'ClientCorporation':
      dataArray = dataStore.clients;
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  newEntity = {
    id: dataArray.length + 1,
    ...entityData,
    dateAdded: new Date().toISOString(),
    dateLastModified: new Date().toISOString()
  };
  
  dataArray.push(newEntity);
  
  // Bullhorn returns changedEntityId for creates
  res.status(200).json({
    changedEntityType: entityType,
    changedEntityId: newEntity.id,
    changeType: 'INSERT',
    data: newEntity
  });
});

// POST Update Entity (Bullhorn uses POST for update)
app.post('/rest-services/:corpToken/entity/:entityType/:id', authenticateToken, (req, res) => {
  const { entityType, id } = req.params;
  const updateData = req.body;
  
  let dataArray;
  
  switch (entityType) {
    case 'Candidate':
      dataArray = dataStore.candidates;
      break;
    case 'JobOrder':
      dataArray = dataStore.jobs;
      break;
    case 'ClientCorporation':
      dataArray = dataStore.clients;
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  const entityIndex = dataArray.findIndex(e => e.id === Number.parseInt(id, 10));
  
  if (entityIndex === -1) {
    return res.status(404).json({
      errorMessage: `${entityType} with id ${id} not found`,
      errorCode: 'RECORD_NOT_FOUND'
    });
  }
  
  // Update entity
  dataArray[entityIndex] = {
    ...dataArray[entityIndex],
    ...updateData,
    dateLastModified: new Date().toISOString()
  };
  
  res.json({
    changedEntityType: entityType,
    changedEntityId: Number.parseInt(id, 10),
    changeType: 'UPDATE',
    data: dataArray[entityIndex]
  });
});

// DELETE Entity
app.delete('/rest-services/:corpToken/entity/:entityType/:id', authenticateToken, (req, res) => {
  const { entityType, id } = req.params;
  
  let dataArray;
  
  switch (entityType) {
    case 'Candidate':
      dataArray = dataStore.candidates;
      break;
    case 'JobOrder':
      dataArray = dataStore.jobs;
      break;
    case 'ClientCorporation':
      dataArray = dataStore.clients;
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  const entityIndex = dataArray.findIndex(e => e.id === Number.parseInt(id, 10));
  
  if (entityIndex === -1) {
    return res.status(404).json({
      errorMessage: `${entityType} with id ${id} not found`,
      errorCode: 'RECORD_NOT_FOUND'
    });
  }
  
  dataArray.splice(entityIndex, 1);
  
  res.json({
    changedEntityType: entityType,
    changedEntityId: Number.parseInt(id, 10),
    changeType: 'DELETE'
  });
});

// Search endpoint
app.get('/rest-services/:corpToken/search/:entityType', authenticateToken, (req, res) => {
  const { entityType } = req.params;
  const { query, start, count, fields, orderBy } = req.query;
  
  let data = [];
  
  switch (entityType) {
    case 'Candidate':
      data = [...dataStore.candidates];
      break;
    case 'JobOrder':
      data = [...dataStore.jobs];
      break;
    case 'ClientCorporation':
      data = [...dataStore.clients];
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  // Simple search implementation
  if (query) {
    const searchTerm = query.toLowerCase();
    data = data.filter(item => {
      // Search in the entire object structure
      return JSON.stringify(item).toLowerCase().includes(searchTerm);
    });
  }
  
  // Apply pagination
  const startIndex = Number.parseInt(start, 10) || 0;
  const limit = Number.parseInt(count, 10) || 25;
  const paginatedData = data.slice(startIndex, startIndex + limit);
  
  res.json({
    data: paginatedData,
    start: startIndex,
    count: paginatedData.length,
    total: data.length
  });
});

// Query endpoint (Bullhorn-specific)
app.get('/rest-services/:corpToken/query/:entityType', authenticateToken, (req, res) => {
  const { entityType } = req.params;
  const { where, start, count, fields, orderBy } = req.query;
  
  let data = [];
  
  switch (entityType) {
    case 'Candidate':
      data = [...dataStore.candidates];
      break;
    case 'JobOrder':
      data = [...dataStore.jobs];
      break;
    case 'ClientCorporation':
      data = [...dataStore.clients];
      break;
    default:
      return res.status(404).json({
        errorMessage: `Entity type '${entityType}' not found`,
        errorCode: 'ENTITY_NOT_FOUND'
      });
  }
  
  // Simple where clause parsing (very basic)
  if (where) {
    // This is a simplified implementation
    // Real Bullhorn supports complex SQL-like WHERE clauses
    data = data.filter(item => {
      // Basic id filter support
      const idMatch = where.match(/id=(\d+)/);
      if (idMatch) {
        return item.id === Number.parseInt(idMatch[1], 10);
      }
      return true;
    });
  }
  
  // Apply pagination
  const startIndex = Number.parseInt(start, 10) || 0;
  const limit = Number.parseInt(count, 10) || 25;
  const paginatedData = data.slice(startIndex, startIndex + limit);
  
  res.json({
    data: paginatedData,
    start: startIndex,
    count: paginatedData.length,
    total: data.length
  });
});

// File upload endpoint (mock)
const fileUploadHandler = (req, res) => {
  // Mock file upload response - uses path params for entity context
  res.json({
    fileId: Math.floor(Math.random() * 100000),
    fileName: 'uploaded_file',
    contentType: req.get('Content-Type') || 'application/octet-stream',
    changeType: 'INSERT',
    entityType: req.params.entityType,
    entityId: Number.parseInt(req.params.id, 10)
  });
};

app.post('/rest-services/:corpToken/file/:entityType/:id/raw', authenticateToken, fileUploadHandler);
app.put('/rest-services/:corpToken/file/:entityType/:id/raw', authenticateToken, fileUploadHandler);

// Fetch data endpoint (convenience endpoint for testing)
app.get('/rest-services/:corpToken/fetch-data', authenticateToken, (req, res) => {
  // Return mock successful response with dummy data
  res.status(200).json({
    success: true,
    data: [
      {
        id: 1,
        name: 'John Doe',
        email: 'john.doe@example.com',
        position: 'Software Engineer'
      },
      {
        id: 2,
        name: 'Jane Smith',
        email: 'jane.smith@example.com',
        position: 'Product Manager'
      }
    ],
    total: 2,
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    errorMessage: 'Internal server error',
    errorCode: 'INTERNAL_ERROR'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    errorMessage: 'Endpoint not found',
    errorCode: 'ENDPOINT_NOT_FOUND'
  });
});

// Initialize with some sample data
function initializeSampleData() {
  // Sample candidates
  dataStore.candidates = [
    {
      id: 1,
      firstName: 'John',
      lastName: 'Doe',
      name: 'John Doe',
      email: 'john.doe@example.com',
      phone: '+1-555-0123',
      status: 'Active',
      category: { id: 1, name: 'Engineering' },
      address: {
        address1: '123 Main St',
        city: 'Boston',
        state: 'MA',
        zip: '02110',
        countryID: 1
      },
      dateAdded: '2024-01-15T10:30:00Z',
      dateLastModified: '2024-01-15T10:30:00Z'
    },
    {
      id: 2,
      firstName: 'Jane',
      lastName: 'Smith',
      name: 'Jane Smith',
      email: 'jane.smith@example.com',
      phone: '+1-555-0124',
      status: 'Active',
      category: { id: 2, name: 'Sales' },
      address: {
        address1: '456 Oak Ave',
        city: 'New York',
        state: 'NY',
        zip: '10001',
        countryID: 1
      },
      dateAdded: '2024-01-16T14:20:00Z',
      dateLastModified: '2024-01-16T14:20:00Z'
    }
  ];

  // Sample jobs
  dataStore.jobs = [
    {
      id: 1,
      title: 'Senior Software Engineer',
      clientCorporation: { id: 1, name: 'Tech Corp' },
      status: 'Open',
      employmentType: 'Full-time',
      salary: 150000,
      dateAdded: '2024-01-10T09:00:00Z',
      dateLastModified: '2024-01-10T09:00:00Z'
    },
    {
      id: 2,
      title: 'Product Manager',
      clientCorporation: { id: 2, name: 'Startup Inc' },
      status: 'Open',
      employmentType: 'Full-time',
      salary: 130000,
      dateAdded: '2024-01-12T11:00:00Z',
      dateLastModified: '2024-01-12T11:00:00Z'
    }
  ];

  // Sample clients
  dataStore.clients = [
    {
      id: 1,
      name: 'Tech Corp',
      status: 'Active',
      companyURL: 'https://techcorp.example.com',
      address: {
        address1: '100 Tech Way',
        city: 'San Francisco',
        state: 'CA',
        zip: '94105',
        countryID: 1
      },
      dateAdded: '2024-01-01T08:00:00Z',
      dateLastModified: '2024-01-01T08:00:00Z'
    },
    {
      id: 2,
      name: 'Startup Inc',
      status: 'Active',
      companyURL: 'https://startup.example.com',
      address: {
        address1: '200 Innovation Blvd',
        city: 'Austin',
        state: 'TX',
        zip: '78701',
        countryID: 1
      },
      dateAdded: '2024-01-05T10:00:00Z',
      dateLastModified: '2024-01-05T10:00:00Z'
    }
  ];
}

// Start server if run directly
if (require.main === module) {
  app.listen(PORT, () => {
    initializeSampleData();
    
    // Start periodic cleanup of expired tokens (every 5 minutes)
    setInterval(cleanupExpiredTokens, 5 * 60 * 1000);
    
    console.log(`\n🚀 BullHorn Mock Server running on port ${PORT}`);
    console.log(`   Data Center: ${DATA_CENTER}`);
    console.log(`\n📋 API Endpoints:`);
    console.log(`   Health check: http://localhost:${PORT}/health`);
    console.log(`\n🔐 OAuth Flow (following Bullhorn's actual process):`);
    console.log(`   1. Login Info:     GET  http://localhost:${PORT}/rest-services/loginInfo?username={username}`);
    console.log(`   2. Authorization:  GET  http://localhost:${PORT}/oauth/authorize?client_id=...&response_type=code&action=Login&username=...&password=...`);
    console.log(`   3. Get Token:      POST http://localhost:${PORT}/oauth/token (grant_type=authorization_code)`);
    console.log(`   4. Refresh Token:  POST http://localhost:${PORT}/oauth/token (grant_type=refresh_token)`);
    console.log(`   5. REST Login:     POST http://localhost:${PORT}/rest-services/login?version=*&access_token={token}`);
    console.log(`\n📚 REST API (after login):`);
    console.log(`   Base URL: http://localhost:${PORT}/rest-services/{corpToken}/`);
    console.log(`   Example:  GET  /rest-services/{corpToken}/entity/Candidate?BhRestToken={token}&fields=firstName,lastName`);
    console.log(`\n🔑 Test Credentials:`);
    console.log(`   client_id:     ${OAUTH_CLIENT_ID}`);
    console.log(`   client_secret: ${OAUTH_CLIENT_SECRET}`);
    console.log(`   username:      ${OAUTH_USERNAME}`);
    console.log(`   password:      ${OAUTH_PASSWORD}`);
    console.log('');
  });
} else {
  // Initialize data when imported for testing
  initializeSampleData();
}

module.exports = app; 
