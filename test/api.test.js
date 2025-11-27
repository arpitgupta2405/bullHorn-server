const { test, describe } = require('node:test');
const assert = require('node:assert');
const request = require('supertest');
const app = require('../server');

// Helper to extract parameters from redirect URL
function parseRedirectUrl(location) {
  if (!location) return {};
  const url = new URL(location);
  const params = {};
  url.searchParams.forEach((value, key) => {
    params[key] = value;
  });
  return params;
}

test('BullHorn Mock Server Rigorous Tests', async (t) => {
  // Global variables to store state across tests
  let authorizationCode;
  let accessToken;
  let refreshToken;
  let bhRestToken;
  let corpToken;
  let restUrl;
  let createdCandidateId;

  // ============================================================================
  // 1. DISCOVERY & AUTHENTICATION FLOW
  // ============================================================================
  
  await t.test('1. Authentication Flow', async (t) => {
    
    await t.test('1.1 loginInfo - Should return data center URLs', async () => {
      const response = await request(app)
        .get('/rest-services/loginInfo')
        .query({ username: 'bullhorn_user' });

      assert.strictEqual(response.status, 200);
      assert.ok(response.body.oauthUrl, 'Should return oauthUrl');
      assert.ok(response.body.restUrl, 'Should return restUrl');
      assert.ok(response.body.dataCenter, 'Should return dataCenter');
    });

    await t.test('1.2 loginInfo - Should fail without username', async () => {
      const response = await request(app)
        .get('/rest-services/loginInfo');

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.errorCode, 'MISSING_USERNAME');
    });

    await t.test('1.3 Authorize - Should redirect with authorization code', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'bullhorn_client_123',
          response_type: 'code',
          action: 'Login',
          username: 'bullhorn_user',
          password: 'bullhorn_pass_456',
          state: 'test_state_123',
          redirect_uri: 'https://staging.integrator.io/connection/oauth2callback'
        });

      assert.strictEqual(response.status, 302, 'Should redirect');
      assert.ok(response.headers.location, 'Should have location header');
      
      const params = parseRedirectUrl(response.headers.location);
      assert.ok(params.code, 'Should return authorization code');
      assert.strictEqual(params.state, 'test_state_123', 'Should return state');
      
      // Store code
      authorizationCode = params.code;
    });

    await t.test('1.4 Authorize - Should fail with invalid credentials', async () => {
      const response = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'bullhorn_client_123',
          response_type: 'code',
          action: 'Login',
          username: 'wrong_user',
          password: 'wrong_password'
        });

      assert.strictEqual(response.status, 401);
    });

    await t.test('1.5 Token - Should exchange code for access token', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: authorizationCode,
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123',
          redirect_uri: 'https://staging.integrator.io/connection/oauth2callback'
        });

      assert.strictEqual(response.status, 200);
      assert.ok(response.body.access_token, 'Should return access_token');
      assert.ok(response.body.refresh_token, 'Should return refresh_token');
      assert.strictEqual(response.body.token_type, 'Bearer');
      
      // Store tokens
      accessToken = response.body.access_token;
      refreshToken = response.body.refresh_token;
    });

    await t.test('1.6 Token - Should fail with invalid code', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: 'invalid_code',
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123'
        });

      assert.strictEqual(response.status, 400);
    });

    await t.test('1.7 Refresh Token - Should refresh tokens', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123'
        });

      assert.strictEqual(response.status, 200);
      assert.ok(response.body.access_token, 'Should return new access_token');
      assert.ok(response.body.refresh_token, 'Should return new refresh_token');
      assert.notStrictEqual(response.body.access_token, accessToken, 'Access token should change');
      assert.notStrictEqual(response.body.refresh_token, refreshToken, 'Refresh token should change');
      
      // Update tokens
      accessToken = response.body.access_token;
    });

    await t.test('1.8 REST Login - Should get BhRestToken', async () => {
      const response = await request(app)
        .post('/rest-services/login')
        .query({
          version: '*',
          access_token: accessToken
        });

      assert.strictEqual(response.status, 200);
      assert.ok(response.body.BhRestToken, 'Should return BhRestToken');
      assert.ok(response.body.restUrl, 'Should return restUrl');
      
      // Store REST token and URL
      bhRestToken = response.body.BhRestToken;
      restUrl = response.body.restUrl;
      
      // Extract corpToken from restUrl
      const match = restUrl.match(/\/rest-services\/([A-Za-z0-9]+)\//);
      assert.ok(match, 'restUrl should contain corpToken');
      corpToken = match[1];
    });
  });

  await t.test('1b. OAuth Error Scenarios', async (t) => {
    await t.test('1b.1 Token endpoint requires grant_type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123'
        });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, 'invalid_request');
    });

    await t.test('1b.2 Token endpoint requires client credentials', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: 'some_code'
        });

      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.body.error, 'invalid_client');
    });

    await t.test('1b.3 redirect_uri mismatch should fail', async () => {
      const authorizeResponse = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'bullhorn_client_123',
          response_type: 'code',
          action: 'Login',
          username: 'bullhorn_user',
          password: 'bullhorn_pass_456',
          state: 'redirect_mismatch_state',
          redirect_uri: 'https://staging.integrator.io/connection/oauth2callback'
        });

      const params = parseRedirectUrl(authorizeResponse.headers.location);

      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: params.code,
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123',
          redirect_uri: 'https://example.com/different'
        });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, 'invalid_grant');
    });
  });

  await t.test('1c. REST Login Error Scenarios', async (t) => {
    await t.test('1c.1 Missing access_token should fail', async () => {
      const response = await request(app)
        .post('/rest-services/login')
        .query({ version: '*' });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.errorCode, 'MISSING_ACCESS_TOKEN');
    });

    await t.test('1c.2 Missing version should fail', async () => {
      const response = await request(app)
        .post('/rest-services/login')
        .query({ access_token: accessToken });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.errorCode, 'MISSING_VERSION');
    });

    await t.test('1c.3 Invalid version should fail', async () => {
      const response = await request(app)
        .post('/rest-services/login')
        .query({ access_token: accessToken, version: '1.0' });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.errorCode, 'INVALID_VERSION');
    });
  });

  // ============================================================================
  // 2. ENTITY CRUD OPERATIONS
  // ============================================================================

  await t.test('2. Candidate Entity Operations', async (t) => {
    
    await t.test('2.1 GET Candidates - Should list candidates', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/Candidate`)
        .query({ 
          BhRestToken: bhRestToken,
          fields: 'id,firstName,lastName,email'
        });

      assert.strictEqual(response.status, 200);
      assert.ok(Array.isArray(response.body.data), 'Data should be an array');
      assert.ok(response.body.total > 0, 'Should have total count');
      assert.ok(response.body.data[0].firstName, 'Should return requested fields');
    });

    await t.test('2.2 PUT Candidate - Should create candidate', async () => {
      const newCandidate = {
        firstName: 'Test',
        lastName: 'User',
        email: 'test.user@example.com',
        status: 'Active'
      };

      const response = await request(app)
        .put(`/rest-services/${corpToken}/entity/Candidate`)
        .query({ BhRestToken: bhRestToken })
        .send(newCandidate);

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'INSERT');
      assert.ok(response.body.changedEntityId, 'Should return new ID');
      
      createdCandidateId = response.body.changedEntityId;
    });

    await t.test('2.3 GET Candidate - Should get created candidate', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/Candidate/${createdCandidateId}`)
        .query({ BhRestToken: bhRestToken });

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.data.id, createdCandidateId);
      assert.strictEqual(response.body.data.firstName, 'Test');
    });

    await t.test('2.4 POST Candidate - Should update candidate', async () => {
      const updateData = {
        firstName: 'Updated Test',
        status: 'Inactive'
      };

      const response = await request(app)
        .post(`/rest-services/${corpToken}/entity/Candidate/${createdCandidateId}`)
        .query({ BhRestToken: bhRestToken })
        .send(updateData);

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'UPDATE');
      assert.strictEqual(response.body.data.firstName, 'Updated Test');
    });

    await t.test('2.5 DELETE Candidate - Should delete candidate', async () => {
      const response = await request(app)
        .delete(`/rest-services/${corpToken}/entity/Candidate/${createdCandidateId}`)
        .query({ BhRestToken: bhRestToken });

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'DELETE');
    });

    await t.test('2.6 GET Deleted Candidate - Should return 404', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/Candidate/${createdCandidateId}`)
        .query({ BhRestToken: bhRestToken });

      assert.strictEqual(response.status, 404);
    });
  });

  await t.test('2b. JobOrder Entity Operations', async (t) => {
    await t.test('2b.1 GET JobOrders - Should list job orders', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/JobOrder`)
        .query({ BhRestToken: bhRestToken, fields: 'id,title,status' });

      assert.strictEqual(response.status, 200);
      assert.ok(Array.isArray(response.body.data));
      assert.ok(response.body.total >= response.body.count);
    });

    await t.test('2b.2 GET JobOrder by ID - Should return job order', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/JobOrder/1`)
        .query({ BhRestToken: bhRestToken, fields: 'id,title,clientCorporation' });

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.data.id, 1);
      assert.ok(response.body.data.clientCorporation);
    });

    await t.test('2b.3 PUT JobOrder - Should create job order', async () => {
      const newJob = {
        title: 'QA Engineer',
        status: 'Open'
      };

      const response = await request(app)
        .put(`/rest-services/${corpToken}/entity/JobOrder`)
        .query({ BhRestToken: bhRestToken })
        .send(newJob);

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'INSERT');
      assert.ok(response.body.changedEntityId);
    });
  });

  await t.test('2c. ClientCorporation Entity Operations', async (t) => {
    await t.test('2c.1 GET Clients - Should list clients', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/ClientCorporation`)
        .query({ BhRestToken: bhRestToken, fields: 'id,name,status' });

      assert.strictEqual(response.status, 200);
      assert.ok(Array.isArray(response.body.data));
      assert.ok(response.body.total >= response.body.count);
    });

    await t.test('2c.2 GET Client by ID - Should return client', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/ClientCorporation/1`)
        .query({ BhRestToken: bhRestToken, fields: 'id,name,address' });

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.data.id, 1);
      assert.ok(response.body.data.address);
    });

    await t.test('2c.3 PUT Client - Should create client', async () => {
      const newClient = {
        name: 'Coverage Industries',
        status: 'Active'
      };

      const response = await request(app)
        .put(`/rest-services/${corpToken}/entity/ClientCorporation`)
        .query({ BhRestToken: bhRestToken })
        .send(newClient);

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'INSERT');
      assert.ok(response.body.changedEntityId);
    });
  });

  // ============================================================================
  // 3. SEARCH & ADVANCED QUERIES
  // ============================================================================

  await t.test('3. Search & Query', async (t) => {
    
    await t.test('3.1 Search - Should find entities by text', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/search/Candidate`)
        .query({ 
          BhRestToken: bhRestToken,
          query: 'doe' // Should find John Doe
        });

      assert.strictEqual(response.status, 200);
      assert.ok(response.body.data.length > 0, 'Should find results');
      const found = response.body.data.some(c => c.lastName.toLowerCase() === 'doe');
      assert.ok(found, 'Should find John Doe');
    });

    await t.test('3.2 Search - Should return empty for no matches', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/search/Candidate`)
        .query({ 
          BhRestToken: bhRestToken,
          query: 'nonexistentuserxyz'
        });

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.data.length, 0);
    });

    await t.test('3.3 Query - Should support basic filtering', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/query/Candidate`)
        .query({ 
          BhRestToken: bhRestToken,
          where: 'id=1'
        });

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.data.length, 1);
      assert.strictEqual(response.body.data[0].id, 1);
    });
  });

  // ============================================================================
  // 4. FILE OPERATIONS & OTHER ENDPOINTS
  // ============================================================================

  await t.test('4. File Operations', async (t) => {
    
    await t.test('4.1 POST File - Should upload file', async () => {
      const response = await request(app)
        .post(`/rest-services/${corpToken}/file/Candidate/1/raw`)
        .query({ 
          BhRestToken: bhRestToken,
          externalId: 'portfolio',
          fileType: 'SAMPLE'
        })
        .set('Content-Type', 'text/plain')
        .send('some file content');

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'INSERT');
      assert.ok(response.body.fileId);
    });

    await t.test('4.2 PUT File - Should upload file (PUT support)', async () => {
      const response = await request(app)
        .put(`/rest-services/${corpToken}/file/Candidate/1/raw`)
        .query({ 
          BhRestToken: bhRestToken,
          externalId: 'resume',
          fileType: 'PDF'
        })
        .set('Content-Type', 'application/pdf')
        .send('fake pdf content');

      assert.strictEqual(response.status, 200);
      assert.strictEqual(response.body.changeType, 'INSERT');
      assert.ok(response.body.fileId);
    });
  });

  await t.test('4b. File Operation Error Scenarios', async (t) => {
    await t.test('4b.1 Missing BhRestToken should fail upload', async () => {
      const response = await request(app)
        .post(`/rest-services/${corpToken}/file/Candidate/1/raw`);

      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.body.errorCode, 'BHREST_AUTH_REQUIRED');
    });
  });

  // ============================================================================
  // 5. EDGE CASES & ERROR HANDLING
  // ============================================================================

  await t.test('5. Error Handling', async (t) => {
    
    await t.test('5.1 Invalid BhRestToken', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/Candidate`)
        .query({ BhRestToken: 'invalid_token_123' });

      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.body.errorCode, 'INVALID_BHREST_TOKEN');
    });

    await t.test('5.2 Missing BhRestToken', async () => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/Candidate`);

      assert.strictEqual(response.status, 401);
      assert.strictEqual(response.body.errorCode, 'BHREST_AUTH_REQUIRED');
    });

    await t.test('5.3 Mismatched corpToken', async () => {
      const response = await request(app)
        .get(`/rest-services/WRONG_CORP_TOKEN/entity/Candidate`)
        .query({ BhRestToken: bhRestToken });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.errorCode, 'CORP_TOKEN_MISMATCH');
    });

    await t.test('5.4 Invalid Entity Type', async (t) => {
      const response = await request(app)
        .get(`/rest-services/${corpToken}/entity/UnknownEntity`)
        .query({ BhRestToken: bhRestToken });

      assert.strictEqual(response.status, 404);
      assert.strictEqual(response.body.errorCode, 'ENTITY_NOT_FOUND');
    });

    await t.test('5.5 Unsupported Grant Type', async () => {
      const response = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'client_credentials', // Not supported
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123'
        });

      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, 'unsupported_grant_type');
    });
  });

  // ============================================================================
  // 6. TOKEN EXPIRATION BEHAVIOR
  // ============================================================================

  await t.test('6. Token Expiration & Cleanup', async (t) => {
    await t.test('6.1 BhRestToken should expire when time advances', async () => {
      // Step 1: perform a fresh login to avoid interfering with other tests
      const freshAuthCodeResponse = await request(app)
        .get('/oauth/authorize')
        .query({
          client_id: 'bullhorn_client_123',
          response_type: 'code',
          action: 'Login',
          username: 'bullhorn_user',
          password: 'bullhorn_pass_456',
          state: 'token_expiry_state',
          redirect_uri: 'https://staging.integrator.io/connection/oauth2callback'
        });

      const freshParams = parseRedirectUrl(freshAuthCodeResponse.headers.location);
      const freshTokenResponse = await request(app)
        .post('/oauth/token')
        .send({
          grant_type: 'authorization_code',
          code: freshParams.code,
          client_id: 'bullhorn_client_123',
          client_secret: 'bullhorn_client_secret_123',
          redirect_uri: 'https://staging.integrator.io/connection/oauth2callback'
        });

      const freshAccessToken = freshTokenResponse.body.access_token;
      const freshLoginResponse = await request(app)
        .post('/rest-services/login')
        .query({ version: '*', access_token: freshAccessToken });

      const expiringBhRestToken = freshLoginResponse.body.BhRestToken;
      const freshRestUrl = freshLoginResponse.body.restUrl;
      const freshCorpToken = freshRestUrl.match(/\/rest-services\/([A-Za-z0-9]+)\//)[1];

      // Step 2: advance time beyond expiration
      const originalDateNow = Date.now;
      const ADVANCE_MS = 11 * 60 * 1000; // 11 minutes, BhRestToken expires at 10

      try {
        Date.now = () => originalDateNow() + ADVANCE_MS;

        const expiredResponse = await request(app)
          .get(`/rest-services/${freshCorpToken}/entity/Candidate`)
          .query({ BhRestToken: expiringBhRestToken });

        assert.strictEqual(expiredResponse.status, 401);
        assert.strictEqual(expiredResponse.body.errorCode, 'BHREST_TOKEN_EXPIRED');
      } finally {
        Date.now = originalDateNow;
      }
    });
  });

  // ============================================================================
  // 7. Global 404/Error handling
  // ============================================================================

  await t.test('7. Unknown route should return 404 JSON', async () => {
    const response = await request(app).get('/totally/unknown/route');
    assert.strictEqual(response.status, 404);
    assert.strictEqual(response.body.errorCode, 'ENDPOINT_NOT_FOUND');
  });
});
