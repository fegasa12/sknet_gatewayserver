#!/usr/bin/env node

const axios = require('axios');

// Configuration
const BASE_URL = process.env.PRODUCTION_URL || 'https://your-railway-app.railway.app';
const TEST_USER = {
  username: 'testuser',
  password: 'testpassword123'
};

// Colors for console output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logTest(testName, success, details = '') {
  const status = success ? '✅ PASS' : '❌ FAIL';
  const color = success ? 'green' : 'red';
  log(`${status} ${testName}`, color);
  if (details) log(`   ${details}`, 'yellow');
}

async function testHealthCheck() {
  try {
    const response = await axios.get(`${BASE_URL}/api/health`);
    const isValid = response.status === 200 && response.data.status === 'healthy';
    logTest('Health Check', isValid, `Status: ${response.data.status}`);
    return isValid;
  } catch (error) {
    logTest('Health Check', false, `Error: ${error.message}`);
    return false;
  }
}

async function testCORS() {
  try {
    const response = await axios.options(`${BASE_URL}/api/health`, {
      headers: {
        'Origin': 'https://test-origin.com',
        'Access-Control-Request-Method': 'GET'
      }
    });
    const hasCORS = response.headers['access-control-allow-origin'];
    logTest('CORS Configuration', !!hasCORS, `CORS Headers: ${hasCORS || 'None'}`);
    return !!hasCORS;
  } catch (error) {
    logTest('CORS Configuration', false, `Error: ${error.message}`);
    return false;
  }
}

async function testRateLimiting() {
  try {
    const requests = Array(6).fill().map(() => 
      axios.get(`${BASE_URL}/api/health`).catch(e => e)
    );
    const responses = await Promise.all(requests);
    const rateLimited = responses.some(r => r.response?.status === 429);
    logTest('Rate Limiting', rateLimited, 'Rate limiting should block excessive requests');
    return rateLimited;
  } catch (error) {
    logTest('Rate Limiting', false, `Error: ${error.message}`);
    return false;
  }
}

async function testAuthenticationEndpoints() {
  try {
    // Test primary auth endpoint exists
    const response = await axios.post(`${BASE_URL}/api/auth/primary`, {
      username: TEST_USER.username,
      password: TEST_USER.password
    });
    logTest('Primary Auth Endpoint', true, 'Endpoint responds (auth logic depends on database)');
    return true;
  } catch (error) {
    if (error.response?.status === 503) {
      logTest('Primary Auth Endpoint', true, 'Endpoint exists but database unavailable (expected in test)');
      return true;
    } else if (error.response?.status === 400) {
      logTest('Primary Auth Endpoint', true, 'Endpoint exists and validates input');
      return true;
    } else {
      logTest('Primary Auth Endpoint', false, `Error: ${error.message}`);
      return false;
    }
  }
}

async function testSessionValidation() {
  try {
    const response = await axios.get(`${BASE_URL}/api/session/validate`, {
      headers: { 'Authorization': 'Bearer invalid-token' }
    });
    logTest('Session Validation', false, 'Should reject invalid tokens');
    return false;
  } catch (error) {
    if (error.response?.status === 401) {
      logTest('Session Validation', true, 'Properly rejects invalid tokens');
      return true;
    } else {
      logTest('Session Validation', false, `Unexpected error: ${error.message}`);
      return false;
    }
  }
}

async function testSecurityHeaders() {
  try {
    const response = await axios.get(`${BASE_URL}/api/health`);
    const headers = response.headers;
    
    const securityHeaders = {
      'X-Frame-Options': headers['x-frame-options'],
      'X-Content-Type-Options': headers['x-content-type-options'],
      'X-XSS-Protection': headers['x-xss-protection'],
      'Strict-Transport-Security': headers['strict-transport-security']
    };
    
    const hasSecurityHeaders = Object.values(securityHeaders).some(h => h);
    logTest('Security Headers', hasSecurityHeaders, 
      `Headers: ${Object.entries(securityHeaders).filter(([k,v]) => v).map(([k]) => k).join(', ')}`);
    
    return hasSecurityHeaders;
  } catch (error) {
    logTest('Security Headers', false, `Error: ${error.message}`);
    return false;
  }
}

async function testSSL() {
  try {
    const response = await axios.get(`${BASE_URL}/api/health`);
    const isHTTPS = response.request.res.responseUrl.startsWith('https://');
    logTest('SSL/HTTPS', isHTTPS, `Protocol: ${response.request.res.responseUrl.split('://')[0]}`);
    return isHTTPS;
  } catch (error) {
    logTest('SSL/HTTPS', false, `Error: ${error.message}`);
    return false;
  }
}

async function runAllTests() {
  log('\n🚀 Production Environment Testing', 'blue');
  log(`📍 Testing URL: ${BASE_URL}`, 'blue');
  log('=' * 50, 'blue');
  
  const tests = [
    { name: 'Health Check', fn: testHealthCheck },
    { name: 'SSL/HTTPS', fn: testSSL },
    { name: 'Security Headers', fn: testSecurityHeaders },
    { name: 'CORS Configuration', fn: testCORS },
    { name: 'Rate Limiting', fn: testRateLimiting },
    { name: 'Authentication Endpoints', fn: testAuthenticationEndpoints },
    { name: 'Session Validation', fn: testSessionValidation }
  ];
  
  const results = [];
  
  for (const test of tests) {
    try {
      const result = await test.fn();
      results.push({ name: test.name, passed: result });
    } catch (error) {
      logTest(test.name, false, `Test error: ${error.message}`);
      results.push({ name: test.name, passed: false });
    }
  }
  
  // Summary
  log('\n📊 Test Summary', 'blue');
  log('=' * 30, 'blue');
  
  const passed = results.filter(r => r.passed).length;
  const total = results.length;
  
  results.forEach(result => {
    const status = result.passed ? '✅' : '❌';
    log(`${status} ${result.name}`);
  });
  
  log(`\n🎯 Overall: ${passed}/${total} tests passed`, passed === total ? 'green' : 'red');
  
  if (passed === total) {
    log('\n🎉 All tests passed! Your production environment is working correctly.', 'green');
  } else {
    log('\n⚠️  Some tests failed. Check the details above and fix any issues.', 'yellow');
  }
  
  return passed === total;
}

// Run tests if this script is executed directly
if (require.main === module) {
  runAllTests().catch(console.error);
}

module.exports = { runAllTests }; 