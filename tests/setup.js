// Test setup file
process.env.NODE_ENV = 'test';

// Mock environment variables for testing
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
process.env.GATEWAY_SECRET = 'test-gateway-secret';
process.env.PRIVATE_API_URL = 'https://test-api.internal';
process.env.ALLOWED_ORIGINS = 'http://localhost:3000';

// Suppress console logs during tests
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}; 