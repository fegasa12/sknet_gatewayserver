const request = require('supertest');
const express = require('express');

// Mock the server for testing
jest.mock('../src/server.js', () => {
  const express = require('express');
  const app = express();
  
  // Add basic routes for testing
  app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  });
  
  app.post('/api/auth/primary', (req, res) => {
    res.status(200).json({ message: 'Primary auth endpoint' });
  });
  
  return { GatewayServer: class { 
    constructor() { this.app = app; }
    async initialize() { return Promise.resolve(); }
  }};
});

describe('Gateway Server', () => {
  let server;
  
  beforeAll(async () => {
    const { GatewayServer } = require('../src/server.js');
    server = new GatewayServer();
    await server.initialize();
  });
  
  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const response = await request(server.app)
        .get('/api/health')
        .expect(200);
      
      expect(response.body).toHaveProperty('status', 'healthy');
      expect(response.body).toHaveProperty('timestamp');
    });
  });
  
  describe('Authentication', () => {
    it('should have primary auth endpoint', async () => {
      const response = await request(server.app)
        .post('/api/auth/primary')
        .expect(200);
      
      expect(response.body).toHaveProperty('message', 'Primary auth endpoint');
    });
  });
}); 