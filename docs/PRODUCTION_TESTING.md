# Production Testing Guide

This guide explains how to thoroughly test your production deployment on Railway.

## 🚀 Quick Start Testing

### 1. **Automated Testing Script**

```bash
# Set your production URL
export PRODUCTION_URL=https://your-railway-app.railway.app

# Run comprehensive tests
npm run test:prod
```

### 2. **Manual Health Check**

```bash
# Test basic connectivity
curl https://your-railway-app.railway.app/api/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## 🧪 Comprehensive Testing

### **What the Test Script Checks**

1. **✅ Health Check** - Server is running and responding
2. **🔒 SSL/HTTPS** - Secure connection is working
3. **🛡️ Security Headers** - Proper security headers are set
4. **🌐 CORS Configuration** - Cross-origin requests are handled
5. **⏱️ Rate Limiting** - Protection against abuse is active
6. **🔐 Authentication Endpoints** - Auth endpoints are accessible
7. **🎫 Session Validation** - Token validation works correctly

### **Running Specific Tests**

```bash
# Test just health check
curl -s https://your-railway-app.railway.app/api/health | jq

# Test SSL certificate
openssl s_client -connect your-railway-app.railway.app:443 -servername your-railway-app.railway.app

# Test security headers
curl -I https://your-railway-app.railway.app/api/health

# Test CORS
curl -H "Origin: https://test-origin.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS \
     https://your-railway-app.railway.app/api/health
```

## 🔍 Manual Testing Checklist

### **Basic Connectivity**
- [ ] Server responds to health check
- [ ] HTTPS is working (no certificate errors)
- [ ] Custom domain works (if configured)

### **Security Features**
- [ ] Security headers are present
- [ ] CORS is properly configured
- [ ] Rate limiting is active
- [ ] Invalid tokens are rejected

### **API Endpoints**
- [ ] All authentication endpoints respond
- [ ] Session validation works
- [ ] Error handling is proper
- [ ] Database operations work (if database is set up)

### **Performance**
- [ ] Response times are acceptable
- [ ] No memory leaks
- [ ] Handles concurrent requests
- [ ] Graceful error handling

## 🛠️ Testing Tools

### **1. cURL Commands**

```bash
# Health check
curl https://your-railway-app.railway.app/api/health

# Test authentication (should return 400 or 503)
curl -X POST https://your-railway-app.railway.app/api/auth/primary \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'

# Test session validation (should return 401)
curl -H "Authorization: Bearer invalid-token" \
  https://your-railway-app.railway.app/api/session/validate

# Test rate limiting
for i in {1..10}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    https://your-railway-app.railway.app/api/health
done
```

### **2. Browser Testing**

1. **Open Developer Tools** (F12)
2. **Check Network tab** for:
   - HTTPS connections
   - Security headers
   - Response times
3. **Check Console** for any errors
4. **Test CORS** by making requests from different origins

### **3. Postman/Insomnia**

Create a collection with these requests:

```json
{
  "name": "Production API Tests",
  "requests": [
    {
      "name": "Health Check",
      "method": "GET",
      "url": "https://your-railway-app.railway.app/api/health"
    },
    {
      "name": "Primary Auth",
      "method": "POST",
      "url": "https://your-railway-app.railway.app/api/auth/primary",
      "headers": {
        "Content-Type": "application/json"
      },
      "body": {
        "mode": "raw",
        "raw": "{\"username\":\"test\",\"password\":\"test\"}"
      }
    },
    {
      "name": "Session Validation",
      "method": "GET",
      "url": "https://your-railway-app.railway.app/api/session/validate",
      "headers": {
        "Authorization": "Bearer invalid-token"
      }
    }
  ]
}
```

## 📊 Monitoring & Alerts

### **Railway Dashboard**
- Monitor CPU, memory, and network usage
- Check deployment logs for errors
- Set up alerts for service failures

### **Health Check Monitoring**
```bash
# Set up automated health checks
while true; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    https://your-railway-app.railway.app/api/health)
  if [ "$response" != "200" ]; then
    echo "Health check failed: $response"
    # Send alert (email, Slack, etc.)
  fi
  sleep 60
done
```

### **Performance Monitoring**
```bash
# Test response times
time curl -s https://your-railway-app.railway.app/api/health > /dev/null

# Load testing (install apache bench first)
ab -n 100 -c 10 https://your-railway-app.railway.app/api/health
```

## 🚨 Troubleshooting

### **Common Issues**

**1. Health Check Fails**
```bash
# Check Railway logs
railway logs

# Check if service is running
railway status

# Restart service
railway service restart
```

**2. SSL Certificate Issues**
- Railway handles SSL automatically
- Check if custom domain is configured correctly
- Verify DNS settings

**3. Database Connection Issues**
```bash
# Check if DATABASE_URL is set
railway variables

# Check database service status
railway service list
```

**4. Rate Limiting Too Aggressive**
- Adjust rate limits in environment variables
- Monitor actual traffic patterns
- Consider different limits for different endpoints

### **Debug Commands**

```bash
# Check Railway environment
railway status
railway variables
railway logs

# Test from different locations
curl -I https://your-railway-app.railway.app/api/health

# Check SSL certificate
echo | openssl s_client -connect your-railway-app.railway.app:443 -servername your-railway-app.railway.app 2>/dev/null | openssl x509 -noout -dates
```

## 🎯 Success Criteria

Your production deployment is working correctly when:

- ✅ **Health check returns 200**
- ✅ **HTTPS is working without warnings**
- ✅ **Security headers are present**
- ✅ **Rate limiting is active**
- ✅ **Authentication endpoints respond properly**
- ✅ **Invalid tokens are rejected with 401**
- ✅ **CORS is configured correctly**
- ✅ **Response times are under 1 second**
- ✅ **No errors in Railway logs**

## 📈 Continuous Testing

### **Automated Testing Pipeline**

```yaml
# Example GitHub Actions workflow
name: Production Testing
on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  test-production:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm install
      - run: npm run test:prod
        env:
          PRODUCTION_URL: ${{ secrets.PRODUCTION_URL }}
```

### **Monitoring Dashboard**

Consider setting up monitoring with:
- **Uptime Robot** - For basic uptime monitoring
- **Pingdom** - For performance monitoring
- **Railway Analytics** - Built-in monitoring
- **Custom alerts** - Email/Slack notifications

## 🚀 Next Steps

1. **Run the automated test script**
2. **Perform manual testing**
3. **Set up monitoring and alerts**
4. **Document any issues found**
5. **Implement fixes if needed**
6. **Schedule regular testing**

Your production environment should now be thoroughly tested and ready for real users! 🎉 