# Production Testing - Quick Reference

## 🚀 Quick Start

```bash
# 1. Set your production URL
export PRODUCTION_URL=https://your-railway-app.railway.app

# 2. Run automated tests
npm run test:prod

# 3. Manual health check
curl https://your-railway-app.railway.app/api/health
```

## 🧪 Test Categories

| Test | Command | Expected Result |
|------|---------|----------------|
| **Health Check** | `curl /api/health` | `{"status":"healthy"}` |
| **SSL/HTTPS** | `curl -I /api/health` | HTTPS URL, no cert errors |
| **Security Headers** | `curl -I /api/health` | X-Frame-Options, etc. |
| **Rate Limiting** | Multiple rapid requests | 429 status after limit |
| **Auth Endpoints** | `POST /api/auth/primary` | 400/503 (not 404) |
| **Session Validation** | `GET /api/session/validate` | 401 for invalid tokens |

## 🔍 Manual Testing

### **Basic Connectivity**
```bash
# Health check
curl https://your-railway-app.railway.app/api/health

# SSL certificate
openssl s_client -connect your-railway-app.railway.app:443

# Security headers
curl -I https://your-railway-app.railway.app/api/health
```

### **Authentication Testing**
```bash
# Test auth endpoint exists
curl -X POST https://your-railway-app.railway.app/api/auth/primary \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'

# Test invalid token rejection
curl -H "Authorization: Bearer invalid-token" \
  https://your-railway-app.railway.app/api/session/validate
```

### **Rate Limiting Test**
```bash
# Test rate limiting
for i in {1..10}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    https://your-railway-app.railway.app/api/health
done
```

## 📊 Monitoring

### **Railway Dashboard**
- Check service status
- Monitor logs
- View metrics
- Set up alerts

### **Automated Health Checks**
```bash
# Simple health check loop
while true; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    https://your-railway-app.railway.app/api/health)
  if [ "$response" != "200" ]; then
    echo "Health check failed: $response"
  fi
  sleep 60
done
```

## 🚨 Troubleshooting

### **Common Issues**

| Issue | Check | Fix |
|-------|-------|-----|
| **Health check fails** | `railway logs` | Restart service |
| **SSL errors** | Custom domain config | Check DNS settings |
| **Database errors** | `railway variables` | Add PostgreSQL service |
| **Rate limiting** | Environment variables | Adjust limits |

### **Debug Commands**
```bash
# Railway commands
railway status
railway logs
railway variables
railway service restart

# Network testing
curl -v https://your-railway-app.railway.app/api/health
ping your-railway-app.railway.app
```

## 🎯 Success Criteria

✅ **Health check returns 200**  
✅ **HTTPS works without warnings**  
✅ **Security headers present**  
✅ **Rate limiting active**  
✅ **Auth endpoints respond**  
✅ **Invalid tokens rejected**  
✅ **Response time < 1 second**  
✅ **No errors in logs**  

## 📈 Continuous Testing

### **GitHub Actions Example**
```yaml
name: Production Test
on: [schedule]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm install
      - run: npm run test:prod
        env:
          PRODUCTION_URL: ${{ secrets.PRODUCTION_URL }}
```

### **Monitoring Tools**
- **Uptime Robot** - Basic uptime
- **Pingdom** - Performance
- **Railway Analytics** - Built-in
- **Custom alerts** - Email/Slack

## 📖 Full Documentation

See `docs/PRODUCTION_TESTING.md` for complete guide. 