# Railway Troubleshooting Guide

## 🚨 Common Railway Deployment Issues

### Issue: "server.crt is missing" Error

**Problem**: Server tries to read SSL certificates that don't exist on Railway

**Solution**: ✅ **FIXED** - The server now automatically detects Railway environment and skips local certificates

**What happens now**:
- Railway environment detected automatically
- Server uses HTTP (Railway handles HTTPS)
- No local certificates needed
- SSL termination handled by Railway load balancer

### Issue: Database Connection Fails

**Problem**: `ECONNREFUSED` when connecting to PostgreSQL

**Solution**:
1. **Add PostgreSQL service** in Railway dashboard
2. **Railway automatically sets `DATABASE_URL`**
3. **Verify service is running**

```bash
# Check if DATABASE_URL is set
railway variables

# Restart the service
railway service restart
```

### Issue: Redis Connection Fails

**Problem**: Redis connection timeout or refused

**Solution**:
1. **Add Redis service** in Railway dashboard
2. **Railway automatically sets `REDIS_URL`**
3. **Server will fall back to in-memory storage if Redis unavailable**

### Issue: Environment Variables Missing

**Problem**: Server fails due to missing JWT secrets

**Solution**: Set required environment variables:

```bash
railway variables set NODE_ENV=production
railway variables set JWT_SECRET=your-super-secret-jwt-key-here
railway variables set JWT_REFRESH_SECRET=your-super-secret-refresh-key-here
railway variables set GATEWAY_SECRET=your-gateway-secret-key
```

### Issue: Health Check Fails

**Problem**: Railway reports unhealthy deployment

**Solution**:
1. **Check logs**: `railway logs`
2. **Verify `/api/health` endpoint** returns 200
3. **Check environment variables** are set
4. **Restart service**: `railway service restart`

## 🔍 Debug Commands

```bash
# Check Railway logs
railway logs

# Check environment variables
railway variables

# Check service status
railway status

# Restart service
railway service restart

# Check deployment
railway deployments
```

## 📊 Expected Logs

**Successful startup**:
```
☁️  Detected cloud environment, using HTTP server (SSL handled by platform)
✅ Redis connected successfully
✅ Database connected successfully
🚀 Gateway Server running on port 3000 (HTTPS handled by platform)
```

**If Redis unavailable**:
```
⚠️  Redis connection failed, continuing without Redis
✅ Database connected successfully
🚀 Gateway Server running on port 3000 (HTTPS handled by platform)
```

**If Database unavailable**:
```
⚠️  Database connection failed in development mode, continuing without database
🚀 Gateway Server running on port 3000 (HTTPS handled by platform)
```

## 🎯 Quick Fix Checklist

- [ ] **Environment variables set** (JWT_SECRET, etc.)
- [ ] **PostgreSQL service added**
- [ ] **Redis service added** (optional)
- [ ] **NODE_ENV=production** set
- [ ] **Latest code deployed**
- [ ] **Health check passing**

## 🆘 Still Having Issues?

1. **Check Railway status**: https://status.railway.app/
2. **Railway Discord**: https://discord.gg/railway
3. **Railway Docs**: https://docs.railway.app/
4. **GitHub Issues**: For application-specific problems

## 🔄 Redeploy Process

If you need to redeploy:

```bash
# Force redeploy
railway up

# Or restart service
railway service restart

# Check deployment status
railway deployments
```

## 📈 Monitoring

Railway provides:
- **Real-time logs**
- **Performance metrics**
- **Health check monitoring**
- **Automatic restarts**

Monitor your deployment in the Railway dashboard! 