# Railway Deployment Guide

This guide explains how to deploy the Secure Gateway Server to Railway.

## 🚀 Quick Deploy

1. **Connect your repository to Railway**
2. **Set environment variables** (see below)
3. **Deploy automatically** - Railway will detect the Node.js app

## 🔧 Environment Variables

Set these in your Railway project dashboard:

### Required Variables
```bash
NODE_ENV=production
JWT_SECRET=your-super-secret-jwt-key-here-make-it-long-and-random
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here-make-it-long-and-random
GATEWAY_SECRET=your-gateway-secret-key
```

### Optional Variables
```bash
# Database (Railway will provide DATABASE_URL automatically)
# Redis (Railway will provide REDIS_URL automatically)

# Private API Configuration
PRIVATE_API_URL=https://your-private-api.com
ALLOWED_ORIGINS=https://your-frontend-domain.com

# Security
BCRYPT_ROUNDS=12
SESSION_SECRET=your-session-secret-key

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX_REQUESTS=5
```

## 🔒 SSL/HTTPS

**Railway automatically handles SSL termination** - no certificate setup needed!

- ✅ HTTPS is automatically enabled
- ✅ SSL certificates are managed by Railway
- ✅ Custom domains are supported
- ✅ No local certificate files required

## 🗄️ Database Setup

Railway provides PostgreSQL automatically:

1. **Add PostgreSQL service** in Railway dashboard
2. **Railway sets `DATABASE_URL`** automatically
3. **Tables are created** automatically on first run

## 📊 Redis Setup

Railway provides Redis automatically:

1. **Add Redis service** in Railway dashboard
2. **Railway sets `REDIS_URL`** automatically
3. **No additional configuration needed**

## 🏥 Health Check

Railway automatically monitors your app at `/api/health`

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## 🔍 Troubleshooting

### Common Issues

**1. Server won't start**
- Check environment variables are set
- Verify `NODE_ENV=production`
- Check Railway logs for errors

**2. Database connection fails**
- Ensure PostgreSQL service is added
- Check `DATABASE_URL` is set automatically
- Verify database service is running

**3. Redis connection fails**
- Ensure Redis service is added
- Check `REDIS_URL` is set automatically
- Verify Redis service is running

**4. SSL certificate errors**
- Railway handles SSL automatically
- No local certificates needed
- Check if you're using the latest code

### Debug Commands

```bash
# Check Railway logs
railway logs

# Check environment variables
railway variables

# Restart the service
railway service restart

# Check service status
railway status
```

## 📈 Monitoring

Railway provides built-in monitoring:

- **Logs**: Real-time application logs
- **Metrics**: CPU, memory, network usage
- **Health checks**: Automatic uptime monitoring
- **Alerts**: Email notifications for failures

## 🔄 Deployment Process

1. **Push to main branch** → Automatic deployment
2. **Railway builds** the application
3. **Environment variables** are injected
4. **Health check** verifies deployment
5. **Traffic is routed** to new version

## 🎯 Production Checklist

- [ ] Environment variables set
- [ ] Database service added
- [ ] Redis service added
- [ ] Health check passing
- [ ] SSL certificate working
- [ ] Custom domain configured (optional)
- [ ] Monitoring alerts set up

## 📞 Support

- **Railway Docs**: https://docs.railway.app/
- **Railway Discord**: https://discord.gg/railway
- **GitHub Issues**: For application-specific issues

## 🚀 Next Steps

1. **Deploy to Railway**
2. **Test all endpoints**
3. **Configure custom domain** (optional)
4. **Set up monitoring alerts**
5. **Monitor performance metrics** 