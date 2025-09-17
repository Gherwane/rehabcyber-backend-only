# REHABCYBER Backend - Railway Deployment Package

## Files Included
- `server.js` - Main server application
- `package.json` - Node.js dependencies
- `Procfile` - Railway deployment configuration
- `.gitignore` - Git ignore rules

## Deployment Instructions

### 1. Go to Railway
Visit: https://railway.app

### 2. Create New Project
- Click "New Project"
- Select "Empty Project"
- Name: `rehabcyber-backend`

### 3. Upload Files
- Click "Add Service"
- Select "GitHub Repo" or drag & drop these files
- Upload all files in this folder

### 4. Set Environment Variables
In Railway dashboard → Variables tab:
```
NODE_ENV=production
JWT_SECRET=your-super-secret-jwt-key-here
PORT=3000
```

### 5. Deploy
- Railway will automatically detect Node.js
- Wait for deployment to complete
- Get your Railway URL

### 6. Test
Visit: `https://your-railway-url.up.railway.app/api/health`

## Next Steps
After deployment, update your frontend HTML files to use the Railway URL instead of `localhost:3000`.

Example:
```javascript
// Change this:
fetch('http://localhost:3000/api/search', ...)

// To this:
fetch('https://your-railway-url.up.railway.app/api/search', ...)
```

## Support
If you need help, the deployment process takes about 5-10 minutes total.
