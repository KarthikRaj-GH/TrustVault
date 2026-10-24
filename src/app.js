import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAuthMiddleware } from './middleware/auth.js';
import { sameOriginOnly } from './middleware/csrf.js';
import { createAuthRouter } from './routes/auth.js';
import { createDocumentsRouter } from './routes/documents.js';
import { createAdminRouter } from './routes/admin.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function createApp({ admin, createPublicClient, config }) {
  const app = express();
  app.disable('x-powered-by');
  if (config.isProduction) app.set('trust proxy', 1);
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false
  }));
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());
  app.use(sameOriginOnly(config.appOrigin, config.isProduction));

  const authenticate = createAuthMiddleware({ admin, createPublicClient, config });
  app.get('/api/health', (_req, res) => res.json({ status: 'ok', service: 'trustvault' }));
  app.use('/api/auth', createAuthRouter({ admin, createPublicClient, config, authenticate }));
  app.use('/api/documents', createDocumentsRouter({ admin, authenticate, config }));
  app.use('/api/admin', createAdminRouter({ admin, authenticate }));
  app.use(express.static(path.resolve(here, '../public'), { index: 'index.html', extensions: ['html'] }));

  app.use((req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found.' });
    return res.status(404).sendFile(path.resolve(here, '../public/index.html'));
  });

  app.use((error, req, res, _next) => {
    const status = Number.isInteger(error.status) ? error.status :
      error.code === 'LIMIT_FILE_SIZE' ? 413 : 500;
    if (status >= 500) console.error('REQUEST_FAILED', { method: req.method, path: req.path, message: error.message });
    const message = status >= 500 ? 'The request could not be completed. Check server logs if you administer this service.' : error.message;
    if (res.headersSent) return res.end();
    return res.status(status).json({ error: message });
  });
  return app;
}
