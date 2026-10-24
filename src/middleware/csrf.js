const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Same-origin guard for cookie-authenticated state-changing requests. */
export function sameOriginOnly(appOrigin, isProduction) {
  return function sameOriginMiddleware(req, res, next) {
    if (SAFE_METHODS.has(req.method)) return next();
    const origin = req.get('origin');
    if (!origin && !isProduction) return next(); // Allows local command-line testing.
    if (!origin || origin !== appOrigin) {
      return res.status(403).json({ error: 'Request origin was not accepted.' });
    }
    next();
  };
}
