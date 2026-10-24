import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import { clearSessionCookies, setSessionCookies } from '../middleware/auth.js';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Please try again later.' }
});

export function createAuthRouter({ admin, createPublicClient, config, authenticate }) {
  const router = Router();

  router.post('/login', loginLimiter, async (req, res, next) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const password = String(req.body?.password || '');
      if (!email || !password || email.length > 254 || password.length > 1024) {
        return res.status(400).json({ error: 'Enter a valid email and password.' });
      }
      const publicClient = createPublicClient();
      const { data, error } = await publicClient.auth.signInWithPassword({ email, password });
      if (error || !data.session || !data.user) {
        return res.status(401).json({ error: 'Email or password was not accepted.' });
      }
      const { data: profile, error: profileError } = await admin
        .from('profiles').select('id, email, full_name, role').eq('id', data.user.id).maybeSingle();
      if (profileError || !profile) {
        await publicClient.auth.signOut().catch(() => {});
        return res.status(403).json({ error: 'Your account exists but is not provisioned for TrustVault.' });
      }
      setSessionCookies(res, config, data.session);
      return res.json({ user: profile });
    } catch (error) { next(error); }
  });

  router.post('/logout', async (req, res) => {
    try {
      const accessToken = req.cookies?.tv_access;
      const refreshToken = req.cookies?.tv_refresh;
      if (accessToken && refreshToken) {
        const publicClient = createPublicClient();
        const { error } = await publicClient.auth.setSession({ access_token: accessToken, refresh_token: refreshToken });
        if (!error) await publicClient.auth.signOut({ scope: 'local' }).catch(() => {});
      }
    } finally {
      clearSessionCookies(res, config);
    }
    res.status(204).end();
  });

  router.get('/me', authenticate, (req, res) => res.json({ user: req.user }));
  return router;
}
