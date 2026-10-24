const ACCESS_COOKIE = 'tv_access';
const REFRESH_COOKIE = 'tv_refresh';

function cookieOptions(config, maxAge) {
  return {
    httpOnly: true,
    secure: config.isProduction,
    sameSite: 'strict',
    path: '/',
    maxAge
  };
}

export function setSessionCookies(res, config, session) {
  const accessMs = Math.max(60_000, Number(session.expires_in || 3600) * 1000);
  res.cookie(ACCESS_COOKIE, session.access_token, cookieOptions(config, accessMs));
  // Supabase refresh tokens rotate. The browser never receives them through JS.
  res.cookie(REFRESH_COOKIE, session.refresh_token, cookieOptions(config, 7 * 24 * 60 * 60 * 1000));
}

export function clearSessionCookies(res, config) {
  const options = { ...cookieOptions(config, 0), maxAge: undefined };
  res.clearCookie(ACCESS_COOKIE, options);
  res.clearCookie(REFRESH_COOKIE, options);
}

export function createAuthMiddleware({ admin, createPublicClient, config }) {
  return async function authenticate(req, res, next) {
    const accessToken = req.cookies?.[ACCESS_COOKIE];
    const refreshToken = req.cookies?.[REFRESH_COOKIE];
    if (!accessToken && !refreshToken) {
      return res.status(401).json({ error: 'Please sign in.' });
    }

    let token = accessToken;
    let authResult = token ? await admin.auth.getUser(token) : { data: { user: null }, error: new Error('No access token') };

    if (authResult.error && refreshToken) {
      const publicClient = createPublicClient();
      const refreshed = await publicClient.auth.refreshSession({ refresh_token: refreshToken });
      if (!refreshed.error && refreshed.data.session) {
        setSessionCookies(res, config, refreshed.data.session);
        token = refreshed.data.session.access_token;
        authResult = await admin.auth.getUser(token);
      }
    }

    if (authResult.error || !authResult.data?.user) {
      clearSessionCookies(res, config);
      return res.status(401).json({ error: 'Your session is invalid or expired. Please sign in again.' });
    }

    const { data: profile, error: profileError } = await admin
      .from('profiles')
      .select('id, email, full_name, role')
      .eq('id', authResult.data.user.id)
      .maybeSingle();

    if (profileError || !profile) {
      await admin.auth.admin.signOut(token).catch(() => {});
      clearSessionCookies(res, config);
      return res.status(403).json({ error: 'Your account is not provisioned for TrustVault.' });
    }

    req.user = {
      id: profile.id,
      email: profile.email,
      full_name: profile.full_name,
      fullName: profile.full_name,
      role: profile.role
    };
    next();
  };
}

export const cookieNamesForTesting = { ACCESS_COOKIE, REFRESH_COOKIE };
