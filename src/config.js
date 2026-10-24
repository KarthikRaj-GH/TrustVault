export function loadConfig(env = process.env) {
  const required = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY'];
  const missing = required.filter((key) => !env[key]);
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}. Copy .env.example to .env and configure it.`);
  }

  const isProduction = env.NODE_ENV === 'production';
  if (isProduction && !env.APP_ORIGIN) {
    throw new Error('APP_ORIGIN must be set to the deployed HTTPS origin in production.');
  }

  const maxUploadMb = Number.parseInt(env.MAX_UPLOAD_MB || '10', 10);
  if (!Number.isInteger(maxUploadMb) || maxUploadMb < 1 || maxUploadMb > 25) {
    throw new Error('MAX_UPLOAD_MB must be an integer from 1 to 25.');
  }

  return {
    nodeEnv: env.NODE_ENV || 'development',
    isProduction,
    port: Number.parseInt(env.PORT || '3000', 10),
    appOrigin: env.APP_ORIGIN || 'http://localhost:3000',
    supabaseUrl: env.SUPABASE_URL,
    supabaseAnonKey: env.SUPABASE_ANON_KEY,
    supabaseServiceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY,
    bucket: env.SUPABASE_BUCKET || 'trustvault-private',
    maxUploadBytes: maxUploadMb * 1024 * 1024
  };
}
