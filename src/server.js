import 'dotenv/config';
import { loadConfig } from './config.js';
import { createSupabaseClients } from './supabase.js';
import { createApp } from './app.js';

const config = loadConfig();
const { admin, createPublicClient } = createSupabaseClients(config);
const app = createApp({ admin, createPublicClient, config });

app.listen(config.port, () => {
  console.log(`TrustVault listening on port ${config.port}`);
  console.log(`Environment: ${config.nodeEnv}`);
  console.log('Health endpoint: /api/health');
});
