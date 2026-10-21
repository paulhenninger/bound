// Demo topology. Each party is a separate origin, as it would be in production.
const env = (k, d) => process.env[k] ?? d;

export const ISSUER = env('BOUND_ISSUER', 'http://localhost:4100');
export const RP = env('BOUND_RP', 'http://localhost:4200');
export const RS = env('BOUND_RS', 'http://localhost:4300');

export const port = (origin) => Number(new URL(origin).port);

// Token lifetimes (seconds). Short on purpose: renewal replaces refresh tokens.
export const IDENTITY_TTL = Number(env('BOUND_IDENTITY_TTL', 120));
export const ACCESS_TTL = Number(env('BOUND_ACCESS_TTL', 300));
export const RENEW_WINDOW = Number(env('BOUND_RENEW_WINDOW', 8 * 3600));

// Resource servers the issuer knows about, and what they can be asked for.
export const RESOURCE_SERVERS = {
  [RS]: { name: 'Notes API', actions: { read: 'Read your notes', write: 'Create and delete your notes' } },
};
