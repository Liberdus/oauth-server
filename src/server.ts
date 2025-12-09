import Fastify from "fastify";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import NodeCache from "node-cache";
import path from "path";
import "dotenv/config";

const fastify = Fastify({
  logger:
    process.env.LOGGING === "true"
      ? {
          level: process.env.LOG_LEVEL || "info",
        }
      : false,
});

// Initialize cache with 10 minute TTL
const cache = new NodeCache({ stdTTL: 600, checkperiod: 120 });

// CORS configuration
fastify.register(cors, {
  origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
  credentials: true,
});

// Static file server for client.html
fastify.register(fastifyStatic, {
  root: path.join(__dirname, ".."),
  prefix: "/",
});

// Types
interface AuthQuery {
  sessionId: string;
  provider: string;
}

interface PollQuery {
  sessionId: string;
}

interface SaveBody {
  sessionId: string;
  token: string;
}

interface SessionData {
  provider: string;
  createdAt: number;
}

// OAuth provider configurations
const OAUTH_CONFIGS = {
  google: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    scopes: ["https://www.googleapis.com/auth/drive.file"],
  },
};

/**
 * GET /auth?sessionId=xxx&provider=google
 * Saves sessionId and redirects to OAuth provider
 */
fastify.get<{ Querystring: AuthQuery }>("/auth", async (request, reply) => {
  const { sessionId, provider } = request.query;

  // Validate parameters
  if (!sessionId || !provider) {
    return reply.code(400).send({
      error: "Missing required parameters: sessionId and provider",
    });
  }

  if (provider !== "google") {
    return reply.code(400).send({
      error: 'Unsupported provider. Only "google" is supported.',
    });
  }

  // Validate sessionId format (basic UUID check)
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(sessionId)) {
    return reply.code(400).send({
      error: "Invalid sessionId format. Must be a valid UUID.",
    });
  }

  // Save session data
  const sessionData: SessionData = {
    provider,
    createdAt: Date.now(),
  };
  cache.set(sessionId, sessionData);

  fastify.log.info({ sessionId, provider }, "Session created");

  // Build OAuth URL
  const config = OAUTH_CONFIGS[provider];
  const redirectUri = `${process.env.SERVER_URL}/done`;

  const oauthUrl = new URL(config.authUrl);
  oauthUrl.searchParams.set("client_id", process.env.GOOGLE_CLIENT_ID || "");
  oauthUrl.searchParams.set("redirect_uri", redirectUri);
  oauthUrl.searchParams.set("response_type", "token");
  oauthUrl.searchParams.set("scope", config.scopes.join(" "));
  oauthUrl.searchParams.set("state", sessionId);
  oauthUrl.searchParams.set("prompt", "consent");

  // Redirect to OAuth provider
  return reply.redirect(oauthUrl.toString(), 302);
});

/**
 * GET /done
 * OAuth callback page that extracts token from URL fragment and sends to server
 */
fastify.get("/done", async (_request, reply) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>OAuth Complete</title>
    </head>
    <body>
      <script>
        (function() {
          const params = new URLSearchParams(window.location.hash.substring(1));
          const accessToken = params.get('access_token');
          const state = params.get('state');
          const error = params.get('error');

          if (error) {
            console.error('OAuth error:', error);
            window.close();
            return;
          }

          if (!accessToken || !state) {
            console.error('Missing access_token or state');
            window.close();
            return;
          }

          // Send token to server
          fetch('/auth/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              sessionId: state,
              token: accessToken,
              expiresIn: params.get('expires_in'),
              tokenType: params.get('token_type'),
              scope: params.get('scope')
            })
          })
          .then(response => {
            if (!response.ok) {
              console.error('Failed to save token');
            }
          })
          .catch(err => console.error('Error saving token:', err))
          .finally(() => {
            // Close window after sending token
            setTimeout(() => window.close(), 500);
          });
        })();
      </script>
    </body>
    </html>
  `;

  return reply.type("text/html").send(html);
});

/**
 * POST /auth/save
 * Saves the OAuth token for a session
 */
fastify.post<{ Body: SaveBody }>("/auth/save", async (request, reply) => {
  const { sessionId, token } = request.body;

  if (!sessionId || !token) {
    return reply.code(400).send({
      error: "Missing required fields: sessionId and token",
    });
  }

  // Verify session exists
  const session = cache.get<SessionData>(sessionId);
  if (!session) {
    return reply.code(404).send({
      error: "Session not found or expired",
    });
  }

  // Save token with session
  cache.set(`token:${sessionId}`, token);

  fastify.log.info({ sessionId }, "Token saved successfully");

  return reply.send({ success: true });
});

/**
 * GET /auth/poll?sessionId=xxx
 * Long poll endpoint that returns token when available
 */
fastify.get<{ Querystring: PollQuery }>(
  "/auth/poll",
  async (request, reply) => {
    const { sessionId } = request.query;

    if (!sessionId) {
      return reply.code(400).send({
        error: "Missing required parameter: sessionId",
      });
    }

    // Verify session exists
    const session = cache.get<SessionData>(sessionId);
    if (!session) {
      return reply.code(404).send({
        error: "Session not found or expired",
      });
    }

    const pollTimeout = 60000; // 60 seconds
    const pollInterval = 1000; // Check every 1 second
    const startTime = Date.now();

    // Long polling implementation
    const checkToken = (): Promise<string | null> => {
      return new Promise((resolve) => {
        const check = () => {
          const token = cache.get<string>(`token:${sessionId}`);

          if (token) {
            resolve(token);
            return;
          }

          if (Date.now() - startTime >= pollTimeout) {
            resolve(null);
            return;
          }

          setTimeout(check, pollInterval);
        };

        check();
      });
    };

    const token = await checkToken();

    if (token) {
      fastify.log.info({ sessionId }, "Token retrieved via poll");
      return reply.send({
        success: true,
        token,
        sessionId,
      });
    } else {
      return reply.code(408).send({
        error: "Request timeout. Token not available yet.",
        sessionId,
      });
    }
  }
);

/**
 * GET /health
 * Health check endpoint
 */
fastify.get("/health", async (_request, reply) => {
  return reply.send({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/**
 * Start server
 */
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || "3000", 10);
    const host = process.env.HOST || "0.0.0.0";

    await fastify.listen({ port, host });

    console.log(`
╔════════════════════════════════════════╗
║     OAuth Server Running               ║
║     Port: ${port.toString().padEnd(29)}║
║     Environment: ${(process.env.NODE_ENV || "development").padEnd(22)}║
╚════════════════════════════════════════╝
    `);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on("SIGINT", async () => {
  console.log("\nShutting down gracefully...");
  await fastify.close();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\nShutting down gracefully...");
  await fastify.close();
  process.exit(0);
});

start();
