/**
 * Acme Corp - Main Application Bundle (TEST FILE)
 * This file contains intentionally planted secrets, endpoints, and patterns
 * for testing the JS Recon Scanner.
 */

// ===== SECRETS (should be detected by patterns.py) =====

// AWS credentials (CRITICAL)
const AWS_CONFIG = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "us-east-1"
};

// Stripe keys (CRITICAL + LOW)
const STRIPE_PUB = "pk_xxxx_51HG8k2CjKa8nQ4xR3v2w5y7z9B1dF3g";

// GitHub token (HIGH)
const GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh0123";

// Firebase config (HIGH)
const firebaseConfig = {
  apiKey: "AIzaSyB1234567890abcdefghijklmnopqrstuv",
  authDomain: "acme-prod.firebaseapp.com",
  databaseURL: "https://acme-prod-db.firebaseio.com",
  projectId: "acme-prod",
  storageBucket: "acme-prod.appspot.com"
};

// SendGrid key (HIGH)
const SENDGRID_KEY = "SG.abcdefghijklmnopqrstuv.1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabc";

// Telegram bot (HIGH)
const BOT_TOKEN = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

// Sentry DSN (MEDIUM)
const SENTRY_DSN = "https://a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4@o123456.ingest.sentry.io/1234567";

// JWT token (MEDIUM)
const SESSION = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

// Database URIs (HIGH)
const MONGO_URI = "mongodb+srv://admin:SuperSecret123@cluster0.abc123.mongodb.net/production";
const REDIS_URL = "redis://default:r3d1sP4ss@redis-prod.acme.internal:6379";

// Private key marker (CRITICAL)
const CERT = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...\n-----END RSA PRIVATE KEY-----";

// Generic hardcoded password (MEDIUM)
const config = {
  password: "AcmeAdmin2024!",
  apiSecret: "super-secret-api-key-12345678",
};

// ===== ACME CORP CUSTOM SECRETS (detected by custom_patterns.json) =====

const ACME_API = "ACME-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
const ACME_SVC = "acme_svc_ABCDEFGHIJKLMNOPQRSTUVwx";
const DB_CREDENTIALS = "DB_PASS=SuperSecretDbPassword123!";
const JWT_SECRET = "ACME_JWT_SECRET=dGhpcyBpcyBhIHRlc3QganVzdCBzZWNyZXQga2V5IQ==";

// ===== ENDPOINTS (should be detected by endpoints.py) =====

// REST API calls
fetch('/api/v2/users', { method: 'GET' });
fetch('/api/v2/users/profile', { method: 'POST', body: JSON.stringify(data) });
fetch('/api/admin/dashboard', { method: 'GET' });
fetch('/api/internal/health-check');

// Axios calls
axios.get('/api/v1/products');
axios.post('/api/v1/orders', orderData);
axios.delete('/api/v1/sessions/' + sessionId);

// Config object with base URL
const apiConfig = {
  baseURL: "https://api.acme.com/v3",
  endpoints: {
    users: "/users",
    payments: "/payments",
    admin: "/admin/settings"
  }
};

// GraphQL
const GRAPHQL_QUERY = `
  query GetUsers {
    users {
      id
      name
      email
      role
    }
  }
`;
const GQL_ENDPOINT = "/graphql";

// GraphQL introspection (MEDIUM finding)
const INTROSPECTION = `query { __schema { types { name } } }`;

// WebSocket
const ws = new WebSocket('wss://realtime.acme.com/events');
const socket = io('https://socket.acme.com/chat');

// API documentation endpoints (MEDIUM)
const SWAGGER_URL = "/swagger-ui/index.html";
const OPENAPI = "/openapi.json";

// Debug/admin endpoints (HIGH)
fetch('/actuator/env');
fetch('/debug/pprof');
fetch('/admin/users/impersonate');

// Auth endpoints
fetch('/api/oauth/token', { method: 'POST' });
fetch('/api/auth/login');
fetch('/api/auth/2fa/verify');

// Custom endpoint keywords (detected by endpoint_keywords.txt)
fetch('/acme-api/v1/internal-config');
fetch('/internal-v2/admin-console/settings');
fetch('/backoffice/reports/generate');
fetch('/staging-api/user-management/bulk-import');
fetch('/debug-panel/cache-clear');

// ===== DEPENDENCY CONFUSION (should be detected by dependency.py) =====

import { AuthClient } from '@acme/auth-sdk';
import { ApiHelper } from '@acme/api-client';
import { Logger } from '@acme-internal/logging';
import { MetricsClient } from '@acme-internal/metrics';
import { FeatureFlags } from '@acme/feature-flags';

// Well-known packages (should NOT be flagged)
import React from 'react';
import { useState } from 'react';
import axios from 'axios';
import lodash from 'lodash';
import { Button } from '@mui/material';

// Webpack chunk names
/* webpackChunkName: "@acme/payment-gateway" */

// ===== FRAMEWORKS (should be detected by framework.py) =====

// React detection
React.createElement("div", null, "Hello");
React.version = "18.2.0";

// Next.js detection
window.__NEXT_DATA__ = { props: {}, page: "/dashboard" };

// jQuery detection
jQuery.fn.jquery = "3.7.1";

// Custom framework (detected by custom_frameworks.json)
AcmeUI.init({ theme: 'dark', locale: 'en' });
AcmeUI.version = "2.4.1";
window.__ACME_UI__ = {};

AcmeRouter.navigate('/dashboard');
window.__ACME_ROUTER__ = {};

const store = AcmeStore.createStore({ debug: true });
AcmeStore.version = "1.0.3";

// ===== DOM SINKS (should be detected by framework.py) =====

// innerHTML (HIGH)
document.getElementById("output").innerHTML = userInput;

// eval (CRITICAL)
var result = eval(userCode);

// document.write (HIGH)
document.write("<script src='" + untrustedUrl + "'></script>");

// dangerouslySetInnerHTML (HIGH - React)
const HtmlContent = () => <div dangerouslySetInnerHTML={{__html: rawHtml}} />;

// Prototype pollution (HIGH)
obj.__proto__.isAdmin = true;
constructor.prototype.role = "superadmin";

// postMessage without origin check (MEDIUM)
window.postMessage({ action: "login", token: sessionToken }, "*");

// location manipulation (MEDIUM)
location.href = redirectUrl;
window.open(externalLink);

// ===== DEV COMMENTS (should be detected by patterns.py) =====

// TODO: Remove this hardcoded admin password before production deploy
// FIXME: This bypass allows unauthenticated access to admin panel
// HACK: Temporary workaround for auth - using hardcoded token
// BUG: Session tokens are not being rotated properly
// XXX: Debug credentials left in for testing - remove before release
// TEMP: Using production database credentials for local development

// ===== CLOUD ASSETS (should be detected by patterns.py) =====

const S3_BUCKET = "https://acme-uploads.s3.amazonaws.com/documents";
const S3_BUCKET_2 = "https://s3.us-east-1.amazonaws.com/acme-backups";
const GCS_BUCKET = "https://storage.googleapis.com/acme-prod-assets";
const GCS_ALT = "gs://acme-ml-models";
const AZURE_BLOB = "https://acmestorage.blob.core.windows.net/reports";

// ===== INFRASTRUCTURE (should be detected by patterns.py) =====

// Internal/staging URLs (LOW)
const STAGING = "https://staging-api.acme.internal/v2";
const DEV_SERVER = "https://dev.acme-test.com/api";

// Localhost with ports (LOW)
const LOCAL_API = "localhost:3000";
const LOCAL_DB = "127.0.0.1:5432";

// Private IPs (LOW)
const INTERNAL_SERVER = "192.168.1.100:8080";
const DB_HOST = "10.0.1.50";

// ===== EMAIL ADDRESSES (should be detected, example.com filtered) =====

const ADMIN_EMAIL = "admin@acme.com";
const DEVOPS = "devops@acme.com";
const SUPPORT = "support@acme-corp.com";
const TEST_EMAIL = "test@example.com";  // should be filtered out

// ===== UUIDs / IDOR TARGETS (should be detected by patterns.py) =====

const USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const TENANT_ID = "6ba7b810-9dad-41d4-80b7-00c04fd430c8";
const ORDER_ID = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

// ===== DEBUG FLAGS (LOW) =====
const DEBUG = true;
const NODE_ENV = "development";

// ===== SOURCE MAP REFERENCE (for sourcemap.py) =====
//# sourceMappingURL=test_app.js.map
