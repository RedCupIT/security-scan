/**
 * Cloudflare Worker — GitHub Org Webhook Relay
 *
 * Receives org-level webhook events from GitHub and forwards them to the
 * security-scan repo as `repository_dispatch` events, triggering scans.
 *
 * Required environment variables (set in Cloudflare dashboard or wrangler.toml):
 *   GITHUB_WEBHOOK_SECRET  — the secret you set on the org webhook
 *   GITHUB_TOKEN           — PAT with repo scope on the security-scan repo
 *   SECURITY_SCAN_REPO     — e.g. "my-org/security-scan"
 */

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    const body = await request.text();

    // Verify GitHub webhook signature
    const sigHeader = request.headers.get('x-hub-signature-256');
    if (!sigHeader) {
      return new Response('Missing signature', { status: 401 });
    }

    const valid = await verifySignature(body, sigHeader, env.GITHUB_WEBHOOK_SECRET);
    if (!valid) {
      return new Response('Invalid signature', { status: 401 });
    }

    const event = request.headers.get('x-github-event');
    const payload = JSON.parse(body);

    let dispatchType = null;
    let clientPayload = {};

    // ── Pull request opened, reopened, or new commits pushed ──────────────
    if (event === 'pull_request' && ['opened', 'reopened', 'synchronize'].includes(payload.action)) {
      dispatchType = 'pull_request_scan';
      clientPayload = {
        repo:      payload.repository.full_name,
        sha:       payload.pull_request.head.sha,
        ref:       payload.pull_request.head.ref,
        pr_number: String(payload.pull_request.number),
      };
    }

    // ── Push to default branch (covers new repos on first push and direct-to-main commits) ──
    if (event === 'push' && !payload.deleted) {
      const defaultBranch = payload.repository.default_branch || 'main';
      const pushedRef = payload.ref; // e.g. "refs/heads/main"
      if (pushedRef === `refs/heads/${defaultBranch}`) {
        dispatchType = 'default_branch_scan';
        clientPayload = {
          repo:      payload.repository.full_name,
          sha:       payload.after,
          ref:       pushedRef,
          pr_number: '',
        };
      }
    }

    if (!dispatchType) {
      // Event not relevant — acknowledge and ignore
      return new Response('Event ignored', { status: 200 });
    }

    // ── Dispatch to the security-scan repo ────────────────────────────────
    const [owner, repo] = env.SECURITY_SCAN_REPO.split('/');
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/dispatches`,
      {
        method: 'POST',
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
          'Content-Type': 'application/json',
          'User-Agent': 'security-scan-relay/1.0',
          'X-GitHub-Api-Version': '2022-11-28',
        },
        body: JSON.stringify({
          event_type: dispatchType,
          client_payload: clientPayload,
        }),
      }
    );

    if (!response.ok) {
      const err = await response.text();
      console.error('Dispatch failed:', response.status, err);
      return new Response('Dispatch failed', { status: 502 });
    }

    return new Response('Dispatched', { status: 200 });
  },
};

// ── HMAC-SHA256 signature verification ─────────────────────────────────────
async function verifySignature(body, sigHeader, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
  const expected = 'sha256=' + Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return timingSafeEqual(sigHeader, expected);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
