// LG-SOTF response action: check the signature, the timestamp and the Idempotency-Key exactly as
// the LG-SOTF webhook connector signs, then look the action id up in this workflow's static data.
// Setup (docs/soar-playbooks.md): the Webhook node's "Raw Body" option on; self-hosted n8n needs
// NODE_FUNCTION_ALLOW_BUILTIN=crypto; the secret lives in the n8n variable (or environment
// variable) LGSOTF_WEBHOOK_SECRET. Never paste the secret into this node.
const crypto = require('crypto');

const SCHEMA = 'lg-sotf.response-action.v1';
const EVENT = 'response_action.execute';
const TOLERANCE_S = 300;
const SIGNATURE_HEADER = 'x-lgsotf-signature';
const TIMESTAMP_HEADER = 'x-lgsotf-timestamp';
const IDEMPOTENCY_HEADER = 'idempotency-key';

function readSecret() {
  const readers = [() => $vars.LGSOTF_WEBHOOK_SECRET, () => $env.LGSOTF_WEBHOOK_SECRET];
  for (const read of readers) {
    try {
      const value = read();
      if (typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 16) return value;
    } catch (error) {
      // $vars needs an n8n plan with variables; $env is blocked unless N8N_BLOCK_ENV_ACCESS_IN_NODE=false.
    }
  }
  // Fail closed: the execution errors (visible in n8n) and LG-SOTF records the action as failed.
  throw new Error('LGSOTF_WEBHOOK_SECRET is not set (n8n variable or environment variable, at least 16 bytes)');
}

const answer = (verdict, statusCode, response, extra) => [
  { json: { verdict, status_code: statusCode, response, ...(extra || {}) } },
];
// One answer for every authentication failure: the sender learns nothing about which check failed.
const unauthorized = () => answer('reject', 401, { status: 'rejected', error: 'unauthorized' });

const secret = readSecret();
const headers = $input.first().json.headers || {};
const timestamp = typeof headers[TIMESTAMP_HEADER] === 'string' ? headers[TIMESTAMP_HEADER] : '';
const signature = typeof headers[SIGNATURE_HEADER] === 'string' ? headers[SIGNATURE_HEADER] : '';
if (!/^[0-9]{1,15}$/.test(timestamp) || !/^v1=[0-9a-f]{64}$/.test(signature)) return unauthorized();
if (Math.abs(Date.now() / 1000 - Number(timestamp)) > TOLERANCE_S) return unauthorized();

let raw;
try {
  raw = await helpers.getBinaryDataBuffer(0, 'data');
} catch (error) {
  throw new Error('No raw body: turn on the "Raw Body" option of the LG-SOTF webhook node');
}
const expected = 'v1=' + crypto.createHmac('sha256', secret).update(timestamp + '.').update(raw).digest('hex');
if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature))) return unauthorized();

let payload = null;
try {
  payload = JSON.parse(raw.toString('utf8'));
} catch (error) {
  payload = null;
}
const action = payload && typeof payload.action === 'object' && payload.action !== null ? payload.action : {};
if (typeof action.id !== 'string' || !action.id) {
  return answer('reject', 400, { status: 'rejected', error: 'malformed_payload' });
}
// The Idempotency-Key header is not signed: it must be the signed action id when present.
if (IDEMPOTENCY_HEADER in headers && headers[IDEMPOTENCY_HEADER] !== action.id) return unauthorized();

const base = { action_id: action.id.slice(0, 64), action_type: String(action.type || '').slice(0, 64) };
if (payload.schema !== SCHEMA || payload.event !== EVENT) {
  return answer('reject', 200, { status: 'rejected', error: 'unsupported_schema', ...base });
}

// A repeated action id (a retry, or a re-run after an interruption) gets the original answer.
const seen = ($getWorkflowStaticData('global').lgsotfActions || {})[action.id];
if (seen && seen.response) {
  if (seen.action_type !== action.type || seen.target !== action.target) {
    return answer('reject', 409, { status: 'rejected', error: 'idempotency_conflict', ...base });
  }
  return answer('duplicate', 200, seen.response);
}

return answer('execute', 200, null, {
  ...base,
  tenant_id: payload.tenant_id,
  action,
  alert: payload.alert || {},
  // A rollback (release_host, unblock_ip, ...): the id of the action to undo; null otherwise.
  rollback_of: typeof payload.rollback_of === 'string' && payload.rollback_of ? payload.rollback_of : null,
});
