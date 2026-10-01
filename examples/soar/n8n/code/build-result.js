// Turn the vendor call's outcome into the answer LG-SOTF records on the action ledger, and remember
// it so a retry of the same action id is answered from static data instead of acting twice.
// Static data is kept only by production executions of the active workflow (not by test runs).
const MAX_AGE_S = 7 * 24 * 3600;
const MAX_ENTRIES = 2000;

const verified = $('Verify LG-SOTF signature').first().json;
const result = $input.first().json || {};
const base = { action_id: verified.action_id, action_type: verified.action_type };

if (result.verdict === 'execute') {
  // The placeholder HTTP Request node is still disabled and passed the item through: nothing was done.
  const response = { status: 'rejected', error: 'not_implemented', message: 'connect and enable the TODO node', ...base };
  return [{ json: { status_code: 200, response } }];
}

const httpStatus = typeof result.statusCode === 'number' ? result.statusCode : null;
const ok = !result.error && httpStatus !== null && httpStatus >= 200 && httpStatus < 300;
const response = ok
  ? { status: 'succeeded', ...base, detail: { http_status: httpStatus } }
  : { status: 'failed', error: 'vendor_call_failed', ...base, detail: { http_status: httpStatus } };

const store = $getWorkflowStaticData('global');
const now = Math.floor(Date.now() / 1000);
const kept = Object.entries(store.lgsotfActions || {})
  .filter(([, entry]) => entry && now - entry.at < MAX_AGE_S)
  .sort((a, b) => b[1].at - a[1].at)
  .slice(0, MAX_ENTRIES - 1);
store.lgsotfActions = Object.fromEntries([
  [verified.action.id, { at: now, action_type: verified.action.type, target: verified.action.target, response }],
  ...kept,
]);

return [{ json: { status_code: 200, response } }];
