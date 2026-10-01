// No branch of "Route by action type" matches (for example an action type added to LG-SOTF after
// this workflow was imported): answer rejected, so LG-SOTF records the action as failed.
const verified = $input.first().json;
const response = {
  status: 'rejected',
  error: 'unsupported_action_type',
  action_id: verified.action_id,
  action_type: verified.action_type,
};
return [{ json: { status_code: 200, response } }];
