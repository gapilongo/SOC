/**
 * What a response action acts on (a process, host, user, address), exactly as
 * the API sent it. One presentation wherever a human approves an action: the
 * pending card of the Approvals page and the pre-approval list of the
 * decision page.
 */
export function ActionTarget({ target }: { target: string }) {
  return <code className="break-all font-mono text-xs text-fg">{target}</code>;
}
