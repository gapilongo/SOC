/** Where the MCP setup guide lives (docs/mcp.md in the repository). */
export const MCP_DOCS_URL = 'https://github.com/gapilongo/SOC/blob/main/docs/mcp.md';

/**
 * "Connect an AI client" help shown next to the API keys: Claude Code and other MCP clients use an API key
 * through `lg-sotf mcp` (docs/mcp.md). They read and propose; approvals stay in this app.
 */
export function AiClientHelp() {
  return (
    <p className="mb-3 text-xs text-slate-400">
      <span className="font-medium text-slate-200">Connect an AI client: </span>
      Claude Code and other MCP clients use an API key through <code className="font-mono">lg-sotf mcp</code>. Give the
      key only the scopes it needs (<code className="font-mono">read</code>; testers <code className="font-mono">ingest</code>{' '}
      and <code className="font-mono">read</code>) and keep it in a file only its owner can read. AI clients never approve
      actions or decide escalations.{' '}
      <a href={MCP_DOCS_URL} target="_blank" rel="noopener noreferrer" className="text-sky-300 underline">
        Setup guide (docs/mcp.md)
      </a>
    </p>
  );
}
