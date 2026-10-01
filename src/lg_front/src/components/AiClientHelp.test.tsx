import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { AiClientHelp, MCP_DOCS_URL } from './AiClientHelp';

describe('AiClientHelp', () => {
  it('points to the MCP setup guide in a new tab without an opener', () => {
    render(<AiClientHelp />);
    expect(screen.getByText(/Connect an AI client/)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Setup guide (docs/mcp.md)' });
    expect(link).toHaveAttribute('href', MCP_DOCS_URL);
    expect(MCP_DOCS_URL).toMatch(/^https:\/\/github\.com\/gapilongo\/SOC\/blob\/main\/docs\/mcp\.md$/);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('says AI clients never approve', () => {
    render(<AiClientHelp />);
    expect(screen.getByText(/never approve actions or decide escalations/)).toBeInTheDocument();
  });
});
