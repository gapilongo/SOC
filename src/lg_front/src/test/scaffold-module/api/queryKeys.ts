/** The scaffold module's query keys: every key starts with the module id. */

export const NS = 'scaffold';

export const scaffoldKeys = {
  things: {
    all: [NS, 'things'] as const,
    count: [NS, 'things', 'count'] as const,
  },
} as const;
