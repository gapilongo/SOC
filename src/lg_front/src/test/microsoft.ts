/** Microsoft capability catalog fixtures (the shape of GET /integrations/microsoft/catalog). */

import type { MicrosoftCapabilityOut } from '../modules/soc/api/types';

export const ISOLATION: MicrosoftCapabilityOut = {
  key: 'defender.isolation',
  package: 'defender',
  api: 'defender',
  title: 'Machine isolation',
  description: 'Isolates machines in Defender for Endpoint.',
  actions: {
    isolate_host: { reversible: true, rollback_window_s: 86400, note: '', inverse: 'release_host', risk: 'high' },
    release_host: { reversible: false, note: '', restorative: true, risk: 'high' },
  },
  permissions: [
    { api: 'defender', role: 'Machine.Isolate', purpose: 'isolate machines', required: true, when: '' },
    { api: 'defender', role: 'Machine.Read.All', purpose: 'find machines', required: true, when: '', directory_role: null },
  ],
  options_schema: {
    type: 'object',
    properties: {
      isolation_type: { enum: ['Full', 'Selective'], type: 'string', title: 'Isolation type', default: 'Full' },
      max_machines: { type: 'integer', minimum: 1, maximum: 10, title: 'Max machines', default: 1 },
      comment_prefix: { type: 'string', maxLength: 40, title: 'Comment prefix', default: '' },
      allow_servers: { type: 'boolean', title: 'Allow servers', default: false },
      excluded_tags: { type: 'array', items: { type: 'string' }, maxItems: 5, title: 'Excluded tags' },
      ratio: { type: 'number', title: 'Ignored' },
    },
  },
  options_defaults: { isolation_type: 'Full', max_machines: 1, comment_prefix: '', allow_servers: false, excluded_tags: [] },
  clouds: ['global'],
  licence: 'Defender for Endpoint P1',
  live_confirmation: 'Isolated machines lose network access until released.',
  excludes: [],
};

export const QUARANTINE: MicrosoftCapabilityOut = {
  ...ISOLATION,
  key: 'defender.stop_quarantine',
  title: 'Stop and quarantine',
  actions: { quarantine_file: { reversible: false, note: 'cannot be undone' } },
  options_schema: { type: 'object', properties: {} },
  options_defaults: {},
  live_confirmation: '',
  excludes: ['defender.isolation'],
};
