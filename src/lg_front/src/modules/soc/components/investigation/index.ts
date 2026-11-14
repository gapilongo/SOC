/**
 * Presentational parts of an investigation, shared by the investigation view
 * and any list or preview that shows one: the three voices (observed,
 * claimed, decided), the outcome headline, what is not established, the
 * track record and the steps. They render the read model of
 * api/investigation.ts and fetch nothing.
 */
export { ClaimRow } from './ClaimRow';
export { Glyph, type GlyphName } from './glyphs';
export { NotEstablished } from './NotEstablished';
export { Observation, outcomeWords } from './Observation';
export { OutcomeHeadline, OutcomeTag, outcomeKind, outcomeLabel, splitHeadline, type OutcomeKind } from './OutcomeHeadline';
export { SeverityBars } from './SeverityBars';
export { StepList } from './StepList';
export { MAX_SQUARES, TrackRecord } from './TrackRecord';
export { FactChip, Keycap, SmallTag, VoiceMark, VoiceTag, type Voice } from './voices';
