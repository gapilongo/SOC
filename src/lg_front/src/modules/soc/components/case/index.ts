/**
 * Presentational parts of a case, shared by the case page and any list
 * that says who or what closed an alert. They render the case read model
 * (`CaseOut`, api/types.ts) and fetch nothing.
 */
export { AlertWhy, ClosedBy, CloserMark, auditWords, closerKind, closerLabel, closerOf, decisionWords, reopenedByPerson, tierWords, type CloserKind } from './ClosedBy';
