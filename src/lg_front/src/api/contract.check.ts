/**
 * Contract check between the kernel's hand-written API types (types.ts) and the OpenAPI document
 * (docs/openapi.json, generated into schema.gen.ts by `npm run gen:api`). Compiled by `tsc -b`, never
 * imported, so it has no runtime cost; a drift fails the type check with the field that differs.
 *
 * What the API sends (`Wire<Schemas['X']>`) must be assignable to the hand-written `X`, so the app
 * never assumes a field or a value the API does not promise. A module checks the types of its own
 * API slice the same way (`src/modules/<id>/api/contract.check.ts`).
 */

import type { Response, Schemas, Wire } from './contract';
import type { MeOut, MfaChallengeOut, MfaConfirmOut, MfaEnrollOut, TokenOut, UserOut } from './types';

export interface ResponseContract {
  MeOut: Response<Wire<Schemas['MeOut']>, MeOut>;
  MfaChallengeOut: Response<Wire<Schemas['MfaChallengeOut']>, MfaChallengeOut>;
  MfaConfirmOut: Response<Wire<Schemas['MfaConfirmOut']>, MfaConfirmOut>;
  MfaEnrollOut: Response<Wire<Schemas['MfaEnrollOut']>, MfaEnrollOut>;
  TokenOut: Response<Wire<Schemas['TokenOut']>, TokenOut>;
  UserOut: Response<Wire<Schemas['UserOut']>, UserOut>;
}
