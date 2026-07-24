/// <reference types="node" />

import { createHmac } from "node:crypto";

import type { PairwiseSubInput } from "./types.js";

export function derivePairwiseSub(input: PairwiseSubInput): string {
  const value = [input.issuerDid, input.subjectId, input.sectorIdentifier].join(
    "\u001f",
  );

  return createHmac("sha256", input.secret)
    .update(value, "utf8")
    .digest("base64url");
}
