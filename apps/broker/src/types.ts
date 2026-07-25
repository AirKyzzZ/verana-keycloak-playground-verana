export type PositiveVerdict = "TRUSTED_AUTHORIZED";

export interface AuthorizedIdentity {
  subjectId: string;
  organization: "ACME";
  role: "employee";
  issuerDid: string;
  verifierDid: string;
}

export interface PairwiseSubInput {
  secret: Uint8Array;
  issuerDid: string;
  subjectId: string;
  sectorIdentifier: string;
}

export interface ExpectedReceipt {
  sessionId: string;
  vct: string;
  vtjscId: string;
  network: string;
  ecosystemId: number;
  credentialSchemaId: number;
}

export interface LoginTransaction {
  uid: string;
  vsSessionId: string;
  authorizationRequest: string;
  createdAt: number;
  expiresAt: number;
  status: "pending" | "verified" | "denied" | "unavailable" | "used";
  accountId?: string;
  errorCode?: string;
}

export interface CreateLoginTransaction {
  uid: string;
  vsSessionId: string;
  authorizationRequest: string;
}
