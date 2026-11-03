import type { CredentialClaim } from './model';

export type CredentialResult =
  | { status: 'demo'; label: string }
  | { status: 'verified'; label: string; issuer: string; expiresAt: number }
  | { status: 'rejected' | 'unavailable'; label: string };

/** Future adapter must validate backend evidence, policy, binding and freshness.
 * A claim or UI label alone is never evidence of verification. */
export interface CredentialVerifier { verify(claim: CredentialClaim): Promise<CredentialResult> }

export const DEMO_CREDENTIALS: CredentialClaim[] = [
  { kind: 'x-account' }, { kind: 'followers-1k' }, { kind: 'followers-10k' },
  { kind: 'followed-by', account: 'demo_researcher' },
];
export function credentialLabel(claim: CredentialClaim): string {
  const labels: Record<CredentialClaim['kind'], string> = {
    'x-account': 'Verified X account', 'followers-1k': '1k+ followers',
    'followers-10k': '10k+ followers', 'followed-by': `Followed by @${claim.account ?? 'demo_account'}`,
  };
  return labels[claim.kind];
}

export class DemoCredentialVerifier implements CredentialVerifier {
  async verify(claim: CredentialClaim): Promise<CredentialResult> {
    return { status: 'demo', label: credentialLabel(claim) };
  }
}
export const credentialVerifier: CredentialVerifier = new DemoCredentialVerifier();
