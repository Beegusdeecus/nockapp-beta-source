import { exact, object } from './zkidWire';
import type { Identity as LegacyIdentity } from './bundleDiscussion';
type Identity = Pick<LegacyIdentity, 'chain_id' | 'contract' | 'application'>;

export const ARCHIVE_PROFILE = 'nockapp-public-bundle-archive-v1';
export const ARCHIVE_BYTES = 8 * 1024 * 1024;
export const ARCHIVE_RECORDS = 128;
export type ArchiveScope = { chain_id: 84532; contract: string; application: string };
export type ArchiveRecord = { post_number: string; bundle_hash: string; bundle_base64: string };
export type PublicArchive = { profile: typeof ARCHIVE_PROFILE; scope: ArchiveScope; partial: true;
  records: ArchiveRecord[]; missing_post_numbers: string[] };
export type ArchiveExport = { profile: typeof ARCHIVE_PROFILE; scope: ArchiveScope; record: ArchiveRecord; experimental: true };
export type ArchiveImport = { post_number: string; bundle_hash: string; cached: boolean; verification_required: true; experimental: true };

export const archiveNumber = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,15}$/.test(v)
  && Number.isSafeInteger(Number(v));
export const archiveHash = (v: unknown): v is string => typeof v === 'string' && /^0x[0-9a-f]{64}$/.test(v);
export function validArchiveScope(v: unknown): v is ArchiveScope {
  return object(v) && exact(v, ['chain_id', 'contract', 'application']) && v.chain_id === 84532 && archiveHash(v.application)
    && typeof v.contract === 'string' && /^0x[0-9a-f]{40}$/.test(v.contract);
}
export function scopeMatches(scope: ArchiveScope, identity: Identity): boolean {
  return scope.chain_id === identity.chain_id && scope.contract === identity.contract && scope.application === identity.application;
}
export function validArchiveRecord(v: unknown): v is ArchiveRecord {
  if (!object(v) || !exact(v, ['post_number', 'bundle_hash', 'bundle_base64']) || !archiveNumber(v.post_number)
    || !archiveHash(v.bundle_hash) || typeof v.bundle_base64 !== 'string' || !v.bundle_base64.length || v.bundle_base64.length > 43692) return false;
  try { const decoded = atob(v.bundle_base64);return decoded.length <= 32768 && btoa(decoded) === v.bundle_base64; } catch { return false; }
}
export function parsePublicArchive(text: string, identity: Identity): PublicArchive {
  if (new TextEncoder().encode(text).length > ARCHIVE_BYTES) throw Error('Archive exceeds the 8 MiB limit.');
  const v: unknown = JSON.parse(text);
  if (!object(v) || !exact(v, ['profile', 'scope', 'partial', 'records', 'missing_post_numbers']) || v.profile !== ARCHIVE_PROFILE
    || v.partial !== true || !validArchiveScope(v.scope) || !scopeMatches(v.scope, identity)
    || !Array.isArray(v.records) || !v.records.length || v.records.length > ARCHIVE_RECORDS || !v.records.every(validArchiveRecord)
    || !Array.isArray(v.missing_post_numbers) || v.missing_post_numbers.length > ARCHIVE_RECORDS || !v.missing_post_numbers.every(archiveNumber)
    || v.records.length + v.missing_post_numbers.length > ARCHIVE_RECORDS
    || new Set([...v.records.map(r => r.post_number), ...v.missing_post_numbers]).size !== v.records.length + v.missing_post_numbers.length)
    throw Error('Unsupported archive, duplicate post number, or different Base application.');
  return v as PublicArchive;
}
