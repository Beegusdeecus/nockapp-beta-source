import { useEffect, useRef, useState } from 'react';
import { bundleOperation, type Identity } from '../bundleDiscussion';
import { ARCHIVE_BYTES, ARCHIVE_PROFILE, ARCHIVE_RECORDS, parsePublicArchive, scopeMatches,
  type ArchiveExport, type ArchiveImport, type PublicArchive as Archive } from '../bundleArchive';

export function PublicArchive({ identity, numbers, disabled, onBusy, onRestored, operation = bundleOperation }: {
  identity: Pick<Identity, 'chain_id' | 'contract' | 'application'>; operation?: <T>(op: 'bundle-export-public' | 'bundle-import-public', body: Record<string, unknown>, signal?: AbortSignal) => Promise<T>; numbers: string[]; disabled: boolean; onBusy: (value: boolean) => void; onRestored: () => Promise<unknown>;
}) {
  const [notice, setNotice] = useState('');const [download, setDownload] = useState<string>();
  const [running, setRunning] = useState(false);
  const active = useRef<AbortController | undefined>(undefined);const url = useRef<string | undefined>(undefined);
  const busyCallback = useRef(onBusy);busyCallback.current = onBusy;
  useEffect(() => () => { active.current?.abort();if (url.current) URL.revokeObjectURL(url.current); }, []);
  async function run(work: (signal: AbortSignal) => Promise<void | boolean>) {
    if (active.current || disabled) return;
    const controller = new AbortController();active.current = controller;setRunning(true);onBusy(true);setNotice('');
    let refresh = false;
    try { refresh = await work(controller.signal) === true; }
    catch (error) { if (!controller.signal.aborted) setNotice(error instanceof Error ? error.message : 'Archive unavailable. Existing data is preserved.'); }
    finally { active.current = undefined;setRunning(false);busyCallback.current(false);
      if (controller.signal.aborted) setNotice('Archive work stopped. Any public bytes already cached remain; drafts and credentials are unchanged.'); }
    if (refresh && !controller.signal.aborted) await onRestored();
  }
  async function exportLoaded(signal: AbortSignal) {
    if (url.current) URL.revokeObjectURL(url.current);url.current = undefined;setDownload(undefined);
    const selected = [...new Set(numbers)].slice(0, ARCHIVE_RECORDS);
    const archive: Archive = { profile: ARCHIVE_PROFILE, scope: { chain_id: identity.chain_id, contract: identity.contract,
      application: identity.application }, partial: true, records: [], missing_post_numbers: [] };
    for (const number of selected) {
      if (signal.aborted) return;
      try {
        const value = await operation<ArchiveExport>('bundle-export-public', { post_number: Number(number), approve_public_export: true }, signal);
        if (!scopeMatches(value.scope, identity)) throw Error('Application changed.');
        archive.records.push(value.record);
      } catch { if (signal.aborted) return;archive.missing_post_numbers.push(number); }
    }
    if (!archive.records.length) { setNotice('No public bytes could be exported. Missing content cannot be reconstructed from Base.');return; }
    const text = JSON.stringify(archive);parsePublicArchive(text, identity);
    url.current = URL.createObjectURL(new Blob([text], { type: 'application/json' }));setDownload(url.current);
    setNotice(`${archive.records.length} public records prepared; ${archive.missing_post_numbers.length} unavailable. This is a partial archive of loaded posts.`);
  }
  async function importFile(file: File, signal: AbortSignal) {
    if (file.size > ARCHIVE_BYTES) throw Error('Archive exceeds the 8 MiB limit.');
    const archive = parsePublicArchive(await file.text(), identity);
    let cached = 0, failed = 0;
    for (const record of archive.records) {
      if (signal.aborted) return;
      try {
        const result = await operation<ArchiveImport>('bundle-import-public', { scope: archive.scope, record,
          confirm_public_archive_import: true }, signal);
        if (result.cached) cached++;else failed++;
      } catch { if (signal.aborted) return;failed++; }
    }
    setNotice(`${cached} public records cached; ${failed} unavailable or rejected. Verification is still required. Archive completeness is not established.`);
    return true;
  }
  return <details><summary>Public history archive</summary><section aria-label="Public history archive"><p>Save a partial copy of loaded public posts and selected proof bytes. Drafts and credentials are excluded. Imported bytes must match Base; badges are checked again on refresh.</p>
    <button disabled={disabled || !numbers.length} onClick={() => void run(exportLoaded)}>Prepare archive of loaded public posts</button>
    {running && <button onClick={() => active.current?.abort()}>Stop archive work</button>}
    {download && <p><a href={download} download="nockapp-public-archive.json">Download public archive</a></p>}
    <label>Restore public archive<input type="file" accept="application/json,.json" disabled={disabled} onChange={event => {
      const file = event.target.files?.[0];event.target.value = '';if (file) void run(signal => importFile(file, signal));
    }} /></label><p>At most 128 records and 8 MiB per file. Cache limits still apply; keep the file to retain a larger archive.</p>
    {notice && <p role="status">{notice}</p>}
  </section></details>;
}
