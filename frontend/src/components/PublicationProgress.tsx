import { useEffect, useState } from 'react';

/** Stage completion is not a prediction of chain confirmation time. */
export function PublicationProgress({ stage, message, startedAt, checkedAt, checking = false, indexed = false }: {
  stage: number; message: string; startedAt: number; checkedAt?: number; checking?: boolean; indexed?: boolean;
}) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000);return () => clearInterval(timer); }, []);
  const elapsed = Math.max(0, Math.floor(now / 1000) - startedAt);
  const duration = elapsed < 60 ? `${elapsed}s` : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
  const shownStage=stage>=4?5:stage===3&&indexed?4:stage;
  return <section className="publication-progress" aria-label="Publication status">
    <ol className="publication-stages" aria-label="Publication stages">
      {['Save', 'Prove', 'Submit', 'Finalize', 'Deliver'].map((label, i) => <li key={label} aria-current={i === shownStage ? 'step' : undefined} className={i < shownStage ? 'complete' : ''}>{label}</li>)}
    </ol>
    <progress aria-label="Publication stages completed" max={5} value={shownStage}/>
    <p role="status">{message}</p>
    <p className="forum-muted">Elapsed {duration}{checkedAt ? ` · Last checked ${Math.max(0, Math.floor(now / 1000) - checkedAt)}s ago` : ''}{checking ? ' · Checking now…' : ''}</p>
    {indexed&&stage<4&&<p className="forum-muted">The chain commitment is finalized. Public-file delivery is checked separately and recovers automatically.</p>}
    {stage === 3 && !indexed && <p className="forum-muted">Checking automatically every 30 seconds while this page is visible. No reliable confirmation countdown is available. You can reopen this thread to resume checking; no extra ticket will be spent.</p>}
  </section>;
}
