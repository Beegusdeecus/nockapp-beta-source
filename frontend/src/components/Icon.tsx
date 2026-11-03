export function Icon({ name, size = 16 }: { name: 'arrow' | 'back' | 'copy' | 'external' | 'settings' | 'close' | 'plus' | 'message' | 'check' | 'x'; size?: number }) {
  const paths = {
    arrow: <><path d="M4 12h16M14 6l6 6-6 6" /></>,
    back: <><path d="M20 12H4m6-6-6 6 6 6" /></>,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V4H4v12h4" /></>,
    external: <><path d="M14 4h6v6m0-6L10 14M10 4H4v16h16v-6" /></>,
    settings: <><path d="M4 7h16M4 17h16" /><circle cx="9" cy="7" r="3" /><circle cx="15" cy="17" r="3" /></>,
    close: <path d="m6 6 12 12M18 6 6 18" />,
    plus: <path d="M12 5v14M5 12h14" />,
    message: <path d="M4 4h16v12H9l-5 4V4Z" />,
    check: <path d="m5 12 4 4L19 6" />,
    x: <path d="M4 3h4l12 18h-4L4 3Zm16 0L4 21" />,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
