"""Isolated, hardened entry point for explicit first-journal installation."""
def main():
    import ctypes
    from pathlib import Path
    import resource
    import sys
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if not sys.flags.isolated or not sys.dont_write_bytecode or ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        return 1
    sys.path[:0] = [str(Path(__file__).resolve().parent),
                    '/usr/lib/python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor) + '/site-packages']
    try:
        from ticket_first_journal_process_v1 import main as run
        return run()
    except BaseException:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
