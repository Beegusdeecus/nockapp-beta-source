"""Fixed checkout/package native entrypoint, launched with Python -I -B."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from domain_native import main

raise SystemExit(main())
