"""Fixed isolated-image entrypoint; invoked with Python -I -B -S."""
import sys

sys.path[:0]=['/opt/nockapp/research/zkid',
              '/usr/lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'/site-packages']
from issuer_supervisor import main

raise SystemExit(main())
