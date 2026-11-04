"""Fixed measured renewal-only entrypoint; Python -I -B -S."""
import sys
sys.path[:0]=['/opt/nockapp/research/zkid',
    '/usr/lib/python'+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'/site-packages']
from public_renewal_runtime_v1 import main
raise SystemExit(main())
