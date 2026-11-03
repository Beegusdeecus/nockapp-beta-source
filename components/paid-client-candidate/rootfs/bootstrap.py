import sys
sys.path[:0]=['/opt/nockapp/research/zkid','/usr/lib/python3.14/site-packages']
mode=sys.argv.pop(1)
from domain_native import configuration,authorize,main
if mode=='check':
 config=configuration();authorize(sys.argv[1:],config['browser'])
 if config.get('profile') in ('nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-renewal-v1'):
  from public_installation import factory
  from pathlib import Path
  factory(config,Path('/opt/nockapp/research/zkid'))
 print('{"configuration_checked":true}')
elif mode=='native':raise SystemExit(main())
elif mode in ('authorship-backup','authorship-restore'):
 from installed_authorship_recovery import main as recovery
 raise SystemExit(recovery(mode.removeprefix('authorship-')))
else:raise SystemExit(1)
