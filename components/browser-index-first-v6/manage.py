"""Stdlib-only installer/launcher for the frozen public-post native helper.

Explicit administrative paths/approval only; browser messages cannot select them.
No replacement, keyring operation, resource creation or policy auto-enrollment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import struct
import subprocess
import sys

COMPILED=__file__.endswith('.so')
FORMAT='nockapp-zkid-desktop-runtime-v2-compiled' if COMPILED else 'nockapp-zkid-desktop-runtime-v1'
NATIVE='nockapp-zkid-public-post-native-v1'
HOST='com.nockapp.zkid'
APP='opt/nockapp/research/zkid'


def artifact(name):
    # The installed executable selects the layout, never browser/config input.
    return name[:-3]+'.so' if COMPILED and name.endswith('.py') else name


def require(value):
    if not value:raise ValueError('desktop-package-rejected')


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def unique(pairs):
    value={}
    for k,v in pairs:require(k not in value);value[k]=v
    return value


def safe(path):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts and not any(p.startswith('.env') for p in path.parts)
            and not any(p.is_symlink() for p in [path,*path.parents]))
    return path


def read(path,limit=2097152):
    path=safe(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=limit)
        data=stream.read(limit+1);require(len(data)<=limit)
    return json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:require(False))


def digest(path):
    path=safe(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        return hashlib.file_digest(stream,'sha256').hexdigest()


def private(path):
    path=safe(path);require(path not in (Path('/'),Path('/home'),Path('/tmp')))
    path.mkdir(parents=True,mode=0o700,exist_ok=True);info=path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077)
    return path


def write(path,data):
    path=safe(path);data=canonical(data) if type(data) is dict else data
    require(type(data) is bytes)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())


def flush_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def verify(root,expected):
    root=safe(root);require(type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected)
                            and digest(root/'manifest.json')==expected)
    manifest=read(root/'manifest.json')
    require(set(manifest)=={'profile','python','files','bwrap_sha256','private_secrets_included',
                           'independent_source_rebuild','native_profile'} and manifest['profile']==FORMAT
            and manifest['native_profile']==NATIVE and manifest['private_secrets_included'] is False
            and type(manifest['files']) is dict and 0<len(manifest['files'])<=3000)
    observed=set()
    for path in root.rglob('*'):
        relative=str(path.relative_to(root));safe(path)
        require(path.is_file() or path.is_dir())
        if path.is_file():observed.add(relative)
    require(observed==set(manifest['files'])|{'manifest.json'})
    for name,record in manifest['files'].items():
        relative=Path(name);require(not relative.is_absolute() and '..' not in relative.parts
            and str(relative)==name and type(record) is dict and set(record)=={'sha256','bytes','mode'})
        path=safe(root/name);info=path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_size==record['bytes'] and info.st_mode&0o777==record['mode']
                and digest(path)==record['sha256'])
    require(artifact('manage.py') in manifest['files'] and 'rootfs/'+artifact('bootstrap.py') in manifest['files'])
    if COMPILED:require('manage' in manifest['files'])
    return manifest


def copy_package(root,target,manifest,expected):
    require(not target.exists());target.mkdir(mode=0o700)
    for name,record in manifest['files'].items():
        source=safe(root/name);out=target/name;out.parent.mkdir(parents=True,exist_ok=True)
        with source.open('rb') as incoming,out.open('xb') as outgoing:shutil.copyfileobj(incoming,outgoing,1048576)
        out.chmod(record['mode']);require(digest(out)==record['sha256'])
    write(target/'manifest.json',(root/'manifest.json').read_bytes())
    for name in ('tmp','run','home','state','shared','count-state','proc','dev','sys','var','etc','verifier','legacy'):
        (target/'rootfs'/name).mkdir(exist_ok=True)
    verify(target,expected)


def command(program,record,arguments,*,check=False,recovery=None,backup_input=None):
    require(recovery is None or recovery in ('backup','restore') and not check and not arguments)
    require((backup_input is not None)==(recovery=='restore'))
    root=Path(record['package'])/'rootfs'
    require(digest(Path('/usr/bin/bwrap'))==record['bwrap_sha256'])
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}
    args=['/usr/bin/bwrap','--unshare-all',*(['--share-net'] if recovery is None else []),'--die-with-parent','--new-session',
          '--ro-bind',str(root),'/', '--dev','/dev','--proc','/proc','--tmpfs','/tmp','--tmpfs','/run',
          '--tmpfs','/home','--bind',record['state'],'/state',
          '--ro-bind',str(program/'domain-native-config.json'),'/'+APP+'/domain-native-config.json',
          '--ro-bind',str(program/'passwd'),'/etc/passwd','--ro-bind',str(program/'group'),'/etc/group']
    if 'base_state' in record:
        private(Path(record['base_state']));args+=['--bind',record['base_state'],'/shared']
    if 'bundle_state' in record:
        private(Path(record['bundle_state']));args+=['--bind',record['bundle_state'],'/shared']
    if 'count_state' in record:
        private(Path(record['count_state']));args+=['--bind',record['count_state'],'/count-state']
    if 'legacy_states' in record:
        legacy=record['legacy_states'];require(type(legacy) is list and len(legacy)<=8)
        args+=['--tmpfs','/legacy']
        paths=[safe(Path(record['state']))]
        for number,value in enumerate(legacy):
            require(type(value) is str);path=safe(Path(value));require(path.is_dir());private(path)
            require(not any(path.is_relative_to(old) or old.is_relative_to(path) for old in paths));paths.append(path)
            target='/legacy/'+str(number);args+=['--dir',target,'--bind',str(path),target]
    if not check:
        if record.get('public_network') is True and recovery is None:
            # Fixed OS resolver configuration only; no host home, credentials,
            # browser state or caller-selected bind source enters the sandbox.
            resolver=Path('/etc/resolv.conf');info=resolver.stat()
            # Ubuntu's root-owned symlink may point to a service-owned file.
            # DNS is a routing hint; attestation, not resolver ownership, grants trust.
            require(resolver.lstat().st_uid==0 and stat.S_ISREG(info.st_mode) and not info.st_mode&0o022
                    and 0<info.st_size<=65536)
            args+=['--ro-bind',str(resolver),'/etc/resolv.conf']
        verifier=record.get('verifier_socket') if recovery is None else None
        if verifier is not None:
            verifier=safe(Path(verifier));info=verifier.parent.stat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077)
            # Mount ONLY the socket, never the verifier's archive/config/state.
            # Missing service leaves the approved endpoint unavailable; it does
            # not block enrollment or discover an alternative service.
            args+=['--tmpfs','/verifier','--chmod','0700','/verifier']
            if verifier.exists():
                info=verifier.stat();require(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077)
                args+=['--ro-bind',str(verifier),'/verifier/verifier.sock']
        address=record.get('session_bus_address')
        if address is None:address=os.environ.get('DBUS_SESSION_BUS_ADDRESS','')
        # Chromium's native launcher can explicitly disable session D-Bus. This
        # means unavailable, never a bus to discover or bypass. Readonly empty
        # wallet status still works; any key operation fails in SecretService.
        if address=='disabled:':address=''
        require(address=='' or re.fullmatch(r'unix:(?:path|abstract)=[A-Za-z0-9_./-]+(?:,guid=[0-9a-f]{32})?',address))
        if address:
            env['DBUS_SESSION_BUS_ADDRESS']=address
            if address.startswith('unix:path='):
                socket=Path(address.removeprefix('unix:path=').split(',',1)[0])
                require(stat.S_ISSOCK(socket.stat().st_mode));args+=['--ro-bind',str(socket),str(socket)]
    if backup_input is not None:
        backup_input=safe(backup_input);info=backup_input.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
            and not info.st_mode&0o077 and 0<info.st_size<=4096)
        args+=['--ro-bind',str(backup_input),'/tmp/portable-authorship-backup']
    entry=(['-c',"import sys;sys.path.insert(0,'/');import bootstrap"] if COMPILED else ['/bootstrap.py'])
    mode='authorship-'+recovery if recovery is not None else 'check' if check else 'native'
    args+=['/usr/bin/'+record['python'],'-I','-B','-S',*entry,mode,*arguments]
    return args,env


def install(root,expected,approved,extension_id,*,home,browser='chromium',state=None,registration=None,port=None,session_bus_address=None,
            verifier_approval=None,issuer_endpoint=None,base_approval=None,base_chain=None,base_state=None,
            bundle_approval=None,bundle_chain=None,bundle_state=None,count_approval=None,count_state=None):
    root=safe(root);manifest=verify(root,expected);home=safe(home)
    require(home not in (Path('/'),Path('/home'),Path('/tmp')))
    home.mkdir(parents=True,mode=0o700,exist_ok=True);info=home.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022)
    require(browser in ('chromium','google-chrome','firefox'))
    if issuer_endpoint is None:
        port=19440 if port is None else port
        require(type(port) is int and 1<=port<=65535)
    else:require(port is None and type(issuer_endpoint) is dict)
    require(type(extension_id) is str and re.fullmatch(r'[A-Za-z0-9_.@{}-]{1,128}' if browser=='firefox' else '[a-p]{32}',extension_id))
    require(type(approved) is dict)  # Full approval validated INSIDE the pinned runtime before publishing registration.
    require((base_approval is None)==(base_chain is None))
    require(base_state is None or base_approval is not None)
    if base_approval is not None:require(type(base_approval) is dict and type(base_chain) is dict)
    require((bundle_approval is None)==(bundle_chain is None) and (bundle_state is None or bundle_approval is not None))
    require(base_approval is None or bundle_approval is None)
    if bundle_approval is not None:require(type(bundle_approval) is dict and type(bundle_chain) is dict)
    require(count_state is None or count_approval is not None)
    require(count_approval is None or bundle_approval is not None and type(count_approval) is dict)
    remote_verifier=False
    if verifier_approval is not None:
        require(type(verifier_approval) is dict)
        remote_verifier=verifier_approval.get('profile')=='nockapp-zkid-post-attested-client-v1'
        if remote_verifier:
            require(set(verifier_approval)=={'profile','binding','endpoint','code_identity','pcrs'}
                    and type(verifier_approval['endpoint']) is dict)
        else:
            require(set(verifier_approval)=={'profile','binding','certificate_pem','socket_path','uid'}
                    and verifier_approval['profile']=='nockapp-zkid-post-client-approval-v1'
                    and type(verifier_approval['uid']) is int and verifier_approval['uid']==os.getuid())
        binding=verifier_approval['binding'];require(type(binding) is dict and set(binding)=={
            'profile','definition_hash','audience','state_authority_sha256','native_sha256'}
            and binding['profile']=='nockapp-zkid-post-service-binding-v1')
        for name in ('definition_hash','audience','state_authority_sha256','native_sha256'):
            require(type(binding[name]) is str and re.fullmatch('[0-9a-f]{64}',binding[name]) and any(bytes.fromhex(binding[name])))
        require(binding['definition_hash']==approved.get('definition_hash')
                and binding['state_authority_sha256']==approved.get('state_authority_sha256')
                and binding['native_sha256']==read(root/'build-inputs.json')['native_binary_sha256'])
        if not remote_verifier:
            require(type(verifier_approval['certificate_pem']) is str and re.fullmatch(
                r'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]{1,16000}\n-----END CERTIFICATE-----\n',verifier_approval['certificate_pem']))
            endpoint=safe(Path(verifier_approval['socket_path']))
            require(endpoint.name=='verifier.sock' and len(os.fsencode(endpoint))<104)
    require(session_bus_address is None or (type(session_bus_address) is str and re.fullmatch(
        r'unix:(?:path|abstract)=[A-Za-z0-9_./-]+(?:,guid=[0-9a-f]{32})?',session_bus_address)))
    if registration is None:
        registration=(home/'.mozilla/native-messaging-hosts'/ (HOST+'.json') if browser=='firefox' else
                      home/'.config'/browser/'NativeMessagingHosts'/(HOST+'.json'))
    registration=safe(registration)
    require(registration.is_relative_to(home) and registration.name==HOST+'.json' and not registration.exists())
    state=private(state if state is not None else home/'.local/share/nockapp-zkid')
    if base_approval is not None:
        base_state=private(base_state if base_state is not None else home/'.local/share/nockapp-base')
        require(not base_state.is_relative_to(state) and not state.is_relative_to(base_state))
    if bundle_approval is not None:
        bundle_state=private(bundle_state if bundle_state is not None else home/'.local/share/nockapp-shared-v3')
        paths=[state,bundle_state]
        if count_approval is not None:
            count_state=private(count_state if count_state is not None else home/'.local/share/nockapp-count-v2');paths.append(count_state)
        for i,path in enumerate(paths):require(not any(path.is_relative_to(p) or p.is_relative_to(path) for p in paths[:i]))
    storage=private(home/'.local/lib/nockapp-zkid');releases=private(storage/'releases');cached=releases/expected
    if cached.exists():verify(cached,expected)
    else:
        staged=releases/('.stage-'+secrets.token_hex(12));copy_package(root,staged,manifest,expected)
        os.rename(staged,cached);flush_directory(releases)
    program=private(storage/'registrations'/secrets.token_hex(16))
    native_root='rootfs/'+APP+'/'
    required=read(root/'build-inputs.json')['native_required']
    if base_approval is not None:required=required+read(root/'build-inputs.json')['base_required']
    if bundle_approval is not None:
        inputs=read(root/'build-inputs.json');required=sorted(set(required)|set(inputs['bundle_required']))
        if bundle_approval.get('identity',{}).get('count_native_sha256') is not None:
            required=sorted(set(required)|set(inputs['count_required']))
    require(type(required) is list and len(set(required))==len(required))
    pins={name:manifest['files'][native_root+artifact(name)]['sha256'] for name in required}
    admission=({'kind':'firefox','extension_id':extension_id,'manifest_path':str(registration)} if browser=='firefox'
               else {'kind':'chrome','origin':'chrome-extension://'+extension_id+'/'})
    config={'profile':NATIVE,'browser':admission,'issuer_approval':approved,
            **({'issuer_port':port} if issuer_endpoint is None else {'issuer_endpoint':issuer_endpoint}),
            'wallet_directory':'/state','files_sha256':pins}
    if verifier_approval is not None:
        config['verifier_approval']=(verifier_approval if remote_verifier else {**verifier_approval,'socket_path':'/verifier/verifier.sock'})
    if base_approval is not None:config.update(base_approval=base_approval,base_chain=base_chain,base_directory='/shared')
    if bundle_approval is not None:
        config.update(bundle_approval=bundle_approval,bundle_chain=bundle_chain,bundle_directory='/shared')
        if count_approval is not None:config.update(count_approval=count_approval,count_wallet_directory='/count-state')
    write(program/'domain-native-config.json',config)
    write(program/'passwd',f'zkid:x:{os.getuid()}:{os.getgid()}:NockApp:/state:/bin/false\n'.encode())
    write(program/'group',f'zkid:x:{os.getgid()}:\n'.encode())
    if COMPILED:
        launcher='#!/bin/sh\nexec '+shlex.quote(str(cached/'manage'))+' host '+shlex.quote(str(program))+' "$@"\n'
    else:
        launcher='#!/bin/sh\nexec /usr/bin/python3 -I -B '+shlex.quote(str(cached/'manage.py'))+' host '+shlex.quote(str(program))+' "$@"\n'
    write(program/'run',launcher.encode());(program/'run').chmod(0o700)
    record={'profile':FORMAT,'package':str(cached),'manifest_sha256':expected,'state':str(state),'browser':browser,
        'registration':str(registration),'extension_id':extension_id,'python':manifest['python'],
        'session_bus_address':session_bus_address,
        'bwrap_sha256':manifest['bwrap_sha256'],'files':{p.name:digest(p) for p in program.iterdir() if p.is_file()}}
    if issuer_endpoint is not None or remote_verifier or base_approval is not None or bundle_approval is not None:record['public_network']=True
    if base_approval is not None:record['base_state']=str(base_state)
    if bundle_approval is not None:record['bundle_state']=str(bundle_state)
    if count_approval is not None:record['count_state']=str(count_state)
    if verifier_approval is not None and not remote_verifier:record['verifier_socket']=str(endpoint)
    write(program/'installation.json',record);flush_directory(program)
    arguments=[str(registration),extension_id] if browser=='firefox' else [admission['origin']]
    args,env=command(program,record,arguments,check=True)
    tested=subprocess.run(args,capture_output=True,timeout=20,env=env)
    require(tested.returncode==0 and not tested.stderr and tested.stdout==b'{"configuration_checked":true}\n')
    registration.parent.mkdir(parents=True,mode=0o700,exist_ok=True);safe(registration.parent)
    native={'name':HOST,'description':'NockApp public-post credential helper','path':str(program/'run'),'type':'stdio',
        **({'allowed_extensions':[extension_id]} if browser=='firefox' else {'allowed_origins':[admission['origin']]})}
    staged=registration.parent/('.zkid-'+secrets.token_hex(12));write(staged,native)
    try:os.link(staged,registration)
    finally:staged.unlink()
    flush_directory(registration.parent)
    return {**record,'program':str(program),'registered':True,'private_state_preserved':True}


def host(program,arguments):
    program=safe(program);record=read(program/'installation.json')
    expected=([record['registration'],record['extension_id']] if record['browser']=='firefox' else
              ['chrome-extension://'+record['extension_id']+'/'])
    require(arguments==expected and record['profile']==FORMAT)
    manifest=verify(Path(record['package']),record['manifest_sha256'])
    require(record['python']==manifest['python'] and record['bwrap_sha256']==manifest['bwrap_sha256'])
    for name,sha in record['files'].items():require(Path(name).name==name and digest(program/name)==sha)
    private(Path(record['state']))
    args,env=command(program,record,arguments);os.execve(args[0],args,env)


def authorship_recovery(program,action,backup_file):
    # Explicit local terminal only: no browser caller, argv/env passphrase,
    # registration update, key discovery or automatic destination overwrite.
    require(sys.stdin.isatty() and sys.stderr.isatty() and action in ('backup','restore'))
    program=safe(program);backup_file=safe(backup_file)
    record=read(program/'installation.json');require(record['profile']==FORMAT)
    manifest=verify(Path(record['package']),record['manifest_sha256'])
    require(record['python']==manifest['python'] and record['bwrap_sha256']==manifest['bwrap_sha256'])
    for name,sha in record['files'].items():require(Path(name).name==name and digest(program/name)==sha)
    for name in ('portable_authorship.py','installed_authorship_recovery.py'):
        require('rootfs/'+APP+'/'+artifact(name) in manifest['files'])
    # The recovery file cannot overlap any protected app/runtime/legacy tree.
    protected=[Path(record['package']),program,Path(record['state'])]
    protected += [Path(record[key]) for key in ('base_state','bundle_state','count_state') if key in record]
    protected += [Path(value) for value in record.get('legacy_states',[])]
    require(all(not backup_file.is_relative_to(safe(path)) and not safe(path).is_relative_to(backup_file) for path in protected))
    if action=='backup':require(not backup_file.exists() and backup_file.parent.is_dir())
    private(Path(record['state']))
    args,env=command(program,record,[],recovery=action,backup_input=backup_file if action=='restore' else None)
    child=subprocess.Popen(args,env=env,stdout=subprocess.PIPE)
    try:
        data=child.stdout.read(4097)
        if len(data)>4096:
            child.kill();child.wait();require(False)
        require(child.wait()==0)
    finally:
        child.stdout.close()
        if child.poll() is None:child.kill();child.wait()
    if action=='backup':
        # Only encrypted backup bytes leave the sandbox. Admit their exact
        # public envelope before persisting, without loading any secrets here.
        require(0<len(data)<=4096)
        value=json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:require(False))
        require(type(value) is dict and canonical(value)==data
            and set(value)=={'profile','format','kdf','salt','nonce','ciphertext'}
            and value['profile']=='nockapp-portable-authorship-secret-v1')
        write(backup_file,data);flush_directory(backup_file.parent)
    else:require(data==b'')
    return {'authorship_backup_complete':action=='backup','authorship_restore_complete':action=='restore',
        'credentials_and_tickets_separate':True,'existing_identity_not_replaced':True}


def unregister(registration):
    registration=safe(registration);native=read(registration,8192)
    require(native['name']==HOST and native['type']=='stdio')
    program=safe(Path(native['path']).parent);record=read(program/'installation.json')
    require(record['profile']==FORMAT and record['registration']==str(registration) and native['path']==str(program/'run'))
    registration.unlink();flush_directory(registration.parent)
    return {'unregistered':True,'private_state_preserved':True,'runtime_and_recovery_preserved':True}


def install_configured(root,expected,extension_id,*,home,browser='chromium',state=None,
                       bundle_state=None,count_state=None,registration=None,session_bus_address=None):
    verify(root,expected);value=read(root/'public-release.json',131072)
    require(set(value)=={'profile','issuer_approval','issuer_endpoint','bundle_approval','bundle_chain','count_approval'}
        and value['profile']=='nockapp-public-beta-config-v1')
    issuer=value['issuer_approval'];service=value['bundle_approval'];identity=service['identity'];count=value['count_approval']
    pins=read(root/'build-inputs.json')
    require(identity['definition_hash']==issuer['definition_hash'] and identity['native_sha256']==pins['native_binary_sha256']
        and identity['count_native_sha256']==count['native_sha256']==pins['count_binary_sha256']
        and all(issuer[k]==service[k] for k in ('code_identity','state_authority_sha256','pcrs'))
        and all(value['issuer_endpoint'][k]==service['endpoint'][k] for k in ('host','port')))
    # The existing frozen configuration check validates every approval/schema,
    # scope and code pin before publishing any native registration.
    return install(root,expected,issuer,extension_id,home=home,browser=browser,state=state,
        bundle_state=bundle_state,count_state=count_state,registration=registration,
        session_bus_address=session_bus_address,issuer_endpoint=value['issuer_endpoint'],
        bundle_approval=service,bundle_chain=value['bundle_chain'],count_approval=count)


def install_public(root,expected,config,extension_id,*,home,browser='chromium',registration=None,session_bus_address=None):
    """Install reviewed public-v6 SOURCE runtime, without adopting or opening keys.

    Config uses explicit host data/legacy paths; only fixed sandbox paths enter
    the native configuration. Full semantic validation runs in the frozen helper.
    An existing native registration is never overwritten.
    """
    require(not COMPILED)
    root=safe(root);manifest=verify(root,expected);home=safe(home)
    require(browser in ('chromium','google-chrome') and type(extension_id) is str and re.fullmatch('[a-p]{32}',extension_id))
    supplied=config
    if type(config) is dict and config.get('profile')=='nockapp-installed-public-renewal-v1':
        require(set(config)=={'profile','browser','installation','renewal_approval','registry_deployment_block'}
            and type(config['installation']) is dict and config['browser']==config['installation'].get('browser'))
        config=config['installation']
    require(type(config) is dict and config.get('profile') in ('nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'))
    fields={'profile','browser','data_directory','chain','issuer','storage','binary_sha256','files_sha256','legacy_wallets'}
    if config['profile']!='nockapp-installed-public-direct-v1':
        fields|={'offer','offer_sha256','payment_endpoint','publication_endpoint','operator_ca_pem'}
    if config['profile'] in ('nockapp-installed-public-native-v7','nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'):fields|={'refund_endpoint','refund_vault','refund_vault_sha256'}
    if config['profile']in ('nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'):fields|={'legacy_ticket_scopes','checkout_scope'}
    require(set(config)==fields)
    if config['profile'] in ('nockapp-installed-public-native-v7','nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'):
        # Reject changed public pins before creating installation directories.
        # Full semantic admission still runs in the frozen helper below.
        policy=config['refund_vault'];endpoint=config['refund_endpoint'];pin=config['refund_vault_sha256']
        require(type(policy) is dict and set(policy)=={'profile','parameters','chain_id','vault','runtime_sha256',
            'authority','pack_price_wei','max_refunds','principal_budget_wei','gas'}
            and type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin)
            and hashlib.sha256(canonical(policy)).hexdigest()==pin and policy['parameters']==config['offer_sha256'])
        routed=type(endpoint) is dict and endpoint.get('profile')=='nockapp-refund-service-routed-endpoint-v1'
        require(type(endpoint) is dict and set(endpoint)=={'profile','host','port','service','offer_sha256','policy_sha256'}|({'connect_host'} if routed else set())
            and endpoint['profile'] in ('nockapp-refund-service-endpoint-v1','nockapp-refund-service-routed-endpoint-v1') and endpoint['service']=='refund'
            and endpoint['offer_sha256']==config['offer_sha256'] and endpoint['policy_sha256']==pin)
    admission={'kind':'chrome','origin':'chrome-extension://'+extension_id+'/'}
    require(config.get('browser')==admission)
    inputs=read(root/'build-inputs.json');pins=inputs.get('public_native')
    require(type(pins) is dict and set(pins) in ({'profile','source_sha256','binary_sha256'},
        {'profile','supported_profiles','source_sha256','binary_sha256'}) and pins['profile']=='nockapp-installed-public-native-v6')
    require(('supported_profiles' not in pins or pins['supported_profiles'] in (['nockapp-installed-public-native-v6','nockapp-installed-public-native-v7'],['nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1'],['nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-renewal-v1'],['nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-renewal-v1','nockapp-installed-public-batch-v1'],['nockapp-installed-public-native-v6','nockapp-installed-public-native-v7','nockapp-installed-public-direct-v1','nockapp-installed-public-renewal-v1','nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1']))
        and supplied['profile'] in pins.get('supported_profiles',[pins['profile']]) and config.get('files_sha256')==pins['source_sha256']
        and config.get('binary_sha256')==pins['binary_sha256'])
    # Verify external-module aliases against actual frozen manifest members too.
    for name,h in pins['source_sha256'].items():
        require(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts)
        relative=('opt/nockapp/research/nock-mpc/source-auth/'+Path(name).name
            if name in ('external/x_keystore.py','external/x_holder.py','external/x_policy.py') else APP+'/'+name)
        require(manifest['files']['rootfs/'+relative]['sha256']==h)
    require(session_bus_address is None or type(session_bus_address) is str and re.fullmatch(
        r'unix:(?:path|abstract)=[A-Za-z0-9_./-]+(?:,guid=[0-9a-f]{32})?',session_bus_address))
    require(home not in (Path('/'),Path('/home'),Path('/tmp')))
    if registration is None:registration=home/'.config'/browser/'NativeMessagingHosts'/(HOST+'.json')
    registration=safe(registration)
    require(registration.is_relative_to(home) and registration.name==HOST+'.json' and not registration.exists())
    state=safe(Path(config['data_directory']))
    legacy=config.get('legacy_wallets');require(type(legacy) is list and len(legacy)<=8)
    paths=[state];legacy_paths=[]
    storage=safe(home/'.local/lib/nockapp-zkid')
    for row in legacy:
        require(type(row) is dict and row.get('kind') in ('author-v4','count-v2','domain-v1')
            and set(row)==({'kind','directory','binding'} if row['kind']=='author-v4' else {'kind','directory'})
            and type(row.get('directory')) is str)
        path=safe(Path(row['directory']));require(path.is_dir())
        require(not any(path.is_relative_to(old) or old.is_relative_to(path) for old in paths))
        paths.append(path);legacy_paths.append(str(path))
    ticket_paths={}
    if config['profile']in ('nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'):
        scopes=config['legacy_ticket_scopes'];require(type(scopes) is list and len(scopes)<=4)
        for number,row in enumerate(scopes):
            require(type(row) is dict and type(row.get('directory')) is str)
            path=safe(Path(row['directory']));require(path.is_dir() and path!=state)
            if path.is_relative_to(state):
                target='/state/'+str(path.relative_to(state))
            else:
                require(not any(path.is_relative_to(old) or old.is_relative_to(path)for old in paths))
                target='/legacy/'+str(len(legacy_paths));paths.append(path);legacy_paths.append(str(path))
            ticket_paths[number]=target
        require(len(legacy_paths)<=8)
    for path in paths:
        require(not any(path.is_relative_to(code) or code.is_relative_to(path) for code in (root,storage)))
    # A legacy wallet root must be listed explicitly, never silently treated as
    # the new directory layout with an unrelated fresh identity beside it.
    require(not any((state/n).exists() for n in ('public.json','credential.sealed','pending.sealed','post.sealed')))
    home.mkdir(parents=True,mode=0o700,exist_ok=True)
    info=home.stat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o022)
    private(state)
    for path in legacy_paths:private(Path(path))
    private(storage);releases=private(storage/'releases');cached=releases/expected
    if cached.exists():verify(cached,expected)
    else:
        staged=releases/('.stage-'+secrets.token_hex(12));copy_package(root,staged,manifest,expected)
        os.rename(staged,cached);flush_directory(releases)
    program=private(storage/'registrations'/secrets.token_hex(16))
    native_config=json.loads(canonical(supplied))
    native_base=native_config['installation'] if native_config['profile']=='nockapp-installed-public-renewal-v1' else native_config
    native_base['data_directory']='/state'
    for number,row in enumerate(native_base['legacy_wallets']):row['directory']='/legacy/'+str(number)
    if native_base['profile']in ('nockapp-installed-public-batch-v1','nockapp-installed-public-index-first-v1'):
        for number,row in enumerate(native_base['legacy_ticket_scopes']):row['directory']=ticket_paths[number]
    write(program/'domain-native-config.json',native_config)
    write(program/'passwd',f'zkid:x:{os.getuid()}:{os.getgid()}:NockApp:/state:/bin/false\n'.encode())
    write(program/'group',f'zkid:x:{os.getgid()}:\n'.encode())
    launcher='#!/bin/sh\nexec /usr/bin/python3 -I -B '+shlex.quote(str(cached/'manage.py'))+' host '+shlex.quote(str(program))+' "$@"\n'
    write(program/'run',launcher.encode());(program/'run').chmod(0o700)
    record={'profile':FORMAT,'package':str(cached),'manifest_sha256':expected,'state':str(state),'browser':browser,
        'registration':str(registration),'extension_id':extension_id,'python':manifest['python'],
        'session_bus_address':session_bus_address,'bwrap_sha256':manifest['bwrap_sha256'],
        'public_network':True,'legacy_states':legacy_paths,
        'files':{p.name:digest(p) for p in program.iterdir() if p.is_file()}}
    write(program/'installation.json',record);flush_directory(program)
    args,env=command(program,record,[admission['origin']],check=True)
    tested=subprocess.run(args,capture_output=True,timeout=30,env=env)
    require(tested.returncode==0 and not tested.stderr and tested.stdout==b'{"configuration_checked":true}\n')
    registration.parent.mkdir(parents=True,mode=0o700,exist_ok=True);safe(registration.parent)
    native={'name':HOST,'description':'NockApp public authorship and ticket helper','path':str(program/'run'),
        'type':'stdio','allowed_origins':[admission['origin']]}
    staged=registration.parent/('.zkid-'+secrets.token_hex(12));write(staged,native)
    try:os.link(staged,registration)
    finally:staged.unlink()
    flush_directory(registration.parent)
    return {**record,'program':str(program),'registered':True,'private_state_preserved':True,'legacy_adopted':False}


def main():
    if len(sys.argv)>2 and sys.argv[1]=='host':host(Path(sys.argv[2]),sys.argv[3:]);return 0
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    check=sub.add_parser('verify');check.add_argument('--manifest-sha256',required=True)
    setup=sub.add_parser('install');setup.add_argument('--manifest-sha256',required=True)
    setup.add_argument('--approval',type=Path,required=True);setup.add_argument('--extension-id',required=True)
    setup.add_argument('--home',type=Path,required=True);setup.add_argument('--state',type=Path)
    setup.add_argument('--registration',type=Path)
    issuer=setup.add_mutually_exclusive_group();issuer.add_argument('--port',type=int)
    issuer.add_argument('--issuer-endpoint',type=Path,help='Independently selected public issuer address; attestation trust remains separate')
    setup.add_argument('--session-bus-address',help='Explicit installer-selected desktop session bus; never discovered by browser messages')
    setup.add_argument('--verifier-approval',type=Path,help='Independent public application TLS/authority approval; no service secrets')
    setup.add_argument('--base-approval',type=Path,help='Independently approved Base service identity, address and measurements')
    setup.add_argument('--base-chain',type=Path,help='Pinned chain runtime-code hashes and deployment block')
    setup.add_argument('--base-state',type=Path,help='Separate public outbox/history directory; never the credential wallet')
    setup.add_argument('--bundle-approval',type=Path,help='Independently approved v3 service identity/measurements')
    setup.add_argument('--bundle-chain',type=Path,help='V3 chain/code/storage/cache configuration')
    setup.add_argument('--bundle-state',type=Path,help='Separate v3 public outbox/cache directory')
    setup.add_argument('--count-approval',type=Path,help='Independent raw-count schema/policy/native approval')
    setup.add_argument('--count-state',type=Path,help='Separate encrypted v2 count wallet')
    setup.add_argument('--browser',choices=['chromium','google-chrome','firefox'],default='chromium')
    remove=sub.add_parser('unregister');remove.add_argument('registration',type=Path)
    recovery=sub.add_parser('authorship-recovery',help='Terminal-only encrypted authorship backup/restore for a selected public installation')
    recovery.add_argument('action',choices=['backup','restore']);recovery.add_argument('--program',type=Path,required=True)
    recovery.add_argument('--file',type=Path,required=True)
    configured=sub.add_parser('install-configured');configured.add_argument('--manifest-sha256',required=True)
    configured.add_argument('--extension-id',required=True);configured.add_argument('--home',type=Path,required=True)
    configured.add_argument('--browser',choices=['chromium','google-chrome','firefox'],default='chromium')
    for name in ('state','bundle-state','count-state','registration'):configured.add_argument('--'+name,type=Path)
    configured.add_argument('--session-bus-address')
    public=sub.add_parser('install-public');public.add_argument('--manifest-sha256',required=True)
    public.add_argument('--configuration',type=Path,required=True);public.add_argument('--extension-id',required=True)
    public.add_argument('--home',type=Path,required=True);public.add_argument('--registration',type=Path)
    public.add_argument('--browser',choices=['chromium','google-chrome'],default='chromium')
    public.add_argument('--session-bus-address')
    for operation in ('extension-install','extension-update'):
        extension=sub.add_parser(operation);extension.add_argument('--manifest-sha256',required=True)
        extension.add_argument('--target',type=Path,required=True)
        if operation=='extension-update':extension.add_argument('--expected-current-sha256',required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parent
    if args.operation=='authorship-recovery':result=authorship_recovery(args.program,args.action,args.file)
    elif args.operation=='install-public':result=install_public(root,args.manifest_sha256,read(args.configuration,65536),args.extension_id,
        home=args.home,browser=args.browser,registration=args.registration,session_bus_address=args.session_bus_address)
    elif args.operation=='install-configured':result=install_configured(root,args.manifest_sha256,args.extension_id,
        home=args.home,browser=args.browser,state=args.state,bundle_state=args.bundle_state,count_state=args.count_state,
        registration=args.registration,session_bus_address=args.session_bus_address)
    elif args.operation in ('extension-install','extension-update'):
        verify(root,args.manifest_sha256)
        from extension_release import install as extension_install
        result=extension_install(root,args.target,getattr(args,'expected_current_sha256',None))
    elif args.operation=='verify':verify(root,args.manifest_sha256);result={'integrity_checked':True,'authenticity_requires_independent_checksum':True}
    elif args.operation=='install':result=install(root,args.manifest_sha256,read(args.approval,65536),args.extension_id,
        home=args.home,browser=args.browser,state=args.state,registration=args.registration,port=args.port,
        session_bus_address=args.session_bus_address,
        verifier_approval=read(args.verifier_approval,65536) if args.verifier_approval else None,
        issuer_endpoint=read(args.issuer_endpoint,4096) if args.issuer_endpoint else None,
        base_approval=read(args.base_approval,65536) if args.base_approval else None,
        base_chain=read(args.base_chain,4096) if args.base_chain else None,base_state=args.base_state,
        bundle_approval=read(args.bundle_approval,65536) if args.bundle_approval else None,
        bundle_chain=read(args.bundle_chain,8192) if args.bundle_chain else None,bundle_state=args.bundle_state,
        count_approval=read(args.count_approval,4096) if args.count_approval else None,count_state=args.count_state)
    else:result=unregister(args.registration)
    print(canonical(result).decode());return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        if len(sys.argv)>1 and sys.argv[1]=='host':raise SystemExit(1) from None
        raise SystemExit('Desktop package operation rejected') from None
