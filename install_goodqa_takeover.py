#!/usr/bin/env python3
"""Install one sealed GoodQA takeover release on the Mac and physical t2-dev."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

NAMES = ('takeover_patch.py', 'takeover-native-manifest.json', 'broker_patch_transaction.py', 'broker-takeover-bundle.json')

REMOTE = r'''
import base64,fcntl,hashlib,json,os,pathlib,re,stat,subprocess,sys,tempfile
p=json.loads(sys.stdin.read())
if not re.fullmatch('[a-f0-9]{64}',p['release']):
    raise SystemExit('Invalid release identity')
root=pathlib.Path.home()/'.agent-harness'/'work'/('goodqa-takeover-release-'+p['release'])
for parent in (pathlib.Path.home()/'.agent-harness',pathlib.Path.home()/'.agent-harness/work',root):
    parent.mkdir(mode=0o700,exist_ok=True)
    info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:
        raise SystemExit('Unsafe remote release directory')
lock=os.open(root/'upload.lock',os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR,0o600)
info=os.fstat(lock)
if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o022:
    raise SystemExit('Unsafe upload lock')
fcntl.flock(lock,fcntl.LOCK_EX)
for name in ('broker_patch_transaction.py','broker-takeover-bundle.json'):
    item=p['files'][name]
    data=base64.b64decode(item['content'],validate=True)
    if hashlib.sha256(data).hexdigest()!=item['sha256']:
        raise SystemExit('Remote payload digest mismatch')
    path=root/name
    if not os.path.lexists(path):
        fd,scratch=tempfile.mkstemp(prefix=name+'.incoming-',dir=root)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(scratch,path)
            directory=os.open(root,os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(scratch):
                os.unlink(scratch)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o022 or path.read_bytes()!=data:
        raise SystemExit('Remote release path differs')
command=['python3','-B',str(root/'broker_patch_transaction.py'),'--bundle',str(root/'broker-takeover-bundle.json')]
if p['apply']:
    command.append('--apply')
raise SystemExit(subprocess.run(command).returncode)
'''

def release_files(path, expected):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Release manifest digest mismatch')
    manifest = json.loads(raw)
    if set(manifest) != set(NAMES):
        raise ValueError('Unexpected release file set')
    result = {}
    for name in NAMES:
        item = manifest[name]
        if set(item) != {'path', 'sha256'}:
            raise ValueError('Invalid release file declaration')
        source = Path(item['path'])
        if source.is_symlink() or not source.is_file():
            raise ValueError('Release file is missing or aliased')
        data = source.read_bytes()
        if len(data) > 8*1024*1024 or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Release file changed: ' + name)
        result[name] = {'path': str(source.absolute()), 'sha256': item['sha256'], 'content': base64.b64encode(data).decode()}
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--release-sha256',required=True)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--ssh-config',default=str(Path.home()/'.ssh/config_fleetops'))
    args=parser.parse_args()
    files=release_files(args.release,args.release_sha256)
    native=[sys.executable,'-B',files['takeover_patch.py']['path'],'--manifest',files['takeover-native-manifest.json']['path'],'--manifest-sha256',files['takeover-native-manifest.json']['sha256'],'--ssh-config',args.ssh_config]
    import shlex
    remote=['ssh','-F',args.ssh_config,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','t2-dev','python3 -B -c '+shlex.quote(REMOTE)]
    def broker(apply):
        payload=json.dumps({'release':args.release_sha256,'files':files,'apply':apply}).encode()
        subprocess.run(remote,input=payload,check=True,timeout=240)
    subprocess.run(native,check=True,timeout=120)
    broker(False)
    if args.apply:
        subprocess.run(native+['--apply'],check=True,timeout=120)
        try:
            broker(True)
        except BaseException:
            print('Native module phase succeeded. Broker phase requires reconciliation. Repeat this exact release command after resolving the recorded broker refusal.',file=sys.stderr)
            raise
        print('Both installation phases verified. GoodQA release execution remains tracked in the task checkpoint.')
    else:
        print('Both installation phases passed preflight. Add --apply to install this exact release.')

if __name__=='__main__':
    main()
