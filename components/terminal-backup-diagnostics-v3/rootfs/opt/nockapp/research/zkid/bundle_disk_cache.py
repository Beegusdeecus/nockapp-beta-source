"""Bounded PUBLIC bytes and rebuildable chain checkpoints; no proof verdicts.

The owner-only directory is separate from wallet, outbox and drafts. Corrupt
cache records never establish acceptance or evidence. Checkpoints are hints and
must be checked against canonical chain state after every restart.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time

from policy import Rejected,canonical,require,strict_json
from public_bundle import MAX_BYTES,decode
from public_storage import MAX_CACHE_BYTES

MAX_DB_BYTES=MAX_CACHE_BYTES+8*1048576
FILES=('cache.sqlite','cache.sqlite-journal','cache.sqlite-wal','cache.sqlite-shm')

class CheckpointConflict(Rejected):
    """Validly encoded equal-height checkpoint conflict; never hide as cache IO."""

class LazyCheckpointStore:
    """Checkpoint-only facade: configuration inspection creates no state.

    Existing hints may be read at construction; the first verified completion
    may create the dedicated cache. No wallet/keyring/proof-verdict storage.
    """
    def __init__(self,directory):
        self.root=Path(directory)
        require(self.root.is_absolute() and '..' not in self.root.parts
            and not any(p.startswith('.env') for p in self.root.parts),'public-cache-directory')
        self._cache=None;self._mutex=threading.Lock();self.fault=None
    def _make_cache(self):return DiskPublicCache(self.root)
    def _open(self,create):
        with self._mutex:
            try:
                require(not any(p.is_symlink() for p in (self.root,*self.root.parents)),'public-cache-directory')
                if self._cache is None:
                    if not create and not self.root.exists():return None
                    if create:
                        self.root.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                        info=self.root.parent.stat()
                        require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid()
                            and not info.st_mode&0o022,'public-cache-directory')
                    self._cache=self._make_cache()
                info=self.root.stat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid()
                    and not info.st_mode&0o077,'public-cache-directory')
                return self._cache
            except (Rejected,OSError):self.fault='cache-unavailable';return None
    def get_checkpoint(self,scope):
        DiskPublicCache._digest(scope);cache=self._open(False)
        if cache is None:return None
        value=cache.get_checkpoint(scope);self.fault=cache.fault;return value
    def advance_checkpoint(self,scope,value):
        DiskPublicCache._digest(scope);DiskPublicCache._checkpoint(value);cache=self._open(True)
        if cache is None:return None
        try:return cache.advance_checkpoint(scope,value)
        finally:self.fault=cache.fault
    def put_checkpoint(self,scope,value):return self.advance_checkpoint(scope,value) is not None
    def clear(self):
        cache=self._open(False)
        if cache is None:return 0
        value=cache.clear();self.fault=cache.fault;return value


class DiskPublicCache:
    object_limit=MAX_BYTES
    @staticmethod
    def _validate_bytes(digest,data):return decode(data,digest)
    def __init__(self,directory,*,max_bytes=MAX_CACHE_BYTES,max_entries=1024):
        require(type(max_bytes) is int and 0<max_bytes<=MAX_CACHE_BYTES and type(max_entries) is int
            and 0<max_entries<=4096,'public-cache-limit')
        self.root=Path(directory)
        require(self.root.is_absolute() and not any(p.is_symlink() for p in (self.root,*self.root.parents))
            and not any(p.startswith('.env') for p in self.root.parts),'public-cache-directory')
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        info=self.root.stat();require(info.st_uid==os.getuid() and not info.st_mode&0o077,'public-cache-directory')
        self.max_bytes,self.max_entries=max_bytes,max_entries;self.fault=None
        try:
            with self._lock(),self._db() as db:self._trim(db)
        except (sqlite3.Error,Rejected,OSError):self.fault='cache-unavailable'

    @staticmethod
    def _digest(value):
        require(type(value) is str and re.fullmatch(r'0x[0-9a-f]{64}',value),'public-cache-digest')

    def _check_file(self,path):
        try:info=path.lstat()
        except FileNotFoundError:return
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
            and not info.st_mode&0o077 and info.st_size<=MAX_DB_BYTES,'public-cache-file')

    @contextmanager
    def _lock(self):
        fd=os.open(self.root/'cache.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and info.st_nlink==1 and not info.st_mode&0o077,'public-cache-lock')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Rejected('public-cache-busy') from None
            yield
        finally:os.close(fd)

    @contextmanager
    def _db(self):
        for name in FILES:self._check_file(self.root/name)
        path=self.root/'cache.sqlite'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:empty=os.fstat(fd).st_size==0
        finally:os.close(fd)
        db=sqlite3.connect(path,timeout=1)
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,self.object_limit+2048)
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA journal_mode=DELETE')
            require(db.execute('PRAGMA page_size').fetchone()[0]==4096,'public-cache-format')
            db.execute('PRAGMA synchronous=FULL')
            if empty:db.execute('PRAGMA auto_vacuum=FULL')
            require(db.execute('PRAGMA auto_vacuum').fetchone()[0]==1,'public-cache-format')
            db.execute('PRAGMA max_page_count='+str(MAX_DB_BYTES//4096))
            rows=db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
            if empty:
                db.execute('CREATE TABLE bundles (digest TEXT PRIMARY KEY, data BLOB NOT NULL, touched INTEGER NOT NULL)')
                db.execute('CREATE TABLE checkpoints (scope TEXT PRIMARY KEY, data BLOB NOT NULL, touched INTEGER NOT NULL)')
            else:require(set(rows)=={('table','bundles'),('table','checkpoints')},'public-cache-format')
            yield db
            db.commit()
        finally:db.close()

    def _trim(self,db):
        count,size=db.execute('SELECT count(*),coalesce(sum(length(data)),0) FROM bundles').fetchone()
        while count>self.max_entries or size>self.max_bytes:
            digest,length=db.execute('SELECT digest,length(data) FROM bundles ORDER BY touched,digest LIMIT 1').fetchone()
            db.execute('DELETE FROM bundles WHERE digest=?',(digest,));count-=1;size-=length
        db.execute('DELETE FROM checkpoints WHERE scope NOT IN (SELECT scope FROM checkpoints ORDER BY touched DESC LIMIT 16)')

    def get(self,digest):
        self._digest(digest)
        try:
            with self._lock(),self._db() as db:
                row=db.execute('SELECT data FROM bundles WHERE digest=? AND length(data)<=?',(digest,self.object_limit)).fetchone()
                if row is None:return None
                data=row[0]
                try:self._validate_bytes(digest,data)
                except Exception:
                    db.execute('DELETE FROM bundles WHERE digest=?',(digest,));return None
                db.execute('UPDATE bundles SET touched=? WHERE digest=?',(time.time_ns(),digest));return data
        except (sqlite3.Error,Rejected,OSError):self.fault='cache-unavailable';return None

    def put(self,digest,data):
        self._digest(digest);self._validate_bytes(digest,data)
        if len(data)>self.max_bytes:return False
        try:
            with self._lock(),self._db() as db:
                # Evict before insertion, so a full file cannot exceed its page
                # limit just to make room for the next verified bundle.
                db.execute('DELETE FROM bundles WHERE digest=?',(digest,))
                count,size=db.execute('SELECT count(*),coalesce(sum(length(data)),0) FROM bundles').fetchone()
                while count>=self.max_entries or size+len(data)>self.max_bytes:
                    old,length=db.execute('SELECT digest,length(data) FROM bundles ORDER BY touched,digest LIMIT 1').fetchone()
                    db.execute('DELETE FROM bundles WHERE digest=?',(old,));count-=1;size-=length
                db.execute('INSERT INTO bundles VALUES (?,?,?)',(digest,data,time.time_ns()))
            self.fault=None;return True
        except (sqlite3.Error,Rejected,OSError):self.fault='cache-unavailable';return False

    @staticmethod
    def _checkpoint(value):
        require(type(value) is dict and set(value)=={'number','hash'} and type(value['number']) is str
            and re.fullmatch(r'0x(?:0|[1-9a-f][0-9a-f]{0,15})',value['number'])
            and type(value['hash']) is str and re.fullmatch(r'0x[0-9a-f]{64}',value['hash']),'public-cache-checkpoint')
        return value

    def get_checkpoint(self,scope):
        self._digest(scope)
        try:
            with self._lock(),self._db() as db:
                row=db.execute('SELECT data FROM checkpoints WHERE scope=? AND length(data)<=1024',(scope,)).fetchone()
                if row is None:return None
                value=self._checkpoint(strict_json(row[0],max_bytes=1024))
                require(canonical(value)==row[0],'public-cache-checkpoint');return value
        except (sqlite3.Error,Rejected,OSError):self.fault='cache-unavailable';return None

    def put_checkpoint(self,scope,value):
        return self.advance_checkpoint(scope,value) is not None

    def advance_checkpoint(self,scope,value):
        """Atomically keep the highest hint and return it, or None on cache IO.

        A returned hint is NOT a proof: readers must check its canonical hash.
        Lock contention is unavailable, not a retry or a successful checkpoint.
        """
        self._digest(scope);value=dict(self._checkpoint(value))
        data=canonical(self._checkpoint(value))
        try:
            with self._lock(),self._db() as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT data FROM checkpoints WHERE scope=?',(scope,)).fetchone()
                if row is not None:
                    old=self._checkpoint(strict_json(row[0],max_bytes=1024))
                    require(canonical(old)==row[0],'public-cache-checkpoint')
                    prior_height,height=int(old['number'],16),int(value['number'],16)
                    if prior_height==height and old['hash']!=value['hash']:
                        raise CheckpointConflict('public-cache-checkpoint-conflict') from None
                    if prior_height>=height:
                        self.fault=None;return dict(old)
                db.execute('INSERT OR REPLACE INTO checkpoints VALUES (?,?,?)',(scope,data,time.time_ns()))
                self._trim(db)
            self.fault=None;return value
        except CheckpointConflict:
            self.fault='checkpoint-conflict';raise
        except (sqlite3.Error,Rejected,OSError):self.fault='cache-unavailable';return None

    def clear(self):
        # Fixed owned public-cache files only. Never walk/delete parent paths,
        # drafts, wallet, outbox, unknown files or shared remote replicas.
        with self._lock():
            for name in FILES:self._check_file(self.root/name)
            count=0
            try:
                with self._db() as db:count=db.execute('SELECT count(*) FROM bundles').fetchone()[0]
            except (sqlite3.Error,Rejected):pass
            for name in FILES:
                try:(self.root/name).unlink()
                except FileNotFoundError:pass
            with self._db():pass
        self.fault=None;return count

    def stats(self):
        try:
            with self._lock(),self._db() as db:
                count,size=db.execute('SELECT count(*),coalesce(sum(length(data)),0) FROM bundles').fetchone()
                return {'entries':count,'payload_bytes':size,'database_bytes':(self.root/'cache.sqlite').stat().st_size,
                    'max_payload_bytes':self.max_bytes,'max_entries':self.max_entries,'fault':self.fault}
        except (sqlite3.Error,Rejected,OSError):
            self.fault='cache-unavailable';return {'entries':None,'payload_bytes':None,'fault':self.fault}
