"""Durable, conservative reservation of the user's US$3 live API test allowance.

This tracks OUR requests, not other applications sharing the subscription. A
reserved request is never refunded after uncertainty, and no retry is automatic.
Reservations intentionally exceed the documented one-result endpoint prices.
"""
import os
from pathlib import Path
import sqlite3
import stat

from policy import require

CAP_MICRO_USD=3_000_000
PER_REQUEST_MICRO_USD=10_000  # US$0.01, versus documented <= US$0.00018/one result.
OPERATIONS={'one-user-profile','one-public-post','one-timeline-page'}


class ApiBudget:
    def __init__(self,directory):
        root=Path(directory)
        require(root.is_absolute() and not root.is_symlink(),'budget-directory')
        root.mkdir(parents=True,mode=0o700,exist_ok=True)
        info=root.stat()
        require(info.st_uid==os.getuid() and not info.st_mode&0o077,'budget-directory')
        path=root/'api-budget.sqlite'
        fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077
                    and info.st_nlink==1,'budget-file')
        finally:os.close(fd)
        self.db=sqlite3.connect(path,isolation_level=None,timeout=5)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS reservations (request_id TEXT PRIMARY KEY, operation TEXT NOT NULL, micro_usd INTEGER NOT NULL)')

    def reserve(self,request_id,operation):
        require(type(request_id) is str and len(request_id)==32 and all(c in '0123456789abcdef' for c in request_id)
                and operation in OPERATIONS,'budget-operation')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            require(self.db.execute('SELECT 1 FROM reservations WHERE request_id=?',(request_id,)).fetchone() is None,
                    'budget-request-already-used')
            used=self.db.execute('SELECT COALESCE(SUM(micro_usd),0) FROM reservations').fetchone()[0]
            require(used+PER_REQUEST_MICRO_USD<=CAP_MICRO_USD,'api-spending-limit')
            self.db.execute('INSERT INTO reservations VALUES (?,?,?)',(request_id,operation,PER_REQUEST_MICRO_USD))
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK');raise

    def public_summary(self):
        count,total=self.db.execute('SELECT COUNT(*),COALESCE(SUM(micro_usd),0) FROM reservations').fetchone()
        return {'cap_usd':'3.00','reserved_request_count':count,'conservative_reserved_usd':f'{total/1_000_000:.2f}',
                'billing_observed':False,'other_applications_excluded':True}
