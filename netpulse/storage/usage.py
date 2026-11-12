"""Transactional router counter deltas, observed daily totals, and short WAN history."""
from __future__ import annotations

import datetime as dt
import sqlite3
import time
import uuid
from contextlib import contextmanager


@contextmanager
def connection(path):
    db = sqlite3.connect(path, timeout=5)
    try:
        with db:
            yield db
    finally:
        db.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_baselines (
 kind TEXT, identity TEXT, ts REAL, mono REAL, instance TEXT, uptime INTEGER,
 down INTEGER, up INTEGER, binding TEXT, PRIMARY KEY(kind,identity));
CREATE TABLE IF NOT EXISTS usage_daily (
 kind TEXT, identity TEXT, day TEXT, down INTEGER NOT NULL, up INTEGER NOT NULL,
 seconds REAL NOT NULL, first_ts REAL, last_ts REAL, estimated INTEGER NOT NULL,
 PRIMARY KEY(kind,identity,day));
CREATE TABLE IF NOT EXISTS usage_wan_intervals (
 identity TEXT, ts REAL, started REAL, seconds REAL, down INTEGER, up INTEGER,
 PRIMARY KEY(identity,ts));
CREATE INDEX IF NOT EXISTS usage_interval_ts ON usage_wan_intervals(ts);
CREATE INDEX IF NOT EXISTS usage_daily_day ON usage_daily(day);
"""
MAX_GAP = 180
MAX_BPS = 2_000_000_000


def day_bounds(day):
    date = dt.date.fromisoformat(day)
    def midnight(date):
        return time.mktime((date.year,date.month,date.day,0,0,0,0,0,-1))
    return midnight(date), midnight(date+dt.timedelta(days=1))


def split_days(start, end):
    """Allocate boundary-spanning intervals by time; preserve every byte in the caller."""
    cursor = start
    while cursor < end:
        day = dt.date.fromtimestamp(cursor).isoformat()
        _, boundary = day_bounds(day)
        stop = min(end,boundary)
        yield day, cursor, stop
        cursor = stop


class UsageStore:
    def __init__(self,path):
        self.path = path
        self.instance = uuid.uuid4().hex
        with connection(path) as db:
            db.executescript(SCHEMA)

    def accept(self,rows,now,mono,uptime,*,device_poll=False):
        """Persist baseline and deltas together so retries cannot double-count usage."""
        rates = {}
        with connection(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            if device_poll:
                present={r['identity'] for r in rows if r['kind']=='device'}
                for (identity,) in db.execute("SELECT identity FROM usage_baselines WHERE kind='device'").fetchall():
                    if identity not in present:
                        db.execute("DELETE FROM usage_baselines WHERE kind='device' AND identity=?",(identity,))
            for row in rows:
                kind,identity=row['kind'],row['identity']
                old=db.execute('SELECT ts,mono,instance,uptime,down,up,binding FROM usage_baselines WHERE kind=? AND identity=?',
                               (kind,identity)).fetchone()
                reason='Collecting the first counter baseline'
                valid=False;elapsed=0
                if old:
                    wall=now-old[0]
                    elapsed=mono-old[1] if old[2]==self.instance else wall
                    valid=(0 < wall <= MAX_GAP and 0 < elapsed <= MAX_GAP and abs(wall-elapsed)<=5
                           and 0 <= uptime-old[3] <= MAX_GAP+10
                           and abs((uptime-old[3])-elapsed)<=10 and old[6]==row.get('binding',''))
                    reason='Counter reset, changed device identity, clock correction, or collection gap'
                    down,up=row['down']-old[4],row['up']-old[5]
                    valid=valid and down>=0 and up>=0
                    if valid and row.get('defer') and down==0 and up==0:
                        rates[(kind,identity)]={'available':False,'down_mbps':None,'up_mbps':None,
                            'sample_seconds':None,'reason':'Router counters have not refreshed despite a nonzero reported rate'}
                        continue
                    if valid:
                        valid=max(down,up)*8/elapsed<=MAX_BPS
                        reason='Counter delta exceeds the verified gigabit interface range' if not valid else ''
                if valid:
                    rates[(kind,identity)]={'available':True,'down_mbps':down*8/elapsed/1e6,
                        'up_mbps':up*8/elapsed/1e6,'sample_seconds':elapsed,'reason':''}
                    segments=list(split_days(old[0],now));allocated_down=allocated_up=0
                    for index,(day,start,end) in enumerate(segments):
                        last=index==len(segments)-1
                        d=down-allocated_down if last else int(down*(end-start)/wall)
                        u=up-allocated_up if last else int(up*(end-start)/wall)
                        allocated_down+=d;allocated_up+=u
                        db.execute('''INSERT INTO usage_daily VALUES(?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(kind,identity,day) DO UPDATE SET down=down+excluded.down,
                            up=up+excluded.up,seconds=seconds+excluded.seconds,last_ts=excluded.last_ts,
                            estimated=MAX(estimated,excluded.estimated)''',
                            (kind,identity,day,d,u,end-start,start,end,int(len(segments)>1)))
                    if kind=='wan':
                        db.execute('INSERT INTO usage_wan_intervals VALUES(?,?,?,?,?,?)',
                                   (identity,now,old[0],elapsed,down,up))
                else:
                    rates[(kind,identity)]={'available':False,'down_mbps':None,'up_mbps':None,
                                          'sample_seconds':None,'reason':reason}
                db.execute('INSERT OR REPLACE INTO usage_baselines VALUES(?,?,?,?,?,?,?,?,?)',
                    (kind,identity,now,mono,self.instance,uptime,row['down'],row['up'],row.get('binding','')))
            db.execute('DELETE FROM usage_wan_intervals WHERE ts<?',(now-2*86400,))
            cutoff=dt.date.fromtimestamp(now-400*86400).isoformat()
            db.execute('DELETE FROM usage_daily WHERE day<?',(cutoff,))
        return rates

    def invalidate(self,kind,identities=None):
        with connection(self.path) as db:
            if identities is None:
                db.execute('DELETE FROM usage_baselines WHERE kind=?',(kind,))
            else:
                db.executemany('DELETE FROM usage_baselines WHERE kind=? AND identity=?',[(kind,i) for i in identities])

    def read(self,day,hours=1,now=None):
        day_bounds(day)  # Reject malformed dates before running queries.
        with connection(self.path) as db:
            db.row_factory=sqlite3.Row
            daily=[dict(r) for r in db.execute('SELECT * FROM usage_daily WHERE day=?',(day,))]
            bucket=max(15,int(hours*3600/240)//15*15)
            until=time.time() if now is None else now
            since=until-hours*3600
            intervals=db.execute('SELECT * FROM usage_wan_intervals WHERE ts>? AND started<?',
                                 (since,until)).fetchall()
            buckets={}
            for row in intervals:
                duration=row['ts']-row['started']
                cursor=max(since,row['started']);end=min(until,row['ts'])
                while cursor<end:
                    stamp=int(cursor//bucket)*bucket
                    stop=min(end,stamp+bucket);seconds=stop-cursor
                    total=buckets.setdefault((row['identity'],stamp),[0,0,0])
                    total[0]+=row['down']*seconds/duration
                    total[1]+=row['up']*seconds/duration
                    total[2]+=seconds
                    cursor=stop
            history=[{'wan':wan,'ts':stamp,'down_mbps':d*8/seconds/1e6,
                      'up_mbps':u*8/seconds/1e6,'seconds':seconds}
                     for (wan,stamp),(d,u,seconds) in sorted(buckets.items(),key=lambda item:item[0][1])]
        return {'daily':daily,'points':history,'bucket':bucket,'day':day}
