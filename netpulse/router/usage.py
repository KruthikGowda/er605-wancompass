"""Background, read-only ER605 WAN and uniquely identified client counter collection."""
from __future__ import annotations

from contextlib import closing
import datetime as dt
import math
import threading
import time

from netpulse.router.er605 import RouterAuthError
from netpulse.router.traffic import DeviceTraffic
from netpulse.storage.usage import UsageStore,day_bounds
from netpulse.storage import sqlite

INTERVAL = 30
DEVICE_INTERVAL = 60
LIMITATION = ("Router-reported counters may omit accelerated or policy-routed traffic. "
              "Observed totals are not complete ISP usage or billing records. Device counters may include routed LAN traffic and are not split by WAN.")


class UsageCollector:
    def __init__(self,watch,path,wans,clock=time.time,monotonic=time.monotonic):
        self.watch,self.path,self.wans=watch,path,list(wans)
        self.clock,self.monotonic=clock,monotonic
        self.store=UsageStore(path)
        self.guard=DeviceTraffic(watch,clock=clock,monotonic=monotonic)
        self._lock=threading.RLock()
        self._next_devices=0
        self._next_poll=0
        self._retry_after=0
        self._status={'available':False,'reason':'Waiting for the first router counter sample','sampled_at':None}
        self._wan_rates={}
        self._device_rates={}
        self._device_status='Waiting for a fresh device counter sample'

    @staticmethod
    def wan_counters(rows,wans):
        if not isinstance(rows,list) or len(rows)>32:
            raise ValueError('Invalid interface counter table')
        result={};seen=set()
        for row in rows:
            if not isinstance(row,dict):raise ValueError('Invalid interface counter row')
            name=str(row.get('interface','')).upper()
            if name=='WAN/LAN2':name='WAN2'
            if name not in wans:continue
            if name in seen:raise ValueError('Ambiguous WAN interface counters')
            seen.add(name)
            down=DeviceTraffic._counter_value(row.get('rx_bytes'))
            up=DeviceTraffic._counter_value(row.get('tx_bytes'))
            if down is None or up is None:continue
            result[name]={'kind':'wan','identity':name,'down':down,'up':up,'binding':name,
                          'defer':bool(row.get('rx_bps') or row.get('tx_bps'))}
        return result

    def poll(self):
        now=self.clock()
        mono=self.monotonic()
        if mono<self._next_poll:return
        self._next_poll=mono+INTERVAL
        reason=self.guard._watch_guard()
        if now<self._retry_after:reason='Traffic collection is in router-authentication backoff'
        if reason:
            self._unavailable(reason)
            return
        try:
            with self.watch.api_lock:
                reason=self.guard._watch_guard()
                if reason:
                    self._unavailable(reason);return
                with self.watch.client.session() as client:
                    uptime_before=int(client.public_info()['uptime'])
                    if DeviceTraffic._status(client.get('ifstat','switch')) is not True:
                        self._unavailable('ER605 interface statistics are disabled or unavailable');return
                    wan=self.wan_counters(client.get('ifstat','list'),self.wans)
                    devices_due=mono>=self._next_devices
                    device_rows=[];device_reason=''
                    if devices_due:
                        try:
                            device_rows,device_reason=self._read_devices(client)
                        except RouterAuthError:
                            raise
                        except Exception:
                            device_reason='Device counter read failed; WAN observations remain available'
                    uptime_after=int(client.public_info()['uptime'])
                    if uptime_after<uptime_before:raise ValueError('Router restarted during counter collection')
            sampled=self.clock()
            missing=set(self.wans)-set(wan)
            if missing:self.store.invalidate('wan',missing)
            rates=self.store.accept(list(wan.values())+device_rows,sampled,self.monotonic(),uptime_after,
                                    device_poll=devices_due)
            with self._lock:
                self._wan_rates={name:rates.get(('wan',name),{'available':False,'reason':'WAN counters are missing',
                    'down_mbps':None,'up_mbps':None}) for name in self.wans}
                self._status={'available':any(r['available'] for r in self._wan_rates.values()),
                    'reason':'','sampled_at':sampled}
                if devices_due:
                    self._next_devices=self.monotonic()+DEVICE_INTERVAL
                    self._device_rates={mac:{**rates[('device',mac)],'sampled_at':sampled}
                                        for kind,mac in rates if kind=='device'}
                    self._device_status=device_reason
        except Exception as exc:
            if isinstance(exc,RouterAuthError):
                self._retry_after=self.clock()+1800
            self._unavailable('Router counter read failed; waiting for a verified sample')

    @staticmethod
    def _read_devices(client):
        device_rows=[];device_reason=''
        before,_,_=DeviceTraffic._client_map(client.get('dhcps','client',{}))
        if DeviceTraffic._status(client.get('ipstats','setting')) is True:
            raw=client.get('ipstats','list')
            counters,invalid=DeviceTraffic._counter_map(raw)
            clients=client.get('dhcps','client',{})
            after,_,_=DeviceTraffic._client_map(clients)
            raw_map={r['addr']:r for r in raw if isinstance(r,dict) and r.get('addr') in counters}
            for mac,ip in after.items():
                if before.get(mac)!=ip or ip not in counters or ip in invalid:continue
                rx,tx=counters[ip]
                device_rows.append({'kind':'device','identity':mac,'binding':ip,
                    'down':rx,'up':tx,'defer':bool(raw_map[ip].get('rx_bps') or raw_map[ip].get('tx_bps'))})
            if not device_rows:device_reason='No counters matched stable, unique DHCP identities'
        else:
            device_reason='ER605 per-IP statistics are disabled or unavailable'
        return device_rows,device_reason

    def _unavailable(self,reason):
        with self._lock:
            self._status={**self._status,'available':False,'reason':reason}

    def snapshot(self,day=None,hours=1,ranking='today'):
        now=self.clock()
        day=day or dt.date.fromtimestamp(now).isoformat()
        start,end=day_bounds(day)
        if start>now:raise ValueError('Choose today or an earlier date')
        if not math.isfinite(hours) or not 0.25<=hours<=24:raise ValueError('Choose a range from 15 minutes to 24 hours')
        if ranking not in ('today','now'):raise ValueError('Choose a supported ranking')
        result=self.store.read(day,hours,now)
        with self._lock:
            status=dict(self._status);rates={k:dict(v) for k,v in self._wan_rates.items()}
            devices={k:dict(v) for k,v in self._device_rates.items()};device_reason=self._device_status
        age=None if status['sampled_at'] is None else now-status['sampled_at']
        fresh=bool(age is not None and 0<=age<=INTERVAL*2.5 and status['available'])
        daily={(row['kind'],row['identity']):row for row in result.pop('daily')}
        expected=max(0,min(now,end)-start)
        def totals(kind,identity):
            row=daily.get((kind,identity),{})
            return {'down_bytes':row.get('down',0),'up_bytes':row.get('up',0),
                    'observed_seconds':row.get('seconds',0),'first_observed':row.get('first_ts'),
                    'last_observed':row.get('last_ts'),'estimated_boundary':bool(row.get('estimated',0)),
                    'coverage_pct':min(100,100*row.get('seconds',0)/expected) if expected else 0}
        result.update(status,available=fresh,age_seconds=age,interval_seconds=INTERVAL,device_interval_seconds=DEVICE_INTERVAL,
            today=dt.date.fromtimestamp(now).isoformat(),
            limitation=LIMITATION,accounting_complete=False,timezone=time.tzname[0],expected_seconds=expected,
            wans=[{'wan':name,**rates.get(name,{}),'stale':not fresh,'daily':totals('wan',name)} for name in self.wans])
        if not fresh:
            for row in result['wans']:row.update(available=False,down_mbps=None,up_mbps=None)
        labels=sqlite.device_labels(self.path)
        with closing(sqlite._ro(self.path)) as db:
            names={mac:name for mac,name in db.execute('SELECT mac,name FROM known_devices')}
        identities={identity for kind,identity in daily if kind=='device'}|set(devices)
        ranked=[]
        for mac in identities:
            current=devices.get(mac,{})
            device_age=now-current.get('sampled_at',0)
            available=bool(current.get('available') and 0<=device_age<=DEVICE_INTERVAL*2 and not status['reason'])
            ranked.append({'mac':mac,'label':labels.get(mac) or names.get(mac) or mac,
                'available':available,'rx_mbps':current.get('down_mbps') if available else None,
                'tx_mbps':current.get('up_mbps') if available else None,
                'reason':current.get('reason','No current counter baseline'),'daily':totals('device',mac)})
        def weight(row):
            return ((row['rx_mbps'] or 0)+(row['tx_mbps'] or 0)) if ranking=='now' else row['daily']['down_bytes']+row['daily']['up_bytes']
        ranked.sort(key=lambda row:(-weight(row),row['label'].casefold()))
        result['devices']=ranked[:10]
        result['device_reason']=device_reason
        result['ranking']=ranking
        return result
