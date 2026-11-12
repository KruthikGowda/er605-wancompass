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
NATIVE_MAX_AGE = 75
LIMITATION = ("WAN rates are the router's approximately 30-second averages; daily totals use byte-counter deltas. "
              "Device totals include only intervals with DPI and logging confirmed on. Earlier undercounted observations are excluded. "
              "Counters include overhead and may include routed LAN traffic; these are not ISP billing records or per-WAN device attribution.")


class NativeWanRates:
    """Decode KB/s, retain cached readings without inventing a new sample or zero."""
    def __init__(self,store):
        self.store=store
        self.state={}

    @staticmethod
    def kbps(value):
        parsed=DeviceTraffic._counter_value(value)
        return parsed if parsed is not None and parsed<=250_000 else None

    def accept(self,rows,now,uptime):
        result={};samples=[]
        for name,row in rows.items():
            down,up=row['native_down_kBps'],row['native_up_kBps']
            if down is None or up is None:
                self.state.pop(name,None)
                result[name]={'available':False,'reason':'Built-in WAN rate fields are missing or invalid'}
                continue
            fingerprint=(row['down'],row['up'],down,up,row['rx_packets'],row['tx_packets'])
            previous=self.state.get(name)
            reset=bool(previous and (uptime<previous['uptime'] or row['down']<previous['down'] or row['up']<previous['up']))
            changed=previous is None or fingerprint!=previous['fingerprint']
            idle=down==0 and up==0
            if changed or idle or reset:
                state={'fingerprint':fingerprint,'uptime':uptime,'down':row['down'],'up':row['up'],
                       'rate_at':now,'down_mbps':down*.008,'up_mbps':up*.008,
                       'native_down_kBps':down,'native_up_kBps':up,'refresh_confirmed':bool(previous and changed and not reset),
                       'idle':idle,'reset':reset}
                self.state[name]=state
                if not reset:samples.append({'wan':name,**state})
            else:
                state=previous
            age=now-state['rate_at']
            available=not state['reset'] and 0<=age<=NATIVE_MAX_AGE
            reason=('Router restarted or counters reset; awaiting a new rate window' if state['reset'] else
                    'Built-in rate has not changed; its freshness is unconfirmed' if not available else
                    'Router reports idle; a separate refresh cannot be observed' if idle else
                    'Retaining the previous router rate while its cached counters refresh' if not changed else
                    'Built-in router rate; approximately 30-second average')
            public={k:v for k,v in state.items() if k not in ('fingerprint','uptime','down','up','reset')}
            result[name]={**public,'available':available,'reason':reason,'native_age_seconds':age}
        for name in set(self.state)-set(rows):self.state.pop(name,None)
        self.store.record_native(samples,now)
        return result


class UsageCollector:
    def __init__(self,watch,path,wans,clock=time.time,monotonic=time.monotonic):
        self.watch,self.path,self.wans=watch,path,list(wans)
        self.clock,self.monotonic=clock,monotonic
        self.store=UsageStore(path)
        self.native=NativeWanRates(self.store)
        self.guard=DeviceTraffic(watch,clock=clock,monotonic=monotonic)
        self._lock=threading.RLock()
        self._next_devices=0
        self._next_poll=0
        self._retry_after=0
        self._status={'available':False,'reason':'Waiting for the first router counter sample','sampled_at':None}
        self._wan_rates={}
        self._counter_rates={}
        self._device_rates={}
        self._device_status='Waiting for a fresh device counter sample'
        self._dpi={'known':False,'enabled':False,'logging':False,'sampled_at':None}

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
                          'native_down_kBps':NativeWanRates.kbps(row.get('rx_bps')),
                          'native_up_kBps':NativeWanRates.kbps(row.get('tx_bps')),
                          'rx_packets':DeviceTraffic._counter_value(row.get('rx_pkts')),
                          'tx_packets':DeviceTraffic._counter_value(row.get('tx_pkts')),
                          'defer':bool(NativeWanRates.kbps(row.get('rx_bps')) or NativeWanRates.kbps(row.get('tx_bps')))}
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
                    wan_time,wan_mono=self.clock(),self.monotonic()
                    devices_due=mono>=self._next_devices
                    device_rows=[];device_reason='';dpi=None
                    if devices_due:
                        try:
                            before_dpi=self.dpi_state(client.get('dpi','dpi_setting'))
                            device_rows,device_reason=self._read_devices(client)
                            dpi=self.dpi_state(client.get('dpi','dpi_setting'))
                            if before_dpi!=dpi or not dpi['known']:
                                device_rows=[]
                                device_reason='DPI state changed or could not be verified during the device sample'
                            elif dpi['enabled'] and dpi['logging']:
                                for row in device_rows:row['kind']='device_dpi'
                        except RouterAuthError:
                            raise
                        except Exception:
                            device_reason='Device counter read failed; WAN observations remain available'
                    uptime_after=int(client.public_info()['uptime'])
                    if uptime_after<uptime_before:raise ValueError('Router restarted during counter collection')
            sampled=self.clock()
            missing=set(self.wans)-set(wan)
            if missing:self.store.invalidate('wan',missing)
            rates=self.store.accept(list(wan.values()),wan_time,wan_mono,uptime_before)
            rates.update(self.store.accept(device_rows,sampled,self.monotonic(),uptime_after,device_poll=devices_due))
            native=self.native.accept(wan,wan_time,uptime_before)
            with self._lock:
                self._counter_rates={name:rates.get(('wan',name),{}) for name in self.wans}
                self._wan_rates={name:native.get(name,{'available':False,'reason':'WAN counters are missing',
                    'down_mbps':None,'up_mbps':None}) for name in self.wans}
                self._status={'available':any(r['available'] for r in self._wan_rates.values()),
                    'reason':'','sampled_at':wan_time}
                if devices_due:
                    self._next_devices=self.monotonic()+DEVICE_INTERVAL
                    self._device_rates={mac:{**rates[(kind,mac)],'sampled_at':sampled,'dpi_captured':kind=='device_dpi'}
                                        for kind,mac in rates if kind in ('device','device_dpi')}
                    self._device_status=device_reason
                    self._dpi={**(dpi or {'known':False,'enabled':False,'logging':False}),'sampled_at':sampled}
        except Exception as exc:
            if isinstance(exc,RouterAuthError):
                self._retry_after=self.clock()+1800
            self._unavailable('Router counter read failed; waiting for a verified sample')

    @staticmethod
    def dpi_state(value):
        if not isinstance(value,dict):return {'known':False,'enabled':False,'logging':False}
        enabled=DeviceTraffic._status({'status':value.get('switch')})
        logging=DeviceTraffic._status({'status':value.get('log_switch')})
        return {'known':enabled is not None and logging is not None,'enabled':enabled is True,'logging':logging is True}

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
                    'down':rx,'up':tx,'defer':bool(NativeWanRates.kbps(raw_map[ip].get('rx_bps')) or NativeWanRates.kbps(raw_map[ip].get('tx_bps')))})
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
            counter_rates={k:dict(v) for k,v in self._counter_rates.items()}
            devices={k:dict(v) for k,v in self._device_rates.items()};device_reason=self._device_status
            dpi=dict(self._dpi)
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
        dpi_age=now-dpi['sampled_at'] if dpi['sampled_at'] is not None else None
        dpi['fresh']=bool(dpi_age is not None and 0<=dpi_age<=DEVICE_INTERVAL*2 and not status['reason'])
        dpi['capture_active']=bool(dpi['fresh'] and dpi['known'] and dpi['enabled'] and dpi['logging'])
        result.update(status,available=fresh,age_seconds=age,interval_seconds=INTERVAL,device_interval_seconds=DEVICE_INTERVAL,
            today=dt.date.fromtimestamp(now).isoformat(),
            limitation=LIMITATION,accounting_complete=False,device_accounting_complete=False,
            dpi=dpi,device_limitation=('DPI and logging confirmed on. Totals exclude earlier undercounted observations. '
                'Overhead and routed LAN traffic may be included; devices are not split by WAN.' if dpi['capture_active'] else
                'DPI capture is off, unverified, or stale. Current device rates are unavailable. Earlier undercounted observations are excluded from these totals.'),
            native_window_seconds=30,native_max_age_seconds=NATIVE_MAX_AGE,native_unit='decimal kB/s',
            timezone=time.tzname[0],expected_seconds=expected,
            wans=[{'wan':name,**rates.get(name,{}),'counter_average':counter_rates.get(name,{}),
                   'stale':not fresh,'daily':totals('wan',name)} for name in self.wans])
        for row in result['wans']:
            rate_age=now-row['rate_at'] if 'rate_at' in row else None
            row['native_age_seconds']=rate_age
            if rate_age is not None and not 0<=rate_age<=NATIVE_MAX_AGE:
                row.update(available=False,stale=True,reason='Built-in rate freshness is unconfirmed; waiting for a changed counter snapshot')
            if not row.get('available'):
                row.update(down_mbps=None,up_mbps=None)
        result['available']=bool(fresh and any(w.get('available') for w in result['wans']))
        if not fresh:
            for row in result['wans']:
                row.update(available=False,down_mbps=None,up_mbps=None)
                row['counter_average'].update(available=False,down_mbps=None,up_mbps=None)
        labels=sqlite.device_labels(self.path)
        with closing(sqlite._ro(self.path)) as db:
            names={mac:name for mac,name in db.execute('SELECT mac,name FROM known_devices')}
        identities={identity for kind,identity in daily if kind in ('device','device_dpi')}|set(devices)
        ranked=[]
        for mac in identities:
            current=devices.get(mac,{})
            device_age=now-current.get('sampled_at',0)
            available=bool(current.get('available') and current.get('dpi_captured') and dpi['capture_active'] and 0<=device_age<=DEVICE_INTERVAL*2)
            ranked.append({'mac':mac,'label':labels.get(mac) or names.get(mac) or mac,
                'available':available,'rx_mbps':current.get('down_mbps') if available else None,
                'tx_mbps':current.get('up_mbps') if available else None,
                'down_mbps':current.get('down_mbps') if available else None,
                'up_mbps':current.get('up_mbps') if available else None,
                'reason':current.get('reason','No current DPI counter baseline'),'daily':totals('device_dpi',mac),
                'legacy_daily':totals('device',mac),'dpi_captured':bool(current.get('dpi_captured'))})
        def weight(row):
            return ((row['rx_mbps'] or 0)+(row['tx_mbps'] or 0)) if ranking=='now' else row['daily']['down_bytes']+row['daily']['up_bytes']
        ranked.sort(key=lambda row:(-weight(row),row['label'].casefold()))
        result['devices']=ranked[:10]
        result['device_reason']=device_reason
        result['ranking']=ranking
        return result
