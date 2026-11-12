/* Observed ER605 counter deltas. Polling this endpoint never logs into the router. */
let usageData=null,usageBusy=false,usageAgain=false;
const usageSelections={};
const usageGB=value=>`${(Number(value)/1e9).toFixed(3)} GB`;

async function refreshUsage(){
  if(usageBusy){usageAgain=true;return;}
  usageBusy=true;
  try{
    const day=$("usage-day").value,query=new URLSearchParams({hours:$("usage-window").value,ranking:$("usage-ranking").value});
    if(day)query.set("day",day);
    const response=await getJSON(`/api/usage?${query}`);
    if(usageAgain)return;
    usageData=response;
    if(usageData.today)$("usage-day").max=usageData.today;
    if(!day && usageData.day)$("usage-day").value=usageData.day;
    renderUsage();
  }catch(error){if(usageData){usageData.available=false;usageData.reason="Router usage feed unavailable";usageData.devices=(usageData.devices||[]).map(row=>({...row,available:false}));renderUsage();}$("usage-status").textContent="Router usage feed unavailable · retained history may be incomplete";}
  finally{usageBusy=false;if(usageAgain){usageAgain=false;refreshUsage();}}
}

function renderUsage(){
  const d=usageData;if(!d)return;
  $("usage-limitation").textContent=d.limitation || d.reason || "Router-reported observations; completeness is unverified";
  if(!d.enabled){$("usage-wans").innerHTML="";$("usage-devices").innerHTML='<tr><td colspan="3">Usage collection is disabled.</td></tr>';$("usage-status").textContent=d.reason || "Router usage collection is disabled";return;}
  const now=Date.now()/1000,age=d.sampled_at==null?null:now-d.sampled_at;
  const fresh=d.available && age!=null && age>=0 && age<=d.interval_seconds*2.5;
  $("usage-status").textContent=`${fresh ? "Counter sample "+Math.floor(age)+"s ago" : d.reason || "Waiting for valid counter deltas"} · WAN polls ${d.interval_seconds}s · device polls ${d.device_interval_seconds}s · daily calendar: ${d.timezone}`;
  const focused=document.activeElement?.id;
  const sharedValues=(d.points||[]).flatMap(p=>[p.down_mbps,p.up_mbps]).filter(Number.isFinite);
  const ymax=Math.max(1,...sharedValues)*1.15;
  const hours=Number($("usage-window").value),t0=now-hours*3600;
  $("usage-wans").innerHTML=(d.wans||[]).map((w,index)=>{
    const total=w.daily||{},observed=total.observed_seconds>0,available=fresh && w.available;
    return `<article class="card live-panel" style="--c:${colorOf(w.wan)}"><header><h3>${esc(labelOf(w.wan))}</h3><span class="soft">Router-reported</span></header>
      <div class="usage-metrics"><div><small>↓ Download</small><strong>${available?fmt(w.down_mbps,2):"—"}</strong> <span>Mbps</span></div><div><small>↑ Upload</small><strong>${available?fmt(w.up_mbps,2):"—"}</strong> <span>Mbps</span></div></div>
      <svg class="live-plot" id="usage-svg-${index}" role="img" aria-label="${esc(labelOf(w.wan))} router-reported upload and download in Mbps"></svg>
      <label class="sample-explorer">Explore intervals<input type="range" id="usage-slider-${index}" min="0" max="0" value="0" aria-label="Explore ${esc(labelOf(w.wan))} bandwidth intervals"></label>
      <div class="sample-readout" id="usage-readout-${index}" aria-live="polite"></div>
      <p class="live-note">Download: solid line · Upload: dashed line · ${d.bucket}s graph buckets</p>
      <div class="usage-total"><small class="soft">Observed on ${esc(d.day)}</small><p><strong>${observed?usageGB(total.down_bytes):"—"}</strong> ↓ &nbsp; <strong>${observed?usageGB(total.up_bytes):"—"}</strong> ↑</p>
      <p class="live-note">Collection coverage ${fmt(total.coverage_pct,1)}% · ${fmt(total.observed_seconds/60,1)} observed minutes${total.first_observed?" · first "+clock(total.first_observed):""}</p>
      ${total.estimated_boundary?'<p class="live-note">Intervals crossing midnight are apportioned by time.</p>':""}
      ${!available?`<p class="live-note">${esc(w.reason||d.reason||"No fresh throughput measurement")}</p>`:""}</div></article>`;
  }).join("");
  (d.wans||[]).forEach((w,index)=>{
    const svg=$("usage-svg-"+index),W=svg.clientWidth||500,H=190,L=42,R=12,T=12,B=26;
    svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
    const x=t=>L+(W-L-R)*(t-t0)/(now-t0),y=v=>H-B-(H-B-T)*v/ymax;
    const points=(d.points||[]).filter(p=>p.wan===w.wan && p.ts>=t0 && p.ts<=now);
    let markup=[0,.5,1].map(f=>`<line x1="${L}" x2="${W-R}" y1="${y(ymax*f)}" y2="${y(ymax*f)}" stroke="${css("--line")}"/><text x="${L-6}" y="${y(ymax*f)+4}" text-anchor="end" font-size="11" fill="${css("--soft")}">${fmt(ymax*f,1)}</text>`).join("");
    for(const key of ["down_mbps","up_mbps"]){
      let path="",prev=null;
      for(const p of points){if(p[key]==null){prev=null;continue;}path+=`${!prev || p.ts-prev.ts>d.bucket*2.5?"M":"L"}${x(p.ts).toFixed(1)},${y(p[key]).toFixed(1)}`;prev=p;}
      markup+=`<path d="${path}" fill="none" stroke="${colorOf(w.wan)}" stroke-width="2" ${key==="up_mbps"?'stroke-dasharray="6 4"':""}/>`;
      if(points.length<=120)markup+=points.filter(p=>p[key]!=null).map(p=>`<circle cx="${x(p.ts)}" cy="${y(p[key])}" r="1.6" fill="${colorOf(w.wan)}"/>`).join("");
    }
    if(!points.length)markup+=`<text x="${W/2}" y="${H/2}" text-anchor="middle" font-size="12" fill="${css("--soft")}">No observed counter intervals yet</text>`;
    markup+=`<text x="${L}" y="${H-4}" font-size="11" fill="${css("--soft")}">${clock(t0)}</text><text x="${W-R}" y="${H-4}" text-anchor="end" font-size="11" fill="${css("--soft")}">${clock(now)}</text>`;
    svg.innerHTML=markup;
    const slider=$("usage-slider-"+index),readout=$("usage-readout-"+index);
    slider.max=Math.max(0,points.length-1);slider.disabled=!points.length;
    let selected=points.findIndex(p=>p.ts===usageSelections[w.wan]);if(selected<0)selected=points.length-1;
    slider.value=Math.max(0,selected);
    const show=p=>{readout.textContent=p?`${clock(p.ts)} · ↓ ${fmt(p.down_mbps,2)} / ↑ ${fmt(p.up_mbps,2)} Mbps · ${fmt(p.seconds)}s observed in bucket`:"No measurement at this time";};
    show(points[selected]);
    slider.oninput=()=>{const p=points[Number(slider.value)];if(p)usageSelections[w.wan]=p.ts;show(p);};
    svg.onpointermove=event=>{const box=svg.getBoundingClientRect(),t=t0+((event.clientX-box.left)/box.width*W-L)/(W-L-R)*(now-t0);
      const p=points.reduce((best,p)=>!best || Math.abs(p.ts-t)<Math.abs(best.ts-t)?p:best,null);show(p && Math.abs(p.ts-t)<=d.bucket*1.5?p:null);};
    svg.onpointerleave=()=>show(points[Number(slider.value)]);
  });
  if(focused?.startsWith("usage-slider-") && $(focused))$(focused).focus({preventScroll:true});
  const devices=d.devices||[],weight=row=>d.ranking==="now"?(row.rx_mbps||0)+(row.tx_mbps||0):(row.daily?.down_bytes||0)+(row.daily?.up_bytes||0);
  const max=Math.max(0,...devices.map(weight));
  $("usage-device-note").textContent=d.device_reason || `Top ${devices.length} DHCP-identified devices by ${d.ranking==="now"?"current router-reported RX + TX rate":"observed RX + TX bytes on "+d.day}. Counter coverage and firmware omissions apply; this is not per-WAN attribution.`;
  $("usage-devices").innerHTML=devices.map((row,index)=>`<tr><td>${index+1}. ${esc(row.label)}<small>${esc(row.mac)}</small><div class="usage-bar" style="width:${max?Math.max(0,Math.min(100,100*weight(row)/max)):0}%"></div></td>
    <td>${row.available?fmt(row.rx_mbps,2)+" / "+fmt(row.tx_mbps,2):"Unavailable"}<small>Mbps · router RX / TX</small></td>
    <td>${row.daily?.observed_seconds>0?usageGB(row.daily.down_bytes+row.daily.up_bytes):"No observations"}<small>${fmt((row.daily?.observed_seconds||0)/60,1)} collected min</small></td></tr>`).join("") || '<tr><td colspan="3">No identified device observations are available yet.</td></tr>';
}

document.addEventListener("DOMContentLoaded",()=>{
  for(const id of ["usage-day","usage-window","usage-ranking"])$(id).onchange=refreshUsage;
  refreshUsage();setInterval(()=>{if(!document.hidden)refreshUsage();},15000);
  document.addEventListener("visibilitychange",()=>{if(!document.hidden)refreshUsage();});
  window.addEventListener("resize",()=>{clearTimeout(window.wanUsageResize);window.wanUsageResize=setTimeout(renderUsage,150);});
});
