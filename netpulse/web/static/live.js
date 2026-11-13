/* Live, source-bound probe measurements. No external libraries or network assets. */
let liveData = null, liveBusy = false;
const liveSelection = {};
const INTERNET_LABELS = {ONLINE:"Internet usable",PARTIAL:"Partially reachable",DNS_FAILURE:"DNS failure",
  RESTRICTED:"Possible restriction",NO_INTERNET:"Web checks failing",MONITOR_ERROR:"Monitor problem",UNKNOWN:"Awaiting web checks"};
const WEB_ERRORS = {dns_failed:"DNS resolution failed",timeout:"Timed out",tls_failed:"TLS verification failed",
  source_unavailable:"Pi probe address unavailable",connection_failed:"Connection failed",invalid_response:"Invalid response",unexpected_response:"Unexpected response"};

function webEvidence(w, now) {
  const c = w.connectivity, age = c ? now - Number(c.checked_at) : NaN;
  if (w.state === "UNKNOWN" && (w.errors || []).length) return {state:"MONITOR_ERROR",reason:"The Pi cannot send measurements on this path",checks:[],age:null};
  if (!c || !Number.isFinite(age) || age < 0 || age > 180 || !(c.web_checks || []).length)
    return {state:"UNKNOWN",reason:"Independent web evidence is missing or stale; Internet usability is unconfirmed",checks:[],age:null};
  return {state:c.internet_state || "UNKNOWN",reason:c.internet_reason,checks:c.web_checks,age,c};
}

function renderNetworkOverview(s) {
  const opened = Array.from($("isps").querySelectorAll("details")).map(detail=>detail.open);
  const now = feedNow(s), monitorAge = now - Number(s.updated);
  const fresh = Number.isFinite(monitorAge) && monitorAge >= 0 && monitorAge <= 30;
  const rows = s.wans.map(w => ({w,e:fresh ? webEvidence(w,now) :
    {state:"UNKNOWN",reason:"Monitor data is stale; current Internet usability is unconfirmed",checks:[],age:null}}));
  const online = rows.filter(row => row.e.state === "ONLINE").length;
  const unknown = rows.some(row => ["UNKNOWN","MONITOR_ERROR"].includes(row.e.state));
  const level = !fresh || unknown ? "UNKNOWN" : online === rows.length ? "HEALTHY" : online ? "DEGRADED" : "OFFLINE";
  $("monitor").dataset.level = level;
  $("verdict").textContent = !fresh ? "Monitor data is stale" : unknown ? "Checking Internet usability" :
    online === rows.length ? "Both Internet paths are usable" : online ? "One Internet path needs attention" : "Internet checks need attention";
  $("because").textContent = !fresh ? "Probe measurements are missing or delayed. Router traffic is collected separately; retained probe readings are for reference." :
    rows.map(({w,e}) => `${labelOf(w.name)}: ${INTERNET_LABELS[e.state] || "Checking"}`).join(" · ");
  if (!fresh) $("updated").classList.add("stale");
  const delivery = s.alert_policy?.delivery_since_start || {};
  const tg = !s.alert_policy?.telegram_enabled ? "Off" : delivery.durable_store_ok === false ? "Queue storage needs attention" :
    delivery.queued ? `${delivery.queued} pending` : "No pending messages";
  $("ops-summary").innerHTML = `<div><span>INTERNET EVIDENCE</span><strong>${fresh && !unknown ? online+" / "+rows.length+" paths passed" : "Awaiting fresh checks"}</strong></div>
    <div><span>MEASUREMENT FEED</span><strong>${fresh ? "Fresh · 10 second samples" : "Stale / unavailable"}</strong></div>
    <div><span>TELEGRAM</span><strong>${esc(tg)}</strong></div><div><span>ALERT CONFIRMATION</span><strong>2 failures · partial needs 3</strong></div>`;
  $("isps").innerHTML = rows.map(({w,e}) => {
    const valid = fresh && w.state !== "UNKNOWN";
    const badge = !fresh ? "UNKNOWN" : e.state === "ONLINE" ? "HEALTHY" : e.state === "PARTIAL" ? "DEGRADED" :
      ["UNKNOWN","MONITOR_ERROR"].includes(e.state) ? "UNKNOWN" : "OFFLINE";
    const web = e.checks.map(check => `<li><strong>${esc(check.provider)}</strong>: ${check.ok ? "Expected HTTP 204 received" :
      esc(check.status_code ? `Unexpected HTTP ${check.status_code}` : WEB_ERRORS[check.error] || "Check failed")}${check.elapsed_ms ? ` · ${fmt(check.elapsed_ms)} ms` : ""}</li>`).join("");
    return `<article class="card isp" style="--c:${colorOf(w.name)}"><div class="isp-head"><div class="isp-name">${esc(labelOf(w.name))}<span>${esc(w.name)}</span></div>
      <span class="state ${badge}">${esc(!fresh ? "Stale" : INTERNET_LABELS[e.state] || "Checking")}</span></div>
      <p class="connection-reason">${esc(!fresh ? "Last known values; waiting for fresh monitor data" : e.reason)}</p>
      <div class="evidence-grid"><div class="evidence-cell"><small>Ping latency · typical over 5 min</small><strong>${valid ? fmt(w.rtt_ms,1)+" ms" : "Unavailable"}</strong></div>
      <div class="evidence-cell"><small>Observed ping loss · 5 min</small><strong>${valid ? fmt(w.loss_pct,1)+"%" : "Unavailable"}</strong></div>
      <div class="evidence-cell" data-ok="${e.c ? e.c.dns_ok : "unknown"}"><small>Public DNS</small><strong>${e.c ? e.c.dns_ok ? "Responding" : "Failed" : "Not confirmed"}</strong></div>
      <div class="evidence-cell"><small>Independent web checks</small><strong>${e.checks.length ? e.checks.filter(c=>c.ok).length+" / 2 passed" : "Not confirmed"}</strong></div></div>
      <details class="probe-details"><summary>Evidence and diagnosis${e.age == null ? "" : " · "+Math.floor(e.age)+"s ago"}</summary>
      <ul>${web || "<li>No fresh web check result available</li>"}<li>Ping quality: ${esc(STATE_WORD[w.state] || w.state)}. Ping loss alone does not prove an Internet outage.</li>
      ${(w.errors||[]).map(error=>`<li>${esc(error)}</li>`).join("")}
      ${e.c?.wan_dns_ok == null ? "" : `<li>WAN-assigned DNS: ${e.c.wan_dns_ok ? "responding" : "failed"}</li>`}</ul>
      <p class="soft">A portal or exhausted data allowance is a possible cause, not a confirmed diagnosis. Router carrier and Internet usability are separate checks.</p></details></article>`;
  }).join("");
  $("isps").querySelectorAll("details").forEach((detail,index)=>{detail.open=!!opened[index];});
}

async function refreshLive() {
  if (liveBusy) return;
  liveBusy = true;
  try { liveData = await getJSON("/api/live"); drawLive(); }
  catch (_) { $("live-status").textContent = "Live feed unavailable · showing last received samples"; }
  finally { liveBusy = false; }
}

function drawLive() {
  if (!lastStatus) return;
  const focused = document.activeElement?.id;
  const opened = Array.from($("live-plots").querySelectorAll("details")).map(detail=>detail.open);
  const now = feedNow(liveData || lastStatus), minutes = Number($("live-window").value), key = $("live-metric").value;
  const t0 = now - minutes * 60, unit = key === "loss_pct" ? "%" : "ms";
  const age = liveData?.updated == null ? Infinity : now-liveData.updated;
  const fresh = age >= 0 && age <= (liveData?.max_age_seconds || 30);
  $("live-status").textContent = fresh ? `Live · last sample ${Math.floor(age)}s ago · ${liveData.interval_seconds}s interval · since this service started` :
    "Waiting for fresh samples · gaps are not counted as outages";
  $("live-plots").innerHTML = lastStatus.wans.map((w,index) => {
    const points = (liveData?.points||[]).filter(p=>p.wan===w.name && p.ts>=t0 && p.ts<=now);
    const latest = points[points.length-1], value = fresh && latest?.[key] != null ? `${fmt(latest[key],1)} ${unit}` : "Unavailable";
    return `<article class="card live-panel" style="--c:${colorOf(w.name)}"><header><h3>${esc(labelOf(w.name))}</h3><span class="live-value">${value}</span></header>
      <svg class="live-plot" id="live-svg-${index}" role="img" aria-label="${esc(labelOf(w.name))} ${esc(key)} over the last ${minutes} minutes"></svg>
      <label class="sample-explorer">Explore samples<input type="range" id="live-slider-${index}" min="0" max="${Math.max(0,points.length-1)}" value="${Math.max(0,points.length-1)}" ${points.length ? "" : "disabled"} aria-label="Explore ${esc(labelOf(w.name))} samples"></label>
      <div class="sample-readout" id="live-readout-${index}" aria-live="polite"></div>
      <details><summary>Recent measured values</summary><table><thead><tr><th>Time</th><th>Latency ms</th><th>Loss %</th><th>Jitter ms</th></tr></thead><tbody>
      ${points.slice(-6).reverse().map(p=>`<tr><td>${clock(p.ts)}</td><td>${fmt(p.rtt_ms,1)}</td><td>${fmt(p.loss_pct,1)}</td><td>${fmt(p.jitter_ms,1)}</td></tr>`).join("") || '<tr><td colspan="4">No measurements yet</td></tr>'}</tbody></table></details></article>`;
  }).join("");
  const sharedValues=(liveData?.points||[]).filter(p=>p.ts>=t0 && p.ts<=now && p[key]!=null).map(p=>p[key]);
  const sharedMax=key==="loss_pct"?100:Math.max(10,...sharedValues)*1.15;
  lastStatus.wans.forEach((w,index)=>{
    const points = (liveData?.points||[]).filter(p=>p.wan===w.name && p.ts>=t0 && p.ts<=now);
    const svg = $("live-svg-"+index), width = svg.clientWidth || 500, H=190, L=42,R=12,T=12,B=26;
    svg.setAttribute("viewBox",`0 0 ${width} ${H}`);
    const vals=points.filter(p=>p[key]!=null), max=sharedMax;
    const x=t=>L+(width-L-R)*(t-t0)/(now-t0),y=v=>H-B-(H-B-T)*v/max;
    let path="",prev=null;
    for(const p of points){if(p[key]==null){prev=null;continue;}path+=`${!prev || p.ts-prev.ts>(liveData.interval_seconds||10)*2.5 ? "M":"L"}${x(p.ts).toFixed(1)},${y(p[key]).toFixed(1)}`;prev=p;}
    svg.innerHTML=[0,.5,1].map(f=>`<line x1="${L}" x2="${width-R}" y1="${y(max*f)}" y2="${y(max*f)}" stroke="${css("--line")}"/><text x="${L-7}" y="${y(max*f)+4}" text-anchor="end" font-size="11" fill="${css("--soft")}">${fmt(max*f)}</text>`).join("")+
      `<path d="${path}" fill="none" stroke="${colorOf(w.name)}" stroke-width="2"/>`+
      vals.map(p=>`<circle cx="${x(p.ts)}" cy="${y(p[key])}" r="1.8" fill="${colorOf(w.name)}"/>`).join("")+
      `<text x="${L}" y="${H-4}" font-size="11" fill="${css("--soft")}">${clock(t0)}</text><text x="${width-R}" y="${H-4}" text-anchor="end" font-size="11" fill="${css("--soft")}">${clock(now)}</text>`;
    const slider=$("live-slider-"+index),readout=$("live-readout-"+index);
    const show=p=>{readout.textContent=p?`${clock(p.ts)} · ${p[key]==null?"Measurement unavailable":fmt(p[key],1)+" "+unit}`:"No measurement at this time";};
    const selected=liveSelection[w.name];
    const selectedIndex=selected==null?-1:points.findIndex(p=>p.ts===selected);
    if(selectedIndex>=0)slider.value=selectedIndex;
    show(points[selectedIndex>=0?selectedIndex:points.length-1]);
    slider.oninput=()=>{const p=points[Number(slider.value)];if(p)liveSelection[w.name]=p.ts;show(p);};
    svg.onpointermove=event=>{const box=svg.getBoundingClientRect(),t=t0+((event.clientX-box.left)/box.width*width-L)/(width-L-R)*(now-t0);
      const p=points.reduce((best,p)=>!best || Math.abs(p.ts-t)<Math.abs(best.ts-t)?p:best,null);show(p && Math.abs(p.ts-t)<=(liveData.interval_seconds||10)*1.5?p:null);};
    svg.onpointerleave=()=>show(points[Number(slider.value)]);
  });
  $("live-plots").querySelectorAll("details").forEach((detail,index)=>{detail.open=!!opened[index];});
  if (focused?.startsWith("live-slider-") && $(focused)) $(focused).focus({preventScroll:true});
}

document.addEventListener("DOMContentLoaded",()=>{
  $("live-metric").onchange=drawLive;$("live-window").onchange=drawLive;
  document.addEventListener("visibilitychange",()=>{if(!document.hidden){refreshStatus();refreshLive();}});
  window.addEventListener("resize",()=>{clearTimeout(window.wanLiveResize);window.wanLiveResize=setTimeout(drawLive,150);});
});
/* Anchor links remain usable without script; with script they become focused workspaces. */
function setupDashboardWorkspace(){
  const pages=Array.from(document.querySelectorAll('[data-dashboard-page]'));
  const links=Array.from(document.querySelectorAll('.section-nav a'));
  const views={monitor:'overview','devices-heading':'devices','history-heading':'history','system-heading':'system'};
  const titles={overview:'Network overview',devices:'Devices & usage',history:'Network history',system:'System & diagnostics'};
  function selectView(){
    const anchor=location.hash.slice(1),key=views[anchor] || 'overview';
    pages.forEach(page=>{page.hidden=page.dataset.dashboardPage!==key;});
    links.forEach(link=>{if(views[link.hash.slice(1)]===key)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');});
    $('workspace-title').textContent=titles[key];
    window.scrollTo({top:0,behavior:'instant'});
    // Previously hidden charts need their real width, including after browser Back.
    requestAnimationFrame(()=>{drawLive();renderUsage();if(key==='history')refreshHistory();});
  }
  window.addEventListener('hashchange',selectView);
  selectView();
  const theme=$('dashboard-theme');
  function applyTheme(value){
    if(value==='auto')document.documentElement.removeAttribute('data-theme');
    else document.documentElement.dataset.theme=value;
    try{localStorage.setItem('wancompass-theme',value);}catch(_){}
    drawLive();renderUsage();refreshHistory();
  }
  try{const saved=localStorage.getItem('wancompass-theme');if(['light','dark','auto'].includes(saved))theme.value=saved;}catch(_){}
  theme.onchange=()=>applyTheme(theme.value);
  applyTheme(theme.value);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(theme.value==='auto'){drawLive();renderUsage();refreshHistory();}});
}
document.addEventListener('DOMContentLoaded',setupDashboardWorkspace);
