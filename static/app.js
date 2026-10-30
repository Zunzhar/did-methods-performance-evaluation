const API = '/api/v1';
const wallets = new Map(); // demo-only client wallet memory; cleared on refresh
let lastPermissionId = null;
let lastCredentialId = null;
let profileMap = {};

const $ = (id) => document.getElementById(id);
const json = (value) => JSON.stringify(value, null, 2);
const parseJson = (value, label) => {
  try { return JSON.parse(value); } catch { throw new Error(`${label} must be valid JSON.`); }
};

async function request(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.message || `Request failed (${res.status})`);
  return data;
}
function setResult(id, data, className = '') {
  const el = $(id);
  el.className = `result-box ${className}`.trim();
  el.innerHTML = '';
  if (typeof data === 'string') {
    const p = document.createElement('pre'); p.textContent = data; el.appendChild(p); return;
  }
  if (data && data.decision) {
    const head = document.createElement('div'); head.className='decision-hero';
    const pill = document.createElement('span'); pill.className=`pill ${data.allowed ? 'allow' : 'deny'}`; pill.textContent=data.decision;
    const word = document.createElement('div'); word.className='decision-word'; word.textContent=data.allowed ? 'Access granted' : 'Access denied';
    head.append(pill, word); el.appendChild(head);
    const checks = document.createElement('div'); checks.className='checks';
    for (const [key, val] of Object.entries(data.checks || {})) {
      const row=document.createElement('div'); row.className='check-row';
      const name=document.createElement('span'); name.textContent=key.replaceAll('_',' ');
      const status=document.createElement('b'); status.className=val?'pill allow':'pill deny'; status.textContent=val?'PASS':'FAIL';
      row.append(name,status); checks.appendChild(row);
    }
    el.appendChild(checks);
    if (data.reasons?.length) { const p=document.createElement('div'); p.className='warning-text'; p.textContent=data.reasons.join(' · '); el.appendChild(p); }
    const pre=document.createElement('pre'); pre.style.marginTop='10px'; pre.textContent=json(data); el.appendChild(pre); return;
  }
  const pre = document.createElement('pre'); pre.textContent = json(data); el.appendChild(pre);
}
function setError(id, err) { setResult(id, { error: err.message || String(err) }, 'error'); }
function escapeHtml(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function loadHealth() {
  try {
    const data = await request('/health');
    $('healthText').textContent = `${data.status} · ${data.mode}`;
    document.querySelector('.status-dot').classList.add('ok');
  } catch (e) { $('healthText').textContent = 'API not reachable · run the server'; }
}
async function loadProfiles() {
  try {
    const data = await request('/profiles');
    profileMap = Object.fromEntries(data.profiles.map(p => [p.id, p]));
    const select = $('profileSelect'); select.innerHTML = '';
    for (const p of data.profiles) {
      const option = document.createElement('option'); option.value=p.id; option.textContent=p.label; select.appendChild(option);
    }
    const list = $('profileList'); list.innerHTML='';
    for (const p of data.profiles) {
      const card=document.createElement('div'); card.className='profile-chip';
      card.innerHTML=`<strong>${escapeHtml(p.label)}</strong><span>${escapeHtml(p.architecture)}</span><span>Assumed update visibility: ${p.configured_visibility_delay_ms} ms</span><span class="mode-tag">SIMULATED PROFILE</span>`;
      list.appendChild(card);
    }
  } catch (e) { console.error(e); }
}

$('createForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const result = await request('/identities', { method:'POST', body:json({profile:$('profileSelect').value, alias:$('aliasInput').value}) });
    wallets.set(result.did, result.wallet_private_key);
    $('resolveDid').value = result.did; $('issuerDid').value = result.did; $('subjectDid').value = result.did;
    $('permissionDid').value = result.did; $('authDid').value = result.did;
    setResult('createResult', {did:result.did, profile:result.profile, status:result.status, version:result.version, wallet_key_held_in_this_tab:!!wallets.get(result.did), note:result.warning});
    setResult('resolveResult', result.document);
    await refreshEverything();
  } catch (e) { setError('createResult', e); }
});

$('resolveForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const did=encodeURIComponent($('resolveDid').value.trim());
  try { setResult('resolveResult', await request(`/identities/${did}`)); }
  catch(e) { setError('resolveResult', e); }
});
$('rotateBtn').addEventListener('click', async () => {
  const did=$('resolveDid').value.trim(); if(!did) return;
  try {
    const res=await request(`/identities/${encodeURIComponent(did)}/rotate`, {method:'POST',body:json({confirm:true})});
    if (res.wallet_private_key) wallets.set(did,res.wallet_private_key);
    setResult('resolveResult',res);
    window.setTimeout(async()=>{try{setResult('resolveResult',await request(`/identities/${encodeURIComponent(did)}`));}catch{}}, Math.max(50,res.visibility_delay_ms+25));
    await refreshEverything();
  } catch(e){setError('resolveResult',e);}
});
$('deactivateBtn').addEventListener('click', async () => {
  const did=$('resolveDid').value.trim(); if(!did) return;
  if(!confirm('Deactivate this DID? The simulated profile may have a propagation delay.')) return;
  try { setResult('resolveResult',await request(`/identities/${encodeURIComponent(did)}/deactivate`,{method:'POST',body:json({confirm:true})})); await refreshEverything(); }
  catch(e){setError('resolveResult',e);}
});

$('issueForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const claims=parseJson($('claimsInput').value,'Claims');
    const res=await request('/credentials',{method:'POST',body:json({issuer_did:$('issuerDid').value.trim(),subject_did:$('subjectDid').value.trim(),claims,expires_in_seconds:Number($('expirySelect').value)})});
    lastCredentialId=res.credential_id; $('credentialIdInput').value=res.credential_id; $('authCredentialId').value=res.credential_id;
    setResult('issueResult',res); await refreshEverything();
  } catch(e){setError('issueResult',e);}
});
$('credentialForm').addEventListener('submit', async (event) => {
  event.preventDefault(); const id=$('credentialIdInput').value.trim();
  try { setResult('credentialResult',await request(`/credentials/${encodeURIComponent(id)}/verify`,{method:'POST',body:'{}'})); }
  catch(e){setError('credentialResult',e);}
});
$('revokeCredentialBtn').addEventListener('click', async () => {
  const id=$('credentialIdInput').value.trim(); if(!id) return;
  if(!confirm('Revoke this credential? It may still be accepted until the simulated propagation delay passes.')) return;
  try { setResult('credentialResult',await request(`/credentials/${encodeURIComponent(id)}/revoke`,{method:'POST',body:json({confirm:true})})); await refreshEverything(); }
  catch(e){setError('credentialResult',e);}
});

$('permissionForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const conditions=parseJson($('conditionsInput').value,'Required context');
    const res=await request('/permissions',{method:'POST',body:json({did:$('permissionDid').value.trim(),resource:$('resourceInput').value.trim(),action:$('actionInput').value.trim(),require_credential:$('requireCredential').checked,conditions})});
    lastPermissionId=res.permission_id; setResult('permissionResult',res); await refreshEverything();
  } catch(e){setError('permissionResult',e);}
});

async function signChallenge(privateKeyB64, message) {
  if (!window.crypto?.subtle) throw new Error('WebCrypto is unavailable in this browser. Open this app in a modern browser on localhost.');
  const bytes=Uint8Array.from(atob(privateKeyB64), c=>c.charCodeAt(0));
  let privateKey;
  try { privateKey=await crypto.subtle.importKey('pkcs8',bytes,{name:'Ed25519'},false,['sign']); }
  catch { throw new Error('This browser does not support Ed25519 WebCrypto import. Try a current Chrome or Edge browser.'); }
  const signature=await crypto.subtle.sign('Ed25519',privateKey,new TextEncoder().encode(message));
  const array=new Uint8Array(signature); let binary=''; array.forEach(b=>binary+=String.fromCharCode(b)); return btoa(binary);
}
$('authorizeForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const did=$('authDid').value.trim(); const key=wallets.get(did);
    if(!key) throw new Error('No wallet key for this DID in the current tab. Create the DID in this tab again or re-create a demo identity. Keys are not restored after page reload.');
    const credentialId=$('authCredentialId').value.trim() || null;
    const context=parseJson($('contextInput').value,'Runtime context');
    const challenge=await request('/challenges',{method:'POST',body:json({did,verifier_id:$('verifierId').value.trim(),credential_id:credentialId,ttl_seconds:120})});
    const signature=await signChallenge(key,challenge.message);
    const result=await request('/authorize',{method:'POST',body:json({did,resource:$('authResource').value.trim(),action:$('authAction').value.trim(),challenge_id:challenge.challenge_id,signature,verifier_id:$('verifierId').value.trim(),credential_id:credentialId,context})});
    setResult('authorizeResult',result); await refreshEverything();
  } catch(e){setError('authorizeResult',e);}
});

$('runBenchmarkBtn').addEventListener('click', async () => {
  const button=$('runBenchmarkBtn'); button.disabled=true; button.textContent='Running…';
  try {
    const levels=$('concurrencyInput').value.split(',').map(x=>Number(x.trim())).filter(x=>Number.isFinite(x)&&x>0);
    const res=await request('/benchmarks/run',{method:'POST',body:json({iterations:Number($('iterationsInput').value),workload:$('workloadSelect').value,concurrency_levels:levels.length?levels:[1,10,50]})});
    setResult('benchmarkResult',{benchmark_id:res.benchmark_id,workload:res.workload,execution_mode:res.execution_mode});
    renderBenchmark(res.results); await refreshEverything();
  } catch(e){setError('benchmarkResult',e);}
  finally {button.disabled=false;button.textContent='Run benchmark';}
});
function renderBenchmark(results) {
  const wrap=$('benchmarkTableWrap');
  const cols=[['label','Profile'],['operations_completed','Ops'],['observed_throughput_ops_sec','Observed ops/s'],['median_observed_latency_ms','Median ms'],['p95_observed_latency_ms','P95 ms'],['mean_document_storage_bytes','Document bytes'],['synthetic_cost_units_per_iteration','Synthetic cost units'],['configured_propagation_delay_ms','Assumed propagation ms']];
  wrap.innerHTML=`<table><thead><tr>${cols.map(c=>`<th>${c[1]}</th>`).join('')}</tr></thead><tbody>${results.map(r=>`<tr>${cols.map(c=>`<td>${escapeHtml(r[c[0]])}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  if(results[0]?.concurrency_results){
    const sub=document.createElement('div');sub.className='table-wrap';sub.innerHTML='<div class="result-title">Enrollment burst by concurrency</div>'+results.map(r=>`<div class="subtle"><strong>${escapeHtml(r.label)}</strong></div><table><thead><tr><th>Concurrency</th><th>Operations</th><th>Observed ops/s</th><th>Wall time ms</th></tr></thead><tbody>${(r.concurrency_results||[]).map(x=>`<tr><td>${x.concurrency}</td><td>${x.operations}</td><td>${x.observed_throughput_ops_sec}</td><td>${x.observed_wall_time_ms}</td></tr>`).join('')}</tbody></table>`).join('');
    wrap.appendChild(sub);
  }
}

async function refreshMetrics() {
  try {
    const res=await request('/metrics/summary'); const t=res.totals;
    const cards=[['IDENTITIES',t.identities,'Synthetic DIDs stored'],['CREDENTIALS',t.credentials,'Prototype VC envelopes'],['PERMISSIONS',t.active_permissions,'Direct grants active'],['AUDIT EVENTS',t.audit_events,'Recorded operations'],['DENY / ERROR RATE',`${(t.overall_failure_rate*100).toFixed(1)}%`,'Across recorded audit events']];
    $('metricCards').innerHTML=cards.map(c=>`<div class="panel metric-card"><div class="metric-label">${c[0]}</div><div class="metric-number">${c[1]}</div><div class="metric-note">${c[2]}</div></div>`).join('');
  } catch(e){console.error(e);}
}
async function refreshAudit() {
  try {
    const res=await request('/audit?limit=30');
    $('auditBody').innerHTML=res.events.length?res.events.map(e=>`<tr><td>${escapeHtml(e.timestamp)}</td><td>${escapeHtml(e.profile||'—')}</td><td>${escapeHtml(e.operation)}</td><td><span class="pill ${['success','allowed'].includes(e.response_class)?'success':(['denied','rejected','not_found','error'].includes(e.response_class)?'deny':'pending')}">${escapeHtml(e.response_class)}</span></td><td>${escapeHtml(e.observed_duration_ms)}</td><td>${escapeHtml(e.synthetic_cost_units)}</td><td title="${escapeHtml(e.identifier)}">${escapeHtml((e.identifier||'—').slice(0,30))}</td></tr>`).join(''):'<tr><td colspan="7" class="muted">No audit events yet.</td></tr>';
  } catch(e){console.error(e);}
}
async function refreshEverything(){await Promise.all([refreshMetrics(),refreshAudit()]);}
$('refreshProfiles').addEventListener('click',loadProfiles);
$('refreshMetrics').addEventListener('click',refreshMetrics);
$('refreshAudit').addEventListener('click',refreshAudit);
loadHealth(); loadProfiles(); refreshEverything();
