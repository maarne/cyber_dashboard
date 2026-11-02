/* Network controls are explicit POST actions. Page loads only read saved data. */
(() => {
    'use strict';
    const root = document.querySelector('.asset-workspace'); if (!root) return;
    const $ = id => document.getElementById(id), admin = root.dataset.admin === 'true';
    const csrf = document.querySelector('meta[name="asset-csrf-token"]').content;
    const message = text => { $('asset-message').textContent = text; };
    const wrap = fn => async event => { event?.preventDefault(); const b = event?.submitter || (event?.currentTarget?.tagName === 'BUTTON' ? event.currentTarget : null); if (b) b.disabled = true;
        try { await fn(event); } catch (e) { message(e.message); } finally { if (b) b.disabled = false; } };
    async function api(url, method = 'GET', data) {
        const r = await fetch(url, {method, credentials:'same-origin', cache:'no-store', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, ...(data === undefined ? {} : {body:JSON.stringify(data)})});
        const value = await r.json(); if (!r.ok) throw new Error(`${r.status}: ${typeof value.detail === 'string' ? value.detail : JSON.stringify(value.detail || value)}`); return value;
    }
    function node(tag, text) {const e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e;}
    function button(text, action) {const b = node('button', text); b.type='button'; b.className='btn btn-secondary btn-sm'; b.addEventListener('click',wrap(action)); return b;}
    function date(value) {return value ? new Date(value * 1000).toLocaleString() : '—';}
    function showCapabilities(prefix, caps) {
        $(`${prefix}-capabilities`).textContent = JSON.stringify(caps, null, 2);
        $(`${prefix}-scope-warning`).textContent = caps.scope.configured ? '' :
            'No destinations are authorized. Disabled drafts can be saved; ask the operator to set ASSET_PROBE_ALLOWED_CIDRS before enabling checks.';
    }
    function table(container, headings, rows) {
        container.replaceChildren(); if (!rows.length) {container.append(node('p','No saved results.')); return;}
        const scroll=node('div'); scroll.className='asset-scroll'; const t=node('table'), head=node('thead'), tr=node('tr');
        headings.forEach(s=>{const th=node('th',s); th.scope='col'; tr.append(th);});head.append(tr);t.append(head);const body=node('tbody');
        rows.forEach(values=>{const tr=node('tr');values.forEach(value=>{const td=node('td');if (value instanceof Node) td.append(value); else td.textContent=value??'—';tr.append(td);});body.append(tr);});t.append(body);scroll.append(t);container.append(scroll);
    }
    function pager(container, data, load) {const bar=node('div');bar.className='asset-pager';const prev=button('Previous',()=>load(Math.max(0,data.offset-data.limit))),next=button('Next',()=>load(data.offset+data.limit));prev.disabled=!data.offset;next.disabled=data.offset+data.limit>=data.total;bar.append(prev,node('span',`${data.total} records`),next);container.append(bar);}
    function codes(text) {const set=new Set();text.split(',').forEach(part=>{const match=part.trim().match(/^(\d{3})(?:-(\d{3}))?$/);if (!match) throw new Error('Use codes/ranges such as 200-399,401.');const from=Number(match[1]),to=Number(match[2]||match[1]);if (from<100||to>599||to<from)throw new Error('HTTP codes must be 100–599.');for(let i=from;i<=to;i++)set.add(i);});return [...set];}
    function codeText(values) {const sorted=[...values].sort((a,b)=>a-b),parts=[];let i=0;while(i<sorted.length){const start=sorted[i];let end=start;while(i+1<sorted.length&&sorted[i+1]===end+1)end=sorted[++i];parts.push(start===end?`${start}`:`${start}-${end}`);i++;}return parts.join(',');}
    function fill(form, data) {form.reset();Object.entries(data).forEach(([key,value])=>{const e=form.elements.namedItem(key);if(!e)return;if(e.type==='checkbox')e.checked=!!value;else if(key==='first_run_at')e.value=value?new Date(value*1000).toISOString().slice(0,16):'';else if(key==='networks'||key==='exclusions')e.value=value.join('\n');else if(key==='ports')e.value=value.join(',');else if(key==='expected_codes')e.value=codeText(value);else e.value=value??'';});if(data.interval_seconds){const unit=[86400,3600,60,1].find(u=>data.interval_seconds%u===0);form.elements.interval_unit.value=String(unit);form.elements.interval_amount.value=data.interval_seconds/unit;}}
    function interval(form) {const value=Number(form.elements.interval_amount.value)*Number(form.elements.interval_unit.value);if(!Number.isSafeInteger(value)||value<1||value>31536000)throw new Error('Interval must be a positive whole number of seconds, at most one year.');return value;}
    const key=()=>crypto.randomUUID().replaceAll('-','');
    async function poll(url, update) {for(let i=0;i<30;i++){const job=await api(url);await update(job);if(!['queued','running'].includes(job.status))return;await new Promise(resolve=>setTimeout(resolve,2000));}message('Job remains queued/running. Use Refresh saved results to check later; no additional traffic was requested.');}
    if ($('asset-data')) {
        const asset=JSON.parse($('asset-data').textContent), base=`/api/assets/${asset.id}`;let current=null;
        async function reviewedEvidence(offset = 0) {
            if (!$('asset-discovery-evidence')) return;
            const data = await api(`${base}/discovery-evidence?offset=${offset}`);
            table($('asset-discovery-evidence'), ['Imported at / actor', 'Preserved snapshot'], data.items.map(row => {
                const details = node('details');
                details.append(node('summary', `Evidence #${row.id} · SHA-256 ${row.snapshot_hash}`), node('pre', JSON.stringify(JSON.parse(row.snapshot_json), null, 2)));
                return [`${date(row.imported_at)} / ${row.imported_by}`, details];
            }));
            pager($('asset-discovery-evidence'), data, reviewedEvidence);
        }
        async function addresses(offset=0){if(!$('asset-addresses'))return;const data=await api(`${base}/addresses?offset=${offset}`);table($('asset-addresses'),['Address / observed hostname','Scope','Observed at','Provenance'],data.items.map(r=>{const d=node('details');d.append(node('summary','Review evidence'),node('pre',JSON.stringify(JSON.parse(r.provenance_json),null,2)));return[`${r.address} / ${r.hostname||'unknown'}`,r.scope,date(r.observed_at),d];}));pager($('asset-addresses'),data,addresses);}
        async function history(offset=0){const data=await api(`${base}/monitoring/history?offset=${offset}`);table($('monitor-history'),['Time','Job / status','Observation'],data.items.map(j=>[date(j.completed_at||j.started_at||j.created_at),`#${j.id} ${j.status}`,JSON.stringify(j.result)]));pager($('monitor-history'),data,history);}
        async function loadMonitor(refill=false){current=await api(`${base}/monitoring`);const state=current.state;$('monitor-state').replaceChildren(node('strong',`Availability: ${state.availability}`),node('p',`Runner: ${state.runner||'not configured'} · Last success: ${date(state.last_success)} · Failure streak: ${state.failures||0}/${state.failure_threshold||'—'} · Fresh until: ${date(state.fresh_until)}`),node('pre',JSON.stringify(state.latest||{reason:'not checked'},null,2)),node('p',current.job?`Job #${current.job.id}: ${current.job.status}`:'No pending check.'));
            if($('monitor-check'))$('monitor-check').disabled=!current.config?.enabled;
            if(refill&&$('monitor-form'))fill($('monitor-form'),current.config?.settings||{});await history();}
        $('monitor-refresh')?.addEventListener('click',wrap(()=>loadMonitor(true)));
        $('monitor-check')?.addEventListener('click',wrap(async()=>{if(!current?.config?.enabled)throw new Error('An administrator must enable a saved check first.');const job=await api(`${base}/monitoring/check`,'POST',{expected_generation:current.config.generation,idempotency_key:key()});message(`Queued check #${job.id}.`);await poll(`${base}/monitoring/jobs/${job.id}`,()=>loadMonitor());}));
        $('monitor-form')?.addEventListener('submit',wrap(async()=>{const f=$('monitor-form'),d=Object.fromEntries(new FormData(f));const body={expected_version:current?.config?.row_version||0,target:d.target,method:d.method,port:d.method==='icmp'||!d.port?null:Number(d.port),http_method:d.http_method,path:d.path,expected_codes:codes(d.expected_codes),interval_seconds:interval(f),timeout_seconds:Number(d.timeout_seconds),failure_threshold:Number(d.failure_threshold),enabled:f.elements.enabled.checked,authorized:f.elements.authorized.checked,scheduled:f.elements.scheduled.checked};await api(`${base}/monitoring`,'PUT',body);message('Configuration saved. No target contacted by save; scheduled work waits for its due time.');await loadMonitor(true);}));
        wrap(async()=>{await Promise.all([addresses(), reviewedEvidence()]);if($('monitor-panel')){const caps=await api('/api/asset-monitoring/capabilities');showCapabilities('monitor', caps);await loadMonitor(true);}})();
    }
    if ($('discovery-workspace')) {
        let editing=null,pageRows=[],selected=new Map(),previewToken=null;const imports=new Map();
        function selection(){if($('selection-count'))$('selection-count').textContent=`${selected.size} selected (maximum 100)`;}
        function invalidate(){previewToken=null;if($('discovery-import-commit'))$('discovery-import-commit').hidden=true;if($('discovery-import-preview'))$('discovery-import-preview').textContent='';}
        async function profiles(){const data=await api(admin?'/api/asset-discovery/profiles':'/api/asset-discovery/approved-profiles');table($('discovery-profiles'),['Profile','Requested cadence / next due','State','Actions'],data.items.map(p=>{const settings=p.settings||{},actions=node('div');if(admin)actions.append(button('Edit',()=>{editing=p;fill($('discovery-profile-form'),settings);$('profile-editor').open=true;$('profile-editor').scrollIntoView({block:'nearest'});}));const run=button('Run now',async()=>{const job=await api(`/api/asset-discovery/profiles/${p.id}/runs`,'POST',{expected_generation:p.generation,idempotency_key:key()});message(`Queued discovery run #${job.id}. No inventory was imported.`);await poll(`/api/asset-discovery/runs/${job.id}`,async()=>{await runs();await candidates();});});run.disabled=!p.enabled;actions.append(run);return[`#${p.id} ${settings.name||p.name}`,`${settings.interval_seconds?`${settings.interval_seconds} seconds requested · `:''}${date(p.next_due)}`,p.enabled?(settings.scheduled?'Enabled / scheduled':'Enabled / manual'):'Disabled',actions];}));}
        async function runs(offset=0){const data=await api(`/api/asset-discovery/runs?offset=${offset}`);table($('discovery-runs'),['Run / profile','Requested / started / ended','State / coverage','Actions'],data.items.map(j=>{const a=node('div');if(['queued','running'].includes(j.status))a.append(button('Cancel',async()=>{await api(`/api/asset-discovery/runs/${j.id}/cancel`,'POST');await runs();}));const d=node('details');d.append(node('summary',`${j.status} · ${j.processed} targets / ${j.responding} responses · ${j.skipped_periods} coalesced periods`),node('pre',JSON.stringify(j.result,null,2)));return[`#${j.id} / profile ${j.profile_id}`,`${date(j.due_at)} / ${date(j.started_at)} / ${date(j.completed_at)}`,d,a];}));pager($('discovery-runs'),data,runs);}
        async function candidates(offset = 0) {
            const query = new URLSearchParams(new FormData($('candidate-filters')));
            if (!query.get('profile_id')) query.delete('profile_id');
            query.set('offset', offset);
            const data = await api(`/api/asset-discovery/candidates?${query}`);
            pageRows = data.items;
            const headings = ['IP / observed hostname', 'Network / last seen', 'Review / possible matches'];
            if (admin) headings.unshift('Select');
            if (admin) headings.push('Actions');
            table($('discovery-candidates'), headings, data.items.map(c => {
                const row = [
                    `${c.address} / ${c.hostname || 'no hostname found'}`,
                    `${(c.networks || []).join(', ') || 'unknown network'} / ${c.scope} / profile ${c.observation?.profile_id || '—'} · ${date(c.last_seen)}`,
                    `${c.imported_asset_id ? `Imported asset #${c.imported_asset_id}` : c.is_ignored ? 'Ignored' : c.needs_review ? 'Name/binding changed — review, not proven device identity' : 'New'} · ${c.possible_matches.map(m => `#${m.id} ${m.name}`).join(', ') || 'no reviewed address match'}`
                ];
                if (admin) {
                    const check = node('input');
                    check.type = 'checkbox'; check.setAttribute('aria-label', `Select ${c.address}`);
                    check.checked = selected.has(c.id);
                    check.disabled = !!c.imported_asset_id || !!c.is_ignored || !c.observation;
                    check.addEventListener('change', () => {
                        if (check.checked && selected.size >= 100) {
                            check.checked = false; message('Select at most 100 candidates.'); return;
                        }
                        if (check.checked) selected.set(c.id, c); else selected.delete(c.id);
                        selection();
                    });
                    row.unshift(check);
                    const actions = node('div');
                    if (!c.imported_asset_id && !c.is_ignored) actions.append(button('Import…', () => {
                        selected = new Map([[c.id, c]]); selection(); openImport();
                    }));
                    if (c.imported_asset_id) actions.append(button('Review binding', async () => {
                        if (!confirm('Reopen this candidate for explicit create/link review? Existing assets, address evidence and monitoring targets will be preserved.')) return;
                        await api(`/api/asset-discovery/candidates/${c.id}/review`, 'POST', {expected_version: c.row_version, ignored: false, reopen_import: true});
                        await candidates();
                    }));
                    actions.append(button(c.is_ignored ? 'Unignore' : 'Ignore', async () => {
                        await api(`/api/asset-discovery/candidates/${c.id}/review`, 'POST', {expected_version: c.row_version, ignored: !c.is_ignored});
                        selected.delete(c.id); selection(); await candidates();
                    }));
                    row.push(actions);
                }
                return row;
            }));
            pager($('discovery-candidates'), data, candidates);
        }
        $('candidate-filters').addEventListener('submit',wrap(()=>candidates()));
        $('discovery-refresh').addEventListener('click',wrap(()=>Promise.all([profiles(),runs(),candidates()])));
        $('profile-new')?.addEventListener('click',()=>{editing=null;$('discovery-profile-form').reset();message('New profile draft. No traffic requested.');});
        $('discovery-profile-form')?.addEventListener('submit',wrap(async()=>{const f=$('discovery-profile-form'),d=Object.fromEntries(new FormData(f));const split=v=>v.split(/[\s,;]+/).filter(Boolean);const body={expected_version:editing?.row_version||0,name:d.name,networks:split(d.networks),exclusions:split(d.exclusions),ports:split(d.ports).map(Number),interval_seconds:interval(f),timeout_seconds:Number(d.timeout_seconds),first_run_at:d.first_run_at?new Date(`${d.first_run_at}Z`).getTime()/1000:null};for(const name of ['enabled','authorized','scheduled','resolve_names','forward_confirm','allow_partial'])body[name]=f.elements[name].checked;const result=await api(editing?`/api/asset-discovery/profiles/${editing.id}`:'/api/asset-discovery/profiles',editing?'PATCH':'POST',body);editing=result;message(`Profile saved without traffic. Estimate: ${JSON.stringify(result.estimate)}. Requested cadence is not guaranteed cadence.`);await profiles();}));
        $('select-page')?.addEventListener('click',wrap(async()=>{for(const c of pageRows){if(!c.imported_asset_id&&!c.is_ignored&&c.observation&&selected.size<100)selected.set(c.id,c);}selection();await candidates();}));
        $('clear-selection')?.addEventListener('click',wrap(async()=>{selected.clear();selection();await candidates();}));
        function input(name,value,type='text'){const e=node('input');e.name=name;e.value=value;e.type=type;if(type==='number'){e.min='1';e.step='1';}return e;}
        function labeled(text,e){const label=node('label',text);label.append(e);return label;}
        function openImport(){if(!selected.size)throw new Error('Select candidates first.');invalidate();imports.clear();const container=$('discovery-import-rows');container.replaceChildren();for(const c of selected.values()){const box=node('fieldset');box.className='asset-panel';box.append(node('legend',`${c.address} / ${c.hostname||'unknown'} · observed ${date(c.last_seen)}`));const action=node('select');for(const [v,t]of [['create','Create new asset'],['link','Link existing asset (preserve fields)'],['skip','Skip']]){const o=node('option',t);o.value=v;action.append(o);}const name=input('name',c.hostname||c.address),external=input('external_id',`discovery-${c.id}`),assetId=input('asset_id','','number'),version=input('expected_version','','number');box.append(labeled('Action',action),labeled('New asset name',name),labeled('New external ID',external),labeled('Existing asset ID (link only)',assetId),labeled('Existing row version (link only)',version),node('p',`Possible matches: ${c.possible_matches.map(m=>`asset #${m.id}, version ${m.row_version}: ${m.name}${m.is_archived?' (archived)':''}`).join('; ')||'none; no automatic match'}`));container.append(box);imports.set(c.id,{candidate:c,action,name,external,assetId,version});}$('discovery-import-dialog').showModal();}
        $('import-selected')?.addEventListener('click',wrap(()=>openImport()));
        $('discovery-import-close')?.addEventListener('click',()=>{$('discovery-import-dialog').close();invalidate();});
        $('discovery-import-form')?.addEventListener('input',invalidate);
        $('discovery-import-form')?.addEventListener('change',invalidate);
        $('discovery-import-form')?.addEventListener('submit',wrap(async()=>{const f=$('discovery-import-form'),d=Object.fromEntries(new FormData(f)),items=[];invalidate();for(const v of imports.values()){if(v.action.value==='skip')continue;const item={candidate_id:v.candidate.id,observation_id:v.candidate.observation.id,action:v.action.value};if(item.action==='create')item.asset={external_id:v.external.value,name:v.name.value,environment:d.environment,owner_team:d.owner_team,criticality:Number(d.criticality),exposure:d.exposure,tags:d.tags.split(';').map(s=>s.trim()).filter(Boolean)};else{item.asset_id=Number(v.assetId.value);item.expected_version=Number(v.version.value);}items.push(item);}if(!items.length)throw new Error('No selected rows remain.');const result=await api('/api/asset-discovery/import/preview','POST',{items});previewToken=result.preview_token;$('discovery-import-preview').textContent=JSON.stringify(result,null,2);$('discovery-import-commit').hidden=false;message('Review exact preview, then explicitly confirm import. No monitoring will be enabled.');}));
        $('discovery-import-commit')?.addEventListener('click', wrap(async () => {
            if (!previewToken) throw new Error('Preview the selection again.');
            const result = await api('/api/asset-discovery/import/commit', 'POST', {preview_token: previewToken});
            invalidate(); $('discovery-import-dialog').close(); selected.clear(); selection();
            message(`Imported/linked ${result.items.length} selected assets; monitoring remains disabled. `);
            result.items.forEach(item => {
                const link = node('a', `Open asset #${item.asset_id}`);
                link.href = `/assets/${item.asset_id}`;
                $('asset-message').append(link, document.createTextNode(' · '));
            });
            await candidates();
        }));
        wrap(async()=>{const caps=await api('/api/asset-discovery/capabilities');showCapabilities('discovery', caps);await Promise.all([profiles(),runs(),candidates()]);})();
    }
})();
