/* Private inventory UI: all imported/user text is rendered as text, never HTML. */
(() => {
    'use strict';
    const root = document.querySelector('.asset-workspace');
    if (!root) return;
    const $ = id => document.getElementById(id);
    const csrf = document.querySelector('meta[name="asset-csrf-token"]').content;
    const message = (text, error = false) => { $('asset-message').textContent = text; $('asset-message').className = error ? 'asset-error' : ''; };
    const run = fn => async event => {
        event?.preventDefault();
        const button = event?.submitter || (event?.currentTarget?.tagName === 'BUTTON' ? event.currentTarget : null);
        if (button) button.disabled = true;
        try { await fn(event); } catch (error) { message(error.message, true); }
        finally { if (button) button.disabled = false; }
    };
    async function api(url, method = 'GET', data) {
        const response = await fetch(url, {method, credentials: 'same-origin', cache: 'no-store',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
            ...(data === undefined ? {} : {body: JSON.stringify(data)})});
        const result = await response.json();
        if (!response.ok) throw new Error(`${response.status}: ${typeof result.detail === 'string' ? result.detail : JSON.stringify(result.detail || result)}`);
        return result;
    }
    function node(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
    function link(url, text) { const e = node('a', text); e.href = url; return e; }
    function button(text, action) { const e = node('button', text, 'btn btn-secondary btn-sm'); e.type = 'button'; e.addEventListener('click', run(action)); return e; }
    function table(container, headings, rows) {
        container.replaceChildren();
        if (!rows.length) { container.append(node('p', 'No records match.')); return; }
        const wrap = node('div', undefined, 'asset-scroll'), t = node('table'), head = node('thead'), hr = node('tr');
        headings.forEach(h => {const th = node('th', h); th.scope = 'col'; hr.append(th);}); head.append(hr); t.append(head);
        const body = node('tbody');
        rows.forEach(cells => { const tr = node('tr'); cells.forEach(value => { const td = node('td'); if (value instanceof Node) td.append(value); else td.textContent = value ?? 'Unknown'; tr.append(td); }); body.append(tr); });
        t.append(body); wrap.append(t); container.append(wrap);
    }
    function pager(container, result, reload) {
        const bar = node('div', undefined, 'asset-pager');
        const prev = button('Previous', () => reload(Math.max(0, result.offset - result.limit)));
        const next = button('Next', () => reload(result.offset + result.limit));
        prev.disabled = !result.offset; next.disabled = result.offset + result.limit >= result.total;
        bar.append(prev, node('span', `${result.total} records · ${result.total ? result.offset + 1 : 0}–${Math.min(result.offset + result.limit, result.total)}`), next);
        container.append(bar);
    }
    function formData(form) { return Object.fromEntries(new FormData(form)); }
    function assetInput(form) { const data = formData(form); data.criticality = Number(data.criticality); data.tags = data.tags.split(';').map(s => s.trim()).filter(Boolean); return data; }
    function fill(form, record) {
        form.reset();
        Object.entries(record).forEach(([key, value]) => {
            const field = form.elements.namedItem(key);
            if (!field) return;
            field.value = Array.isArray(value) ? value.join(';') : (key.endsWith('_at') && value ? value.replace(' ', 'T').slice(0, 16) : value ?? '');
        });
    }
    function explanation(row) {
        const wrapper = node('div');
        wrapper.append(node('strong', row.score === null ? `Unknown (known subtotal ${row.known_subtotal})` : `${row.score}/100`));
        if (row.urgent_kev) wrapper.append(node('p', 'Known exploited — review urgently', 'asset-warning'));
        const details = node('details'); details.append(node('summary', 'Why this priority?'));
        details.append(node('p', Object.entries(row.components).map(([k, v]) => `${k}: ${v === null ? 'unknown' : Number(v.toFixed(2))} points`).join(' · ')));
        details.append(node('p', `Inputs: ${JSON.stringify(row.inputs)}`));
        if (row.missing_inputs.length) details.append(node('p', `Missing: ${row.missing_inputs.join(', ')}`));
        if (row.freshness_warnings.length) details.append(node('p', `Freshness: ${row.freshness_warnings.join(', ')}`, 'asset-warning'));
        details.append(node('p', `EPSS: ${row.intelligence.epss_fetched_at || 'unknown'} · KEV successful sync: ${row.intelligence.kev_last_success || 'never'} · NVD sync: ${JSON.stringify(row.intelligence.nvd_latest_sync)}`));
        details.append(node('p', `Source: ${row.source} · Confidence: ${row.confidence}`), node('p', row.evidence_note), node('p', `Reason: ${row.reason || '—'} · Expiry: ${row.accepted_risk_expires_at || '—'}`));
        wrapper.append(details); return wrapper;
    }
    function state(row) { return row.risk_acceptance_expired ? 'Accepted risk expired → open for review' : row.status; }
    if ($('inventory-list')) {
        const filters = $('inventory-filters');
        async function load(offset = 0) {
            const query = new URLSearchParams(new FormData(filters)); query.set('offset', offset); query.set('limit', 50);
            const [data, status] = await Promise.all([api(`/api/assets?${query}`), root.dataset.monitoring === 'true' ? api('/api/asset-monitoring/status') : Promise.resolve({items: []})]);
            const states = new Map(status.items.map(r => [r.asset_id, r.state.availability])), container = $('inventory-list');
            const headings = ['Asset / external ID', 'Environment', 'Owner / team', 'Criticality', 'Exposure', 'Tags'];
            if (root.dataset.monitoring === 'true') headings.push('Availability');
            table(container, headings, data.items.map(a => {
                const row = [link(`/assets/${a.id}`, `${a.name} (${a.external_id})`), a.environment, a.owner_team, `${a.criticality}/4`, a.exposure, a.tags.join(', ')];
                if (root.dataset.monitoring === 'true') row.push(states.get(a.id) || 'disabled');
                return row;
            }));
            pager(container, data, load);
        }
        filters.addEventListener('submit', run(() => load()));
        $('asset-create')?.addEventListener('submit', run(async () => {const a = await api('/api/assets', 'POST', assetInput($('asset-create'))); location.assign(`/assets/${a.id}`);}));
        let previewToken = null;
        $('import-form')?.addEventListener('submit', run(async () => {
            previewToken = null; $('import-commit').hidden = true;
            const file = $('import-form').elements.file.files[0];
            if (file.size > 1048576) throw new Error('CSV exceeds the 1 MiB limit.');
            const preview = await api('/api/assets/import/preview', 'POST', {csv_content: await file.text()});
            previewToken = preview.preview_token;
            $('import-preview').textContent = JSON.stringify({summary: preview.summary, policy: preview.policy, items: preview.items}, null, 2);
            $('import-commit').hidden = false; message('Preview valid for 10 minutes. Review all changes before confirming.');
        }));
        $('import-form')?.elements.file.addEventListener('change', () => {previewToken = null; $('import-commit').hidden = true; $('import-preview').textContent = '';});
        $('import-commit')?.addEventListener('click', run(async () => {
            if (!previewToken) return;
            const result = await api('/api/assets/import/commit', 'POST', {preview_token: previewToken});
            previewToken = null; $('import-commit').hidden = true; message(`Import committed: ${JSON.stringify(result)}`); await load();
        }));
        run(() => load())();
    }
    if ($('priority-list')) {
        const filters = $('priority-filters');
        async function load(offset = 0) {
            const query = new URLSearchParams(new FormData(filters)); query.set('offset', offset);
            const data = await api(`/api/priorities?${query}`), container = $('priority-list');
            const headings = ['Asset', 'CVE', 'Priority / explanation', 'Effective assessment'];
            if (root.dataset.monitoring === 'true') headings.push('Availability (not risk)');
            table(container, headings, data.items.map(r => {
                const row = [link(`/assets/${r.asset_id}`, r.asset_name), link(`https://nvd.nist.gov/vuln/detail/${r.cve_id}`, r.cve_id), explanation(r), state(r)];
                if (root.dataset.monitoring === 'true') row.push(r.availability || 'disabled');
                return row;
            }));
            pager(container, data, load);
        }
        filters.addEventListener('submit', run(() => load())); run(() => load())();
    }
    if ($('asset-data')) {
        const asset = JSON.parse($('asset-data').textContent), base = `/api/assets/${asset.id}`;
        const writable = root.dataset.analyst === 'true' && !asset.is_archived;
        let softwareEdit = null, assessmentEdit = null;
        if ($('asset-edit')) fill($('asset-edit'), asset);
        $('asset-edit')?.addEventListener('submit', run(async () => {await api(base, 'PATCH', {...assetInput($('asset-edit')), expected_version: asset.row_version}); location.reload();}));
        $('asset-archive')?.addEventListener('click', run(async () => {
            if (!confirm(`${asset.is_archived ? 'Restore' : 'Archive'} this asset? History is preserved.`)) return;
            await api(`${base}/archive`, 'POST', {expected_version: asset.row_version, archived: !asset.is_archived}); location.reload();
        }));
        document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => $(b.dataset.close).close()));
        function openSoftware(record = null) { softwareEdit = record; fill($('software-form'), record || {}); $('software-dialog').showModal(); }
        function openAssessment(record = null) { assessmentEdit = record; fill($('assessment-form'), record || {}); $('assessment-form').elements.cve_id.disabled = !!record; $('assessment-dialog').showModal(); }
        $('software-add')?.addEventListener('click', () => openSoftware());
        $('assessment-add')?.addEventListener('click', () => openAssessment());
        async function loadSoftware(offset = 0) {
            const data = await api(`${base}/software?offset=${offset}`), container = $('software-list');
            table(container, ['ID', 'Vendor / product', 'Version / CPE', 'Observation', 'Actions'], data.items.map(s => {
                const actions = node('div');
                if (writable) actions.append(button('Edit', () => openSoftware(s)), button('Delete', async () => {if (!confirm('Delete this software observation? Linked CVEs must be detached first.')) return; await api(`${base}/software/${s.id}`, 'DELETE', {expected_version: s.row_version}); await loadSoftware();}));
                return [s.id, `${s.vendor} / ${s.product}`, `${s.version} / ${s.cpe || '—'}`, `${s.source} · ${s.observed_at}`, actions];
            })); pager(container, data, loadSoftware);
        }
        async function loadAssessments(offset = 0) {
            const data = await api(`${base}/cves?offset=${offset}`), container = $('assessment-list');
            table(container, ['CVE / software', 'Priority / evidence', 'Assessment', 'Actions'], data.items.map(r => {
                const actions = node('div'); if (writable) actions.append(button('Assess / edit', () => openAssessment(r)));
                return [`${r.cve_id} / software ${r.software_id || '—'}`, explanation(r), state(r), actions];
            })); pager(container, data, loadAssessments);
        }
        async function loadEvents(offset = 0) {
            const data = await api(`${base}/events?offset=${offset}`), container = $('assessment-events');
            table(container, ['Time / actor', 'Change'], data.items.map(e => {
                const details = node('details'); details.append(node('summary', `Assessment #${e.assessment_id} · audit #${e.audit_event_id}`), node('pre', JSON.stringify({before: e.before_json ? JSON.parse(e.before_json) : null, after: JSON.parse(e.after_json)}, null, 2)));
                return [`${e.created_at} UTC · ${e.actor_name}`, details];
            }));
            const bar = node('div', undefined, 'asset-pager'), prev = button('Previous history', () => loadEvents(Math.max(0, offset - 100))), next = button('Next history', () => loadEvents(offset + 100));
            prev.disabled = offset === 0; next.disabled = data.items.length < 100; bar.append(prev, next); container.append(bar);
        }
        $('software-form')?.addEventListener('submit', run(async () => {
            const data = formData($('software-form')); data.cpe ||= null; data.observed_at = data.observed_at ? `${data.observed_at}:00Z` : null;
            if (softwareEdit) data.expected_version = softwareEdit.row_version;
            await api(`${base}/software${softwareEdit ? `/${softwareEdit.id}` : ''}`, softwareEdit ? 'PATCH' : 'POST', data);
            $('software-dialog').close(); message('Software saved.'); await loadSoftware();
        }));
        $('assessment-form')?.addEventListener('submit', run(async () => {
            const data = formData($('assessment-form')); data.software_id = data.software_id ? Number(data.software_id) : null;
            data.accepted_risk_expires_at = data.status === 'accepted_risk' && data.accepted_risk_expires_at ? `${data.accepted_risk_expires_at}:00Z` : null;
            if (assessmentEdit) data.expected_version = assessmentEdit.row_version;
            await api(assessmentEdit ? `/api/asset-assessments/${assessmentEdit.id}` : `${base}/cves`, assessmentEdit ? 'PATCH' : 'POST', data);
            $('assessment-dialog').close(); message('Assessment saved; history preserved.'); await Promise.all([loadAssessments(), loadEvents()]);
        }));
        run(() => Promise.all([loadSoftware(), loadAssessments(), loadEvents()]))();
    }
})();
