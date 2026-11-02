/* Private case UI. Only explicit POST actions execute/capture investigations. */
(() => {
    'use strict';
    const root = document.getElementById('case-workspace');
    if (!root) return;
    const $ = id => document.getElementById(id);
    const csrf = document.querySelector('meta[name="case-csrf-token"]').content;
    let currentCase = $('case-data') ? JSON.parse($('case-data').textContent) : null;
    let captured = $('captured-data') ? JSON.parse($('captured-data').textContent) : null;
    function message(text) { $('case-message').textContent = text; }
    function node(tag, text) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e; }
    function link(url, text) { const e = node('a', text); e.href = url; return e; }
    function date(value) { return value ? new Date(value).toLocaleString() : '—'; }
    async function api(path, method = 'GET', body) {
        const r = await fetch(path, {method, credentials: 'same-origin', cache: 'no-store',
            headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
            ...(body === undefined ? {} : {body: JSON.stringify(body)})});
        const data = await r.json();
        if (!r.ok) throw new Error(`${r.status}: ${typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail || data)}`);
        return data;
    }
    function lockForms() {
        if (!currentCase) return;
        root.querySelectorAll('[data-case-edit] input, [data-case-edit] textarea, [data-case-edit] select, [data-case-edit] button')
            .forEach(e => { e.disabled = currentCase.is_archived || currentCase.status === 'closed'; });
        $('case-transition').querySelectorAll('input,textarea,select,button').forEach(e => { e.disabled = !!currentCase.is_archived; });
    }
    const wrap = fn => async event => {
        event?.preventDefault();
        const button = event?.submitter || (event?.currentTarget?.tagName === 'BUTTON' ? event.currentTarget : null);
        if (button) button.disabled = true;
        try { await fn(event); } catch (error) { message(error.message); }
        finally { if (button) button.disabled = false; lockForms(); }
    };
    function button(text, action) { const b = node('button', text); b.type = 'button'; b.className = 'btn btn-secondary'; b.addEventListener('click', wrap(action)); return b; }
    function table(container, headings, rows) {
        container.replaceChildren();
        if (!rows.length) { container.append(node('p', 'No saved records.')); return; }
        const scroll = node('div'); scroll.className = 'asset-scroll';
        const t = node('table'), head = node('thead'), h = node('tr'), body = node('tbody');
        headings.forEach(text => { const e = node('th', text); e.scope = 'col'; h.append(e); });
        head.append(h); t.append(head);
        rows.forEach(values => { const tr = node('tr'); values.forEach(v => { const td = node('td'); if (v instanceof Node) td.append(v); else td.textContent = v ?? '—'; tr.append(td); }); body.append(tr); });
        t.append(body); scroll.append(t); container.append(scroll);
    }
    function pager(container, data, load) {
        const bar = node('div'); bar.className = 'asset-pager';
        bar.append(button('Newest', () => load(null)));
        const older = button('Older records', () => load(data.next_before_id)); older.disabled = !data.next_before_id;
        bar.append(older); container.append(bar);
    }
    function details(title, value) { const d = node('details'); d.append(node('summary', title), node('pre', JSON.stringify(value, null, 2))); return d; }
    function formBody(form) { return Object.fromEntries(new FormData(form)); }
    function caseBody(form) { const d = formBody(form); d.assignee_user_id = d.assignee_user_id ? Number(d.assignee_user_id) : null; return d; }
    async function assignees() {
        const data = await api('/api/cases/assignees');
        root.querySelectorAll('[data-assignees]').forEach(select => {
            data.items.forEach(user => { const option = node('option', `${user.username} (${user.role})`); option.value = user.id; select.append(option); });
        });
    }
    async function lookupHistory() {
        if (!$('lookup-history')) return;
        const rows = await api('/api/investigate/history?limit=25');
        table($('lookup-history'), ['Indicator', 'Attribution / evidence', 'Observed verdict', 'Action'], rows.map(row => [
            row.indicator,
            `${row.actor_name || 'Unknown actor'} · ${row.snapshot_id ? `Captured snapshot #${row.snapshot_id}` : 'Legacy/uncaptured summary only — no preserved dossier'}`,
            `${row.verdict} / ${date(row.created_at)}`,
            link(`/investigate?ioc=${encodeURIComponent(row.indicator)}`, 'Prepare new lookup (no execution yet)')
        ]));
    }
    async function list(before = null) {
        const query = new URLSearchParams(new FormData($('case-filters')));
        for (const key of [...query.keys()]) if (!query.get(key)) query.delete(key);
        if (before) query.set('before_id', before);
        const data = await api(`/api/cases?${query}`);
        table($('case-list'), ['Case', 'State / severity', 'Assignee', 'Last changed'], data.items.map(c => [
            link(`/cases/${c.id}`, `${c.reference} — ${c.title}`), `${c.status} / ${c.severity}${c.is_archived ? ' / archived' : ''}`,
            c.assignee_name || 'Unassigned / deleted account', date(c.updated_at)]));
        pager($('case-list'), data, list); $('case-limits').textContent = JSON.stringify(data.limits, null, 2);
    }
    async function collection(kind, before = null) {
        const query = before ? `?before_id=${before}` : '';
        const data = await api(`/api/cases/${currentCase.id}/${kind}${query}`), container = $(`case-${kind}`);
        if (kind === 'notes') table(container, ['Note', 'Actor / captured time', 'Plain text'], data.items.map(n => [
            `#${n.id}${n.supersedes_note_id ? ` corrects #${n.supersedes_note_id}` : ''}`, `${n.actor_name} / ${date(n.created_at)}`, node('pre', n.body)]));
        if (kind === 'events') table(container, ['Event', 'Actor / time', 'Change'], data.items.map(e => [e.kind, `${e.actor_name} / ${date(e.created_at)}`, details('View change', e.payload)]));
        if (kind === 'evidence') table(container, ['Snapshot / capture time', 'Observed result / integrity', 'Actions'], data.items.map(e => {
            const s = e.snapshot, dossier = s.evidence?.dossier;
            const content = node('div');
            content.append(node('p', `${dossier?.indicator || s.indicator} · ${dossier?.verdict || 'unknown'} · ${s.evidence?.privacy_mode || 'unknown mode'}`),
                node('strong', s.integrity_valid ? 'Digest matches captured evidence' : s.warning), details('Full preserved evidence and digest', s));
            const actions = node('div');
            actions.append(link(`/investigate?snapshot_id=${s.id}`, 'Open saved result'), document.createTextNode(' · '),
                link(`/investigate?ioc=${encodeURIComponent(s.indicator)}`, 'Prepare new investigation (does not run yet)'));
            return [`#${s.id} / ${date(s.captured_at)} / ${s.actor_name}`, content, actions];
        }));
        if (kind === 'references') table(container, ['Context', 'Preserved label', 'Current reference'], data.items.map(r => {
            const urls = {asset: `/assets/${r.target_id}`, cve: `/api/cve-intel/${r.target_id}`, actor: `/api/threat-actors/${r.target_id}`, rule: `/api/detection-rules/${r.target_id}`};
            return [`${r.kind} / ${r.target_id}`, r.label, r.available ? link(urls[r.kind], 'Current details (not frozen)') : 'Unavailable / deleted / feature disabled'];
        }));
        pager(container, data, id => collection(kind, id));
    }
    async function loadCase() {
        currentCase = await api(`/api/cases/${currentCase.id}`);
        const c = currentCase;
        $('case-summary').replaceChildren(node('h2', c.title), node('pre', c.summary),
            node('p', `${c.status} / ${c.severity} · Assignee: ${c.assignee_name || 'Unassigned / deleted account'} · Version ${c.row_version}${c.is_archived ? ' · ARCHIVED' : ''}`),
            node('p', c.conclusion ? `Conclusion: ${c.conclusion} · Closed ${date(c.closed_at)}` : 'No human conclusion recorded.'), node('pre', c.closure_reason || ''));
        const f = $('case-edit'); for (const k of ['title', 'summary', 'severity', 'assignee_user_id']) f.elements[k].value = c[k] ?? '';
        lockForms();
        await Promise.all(['evidence', 'notes', 'events', 'references'].map(k => collection(k)));
    }
    function bind(id, fn) { $(id)?.addEventListener('submit', wrap(event => fn(event.currentTarget))); }
    bind('case-filters', () => list());
    bind('case-create', async f => { const c = await api('/api/cases', 'POST', caseBody(f)); location.href = `/cases/${c.id}`; });
    bind('case-edit', async f => { await api(`/api/cases/${currentCase.id}`, 'PATCH', {...caseBody(f), expected_version: currentCase.row_version}); message('Changes saved.'); await loadCase(); });
    bind('case-transition', async f => {
        const d = formBody(f);
        await api(`/api/cases/${currentCase.id}/transition`, 'POST', {...d, conclusion: d.status === 'closed' ? d.conclusion || null : null, expected_version: currentCase.row_version});
        f.reset(); message('Status updated; prior closure history retained.'); await loadCase();
    });
    bind('case-note', async f => { const d = formBody(f); await api(`/api/cases/${currentCase.id}/notes`, 'POST', {...d,
        supersedes_note_id: d.supersedes_note_id ? Number(d.supersedes_note_id) : null, expected_version: currentCase.row_version}); f.reset(); message('Note appended.'); await loadCase(); });
    bind('case-attach', async f => { await api(`/api/cases/${currentCase.id}/evidence`, 'POST', {snapshot_id: Number(f.elements.snapshot_id.value), expected_version: currentCase.row_version}); message('Evidence attached or already present.'); await loadCase(); });
    bind('case-reference', async f => { await api(`/api/cases/${currentCase.id}/references`, 'POST', {...formBody(f), expected_version: currentCase.row_version}); f.reset(); message('Context reference saved.'); await loadCase(); });
    bind('case-archive', async f => { const d = formBody(f); await api(`/api/cases/${currentCase.id}/archive`, 'POST', {...d, archived: d.archived === 'true', expected_version: currentCase.row_version}); message('Archive state saved; content retained.'); await loadCase(); });
    bind('case-compare', async f => {
        const [older, newer] = await Promise.all(['older', 'newer'].map(k => api(`/api/investigations/${Number(f.elements[k].value)}`)));
        const before = older.evidence?.dossier || {}, after = newer.evidence?.dossier || {}, changes = {};
        for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
            if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) changes[key] = {before: before[key] ?? null, after: after[key] ?? null};
        }
        $('case-comparison').textContent = JSON.stringify({older: {id: older.id, captured_at: older.captured_at, integrity_valid: older.integrity_valid},
            newer: {id: newer.id, captured_at: newer.captured_at, integrity_valid: newer.integrity_valid}, changes,
            notice: 'Only saved dossiers compared; no enrichment run. Different privacy modes/source availability can explain differences.'}, null, 2);
    });
    $('case-refresh')?.addEventListener('click', wrap(loadCase));
    async function showCaptured(s, matches = null) {
        captured = s; $('captured-result').hidden = false;
        const d = s.evidence?.dossier;
        $('captured-summary').replaceChildren(node('h3', `Snapshot #${s.id}: ${d?.indicator || s.indicator}`),
            node('p', `${d?.verdict || 'unknown'} · ${s.evidence?.privacy_mode || 'unknown mode'} · Captured ${date(s.captured_at)}`),
            node('strong', s.integrity_valid ? 'Digest matches captured evidence.' : s.warning));
        $('captured-dossier').textContent = JSON.stringify(s, null, 2);
        if (matches === null) matches = (await api(`/api/cases?indicator=${encodeURIComponent(s.indicator)}&limit=10`)).items.filter(c => c.status !== 'closed');
        $('captured-matches').replaceChildren(node('p', 'Matching open cases are suggestions, never automatically merged:'));
        if (!matches.length) $('captured-matches').append(node('p', 'No matching open cases.'));
        matches.forEach(c => { $('captured-matches').append(link(`/cases/${c.id}`, `${c.reference} — ${c.title}`), node('br')); });
        $('captured-create-case').elements.title.value = `Investigate ${s.indicator}`.slice(0, 200);
        for (const id of ['captured-create-case', 'captured-attach']) $(id).querySelectorAll('button').forEach(b => { b.disabled = !s.integrity_valid; });
    }
    bind('investigation-capture', async f => {
        const result = await api('/api/investigations', 'POST', {indicator: f.elements.indicator.value, local_only: f.elements.local_only.checked});
        history.replaceState(null, '', `/investigate?snapshot_id=${result.snapshot.id}`);
        message('Result captured. Refreshing this page will not run another lookup.');
        await showCaptured(result.snapshot, result.matching_cases); await lookupHistory();
    });
    bind('captured-create-case', async f => { if (!captured?.integrity_valid) throw new Error('Capture valid evidence first.');
        const c = await api('/api/cases', 'POST', {...caseBody(f), snapshot_id: captured.id}); location.href = `/cases/${c.id}`; });
    bind('captured-attach', async f => { if (!captured?.integrity_valid) throw new Error('Capture valid evidence first.');
        const c = await api(`/api/cases/${Number(f.elements.case_id.value)}`);
        await api(`/api/cases/${c.id}/evidence`, 'POST', {snapshot_id: captured.id, expected_version: c.row_version}); location.href = `/cases/${c.id}`; });
    wrap(async () => { await assignees(); if ($('case-list')) await list(); if (currentCase) await loadCase(); if (captured) await showCaptured(captured); await lookupHistory(); })();
})();
