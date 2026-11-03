/* Authoring controls never replace the public pointer without explicit publication. */
(() => {
    'use strict';
    const root = document.getElementById('rule-workbench'); if (!root) return;
    const $ = id => document.getElementById(id), csrf = document.querySelector('meta[name="rule-csrf-token"]').content;
    let current = null;
    const node = (tag, text) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; return e; };
    const message = text => { $('rule-message').textContent = text; };
    async function api(path, method = 'GET', body) {
        const r = await fetch(path, {method, credentials: 'same-origin', cache: 'no-store', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
            ...(body === undefined ? {} : {body: JSON.stringify(body)})});
        const data = await r.json();
        if (!r.ok) throw new Error(`${r.status}: ${typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail || data)}`);
        return data;
    }
    function controls() {
        if (!current) return;
        const state = current.working.state, frozen = ['in_review', 'approved'].includes(state), archived = current.is_archived;
        $('rule-validate').disabled = archived || !['draft', 'legacy_unreviewed', 'rejected'].includes(state);
        $('rule-submit').disabled = archived || state !== 'draft';
        $('rule-withdraw').disabled = archived || !frozen;
        $('rule-editor').querySelectorAll('input,select,textarea,button').forEach(e => { e.disabled = archived || frozen; });
        if ($('rule-review')) $('rule-review').querySelectorAll('input,textarea,select,button').forEach(e => {
            e.disabled = archived || state !== 'in_review' || !root.dataset.userId || Number(root.dataset.userId) === current.working.author_user_id;
        });
        if ($('rule-publish')) $('rule-publish').disabled = archived || state !== 'approved' || !root.dataset.userId;
    }
    const wrap = fn => async event => { event?.preventDefault(); const b = event?.submitter || (event?.currentTarget?.tagName === 'BUTTON' ? event.currentTarget : null);
        if (b) b.disabled = true;
        try { await fn(event); } catch (error) { message(error.message); } finally { if (b) b.disabled = false; controls(); }
    };
    const button = (text, fn) => { const b = node('button', text); b.type = 'button'; b.className = 'btn btn-secondary'; b.addEventListener('click', wrap(fn)); return b; };
    function table(container, headings, rows) {
        container.replaceChildren(); if (!rows.length) { container.append(node('p', 'No saved records.')); return; }
        const scroll = node('div'); scroll.className = 'asset-scroll'; const t = node('table'), head = node('thead'), h = node('tr'), body = node('tbody');
        headings.forEach(text => { const th = node('th', text); th.scope = 'col'; h.append(th); }); head.append(h); t.append(head);
        rows.forEach(values => { const tr = node('tr'); values.forEach(v => { const td = node('td'); if (v instanceof Node) td.append(v); else td.textContent = v ?? '—'; tr.append(td); }); body.append(tr); });
        t.append(body); scroll.append(t); container.append(scroll);
    }
    function pager(container, data, load) { container.append(button('Newest', () => load(null))); const older = button('Older', () => load(data.next_before_id)); older.disabled = !data.next_before_id; container.append(older); }
    async function list(before = null) {
        const data = await api(`/api/rule-lifecycle/rules?limit=10&archived=${$('rules-archived').checked}${before ? `&before_id=${before}` : ''}`);
        table($('rule-list'), ['Identity / working title', 'State / revision', 'Published pointer', 'Action'], data.items.map(r => [
            `#${r.id} ${r.working.snapshot.title}`, `${r.working.state} / r${r.working.revision_number}`, r.published_revision_id || 'Private — never published', button('Open', () => select(r.id))]));
        pager($('rule-list'), data, list);
    }
    function details(title, value) { const d = node('details'); d.append(node('summary', title), node('pre', JSON.stringify(value, null, 2))); return d; }
    async function history(before = null) {
        const data = await api(`/api/detection-rules/${current.id}/revisions${before ? `?before_id=${before}` : ''}`);
        table($('rule-history'), ['Revision / parent', 'Author / state', 'Source and report'], data.items.map(r => [
            `r${r.revision_number} / ID ${r.id} / parent ${r.parent_revision_id || 'none'}`, `${r.author_name} / ${r.state}${r.integrity_valid ? '' : ' / INTEGRITY WARNING'}`, details('Inspect preserved snapshot', r)]));
        pager($('rule-history'), data, history);
    }
    async function select(id) {
        current = await api(`/api/detection-rules/${id}/working`);
        window.history.replaceState(null, '', `/rule-workbench/${id}`);
        $('rule-current').hidden = false; $('rule-history-panel').hidden = false;
        const r = current.working;
        $('rule-state').replaceChildren(node('h3', `#${id} ${r.snapshot.title}`), node('p', `${r.state} · r${r.revision_number} / revision ID ${r.id} · Version ${current.row_version}${current.is_archived ? ' · ARCHIVED' : ''}`),
            node('strong', r.integrity_valid ? 'Stored snapshot digest matches.' : 'INTEGRITY WARNING: content changed.'), node('p', `SHA-256: ${r.sha256}`));
        $('rule-validation').replaceChildren(r.validation ? details(`Latest validation: ${r.validation.status}`, r.validation.report) : node('p', 'No validation report for this revision.'));
        $('rule-reviews').replaceChildren(details('Independent review history', r.reviews));
        const f = $('rule-editor'); for (const [key, value] of Object.entries(r.snapshot)) if (f.elements[key]) f.elements[key].value = value ?? '';
        $('rule-editor-title').textContent = `Create the next draft of identity #${id} (never overwrites r${r.revision_number})`;
        const exportLink = node('a', 'Export private revision/report history'); exportLink.href = `/api/detection-rules/${id}/revisions/export`;
        $('rule-export-link').replaceChildren(exportLink); controls(); await history();
    }
    const actionBody = () => ({expected_version: current.row_version});
    async function action(name, body = {}) {
        if (!current) throw new Error('Open a rule first.');
        const id = current.id;
        const result = await api(`/api/detection-rules/${id}/revisions/${current.working.id}/${name}`, 'POST', {...actionBody(), ...body});
        message(name === 'validate' ? `Validation: ${result.report.status} (${result.report.reason}). Syntax is not efficacy.` : `${name} recorded.`);
        await select(id); await list();
    }
    $('rule-refresh').addEventListener('click', wrap(async () => { await list(); if (current) await select(current.id); }));
    $('rules-archived').addEventListener('change', wrap(() => list()));
    $('rule-new').addEventListener('click', () => { current = null; $('rule-editor').reset(); $('rule-editor').querySelectorAll('input,textarea,select,button').forEach(e => { e.disabled = false; });
        $('rule-current').hidden = true; $('rule-history-panel').hidden = true; $('rule-editor-title').textContent = 'Create a new private draft identity'; window.history.replaceState(null, '', '/rule-workbench'); });
    $('rule-editor').addEventListener('submit', wrap(async () => {
        const body = Object.fromEntries(new FormData($('rule-editor')));
        const result = await api(current ? `/api/detection-rules/${current.id}/revisions` : '/api/rule-lifecycle/rules', 'POST', current ?
            {...body, expected_version: current.row_version, expected_parent_revision_id: current.working.id} : body);
        message('Private draft saved. The public revision has not changed.'); await select(result.id); await list();
    }));
    $('rule-validate').addEventListener('click', wrap(() => action('validate')));
    $('rule-submit').addEventListener('click', wrap(() => action('submit')));
    $('rule-withdraw').addEventListener('click', wrap(() => action('withdraw', {reason: 'Withdraw saved candidate to a new draft'})));
    $('rule-review')?.addEventListener('submit', wrap(() => action('review', Object.fromEntries(new FormData($('rule-review'))))));
    $('rule-publish')?.addEventListener('click', wrap(() => action('publish')));
    $('rule-archive')?.addEventListener('submit', wrap(async () => { const d = Object.fromEntries(new FormData($('rule-archive')));
        await api(`/api/detection-rules/${current.id}/archive`, 'POST', {...actionBody(), reason: d.reason, archived: d.archived === 'true'});
        message('Archive state saved; history retained.'); await select(current.id); await list();
    }));
    $('rule-diff').addEventListener('submit', wrap(async () => { const d = Object.fromEntries(new FormData($('rule-diff')));
        const result = await api(`/api/detection-rules/${current.id}/diff?older=${Number(d.older)}&newer=${Number(d.newer)}`);
        $('rule-diff-output').textContent = (result.older_integrity_valid && result.newer_integrity_valid ? '' : 'INTEGRITY WARNING\n') + (result.diff || 'No content difference.');
    }));
    $('rule-rollback').addEventListener('submit', wrap(async () => { const d = Object.fromEntries(new FormData($('rule-rollback')));
        await api(`/api/detection-rules/${current.id}/rollback`, 'POST', {...actionBody(), reason: d.reason, source_revision_id: Number(d.source_revision_id)});
        message('Rollback draft created; validation, independent review and publication are still required.'); await select(current.id); await list();
    }));
    wrap(async () => { await list(); if (root.dataset.ruleId) await select(Number(root.dataset.ruleId)); })();
})();
