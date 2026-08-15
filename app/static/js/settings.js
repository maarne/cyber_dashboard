/* =============================================================
   app/static/js/settings.js — Settings Page Client-Side Logic
   =============================================================

   This file handles all the interactive behavior on the
   Settings page:
   - Show/hide the webhook form
   - Submit new or edited webhooks via fetch() POST/PUT
   - Delete webhooks with confirmation modal
   - Toggle webhooks active/inactive
   - Send test notifications

   JAVASCRIPT CONCEPTS FOR BEGINNERS:
   -----------------------------------
   - fetch(): Make HTTP requests (GET, POST, PUT, DELETE)
   - async/await: Handle asynchronous operations cleanly
   - FormData: Collect form field values
   - Event delegation: Handle events on dynamically created elements
   - JSON.stringify(): Convert a JavaScript object to a JSON string
   ============================================================= */


// =============================================================
// GLOBAL STATE
// =============================================================
// We track which webhook is being edited (if any) and which
// is being deleted (for the confirmation modal).
// =============================================================

// "let" declares a variable that can be reassigned later.
// "null" means "no value" — we start with no selection.
let editingWebhookId = null;
let deletingWebhookId = null;


// =============================================================
// INITIALIZATION
// =============================================================
// DOMContentLoaded fires when the HTML is fully loaded and parsed.
// We use it to set up all our event listeners.
// =============================================================

document.addEventListener('DOMContentLoaded', function() {

    // --- "Add Webhook" button ---
    // When clicked, show the form in "create" mode.
    var addBtn = document.getElementById('add-webhook-btn');
    if (addBtn) {
        addBtn.addEventListener('click', function() {
            if (typeof isUserAuthenticated === 'function' && !isUserAuthenticated()) {
                openLoginModal('Log in as administrator to add webhooks.');
                return;
            }
            showForm('add');
        });
    }

    // --- "Cancel" button in the form ---
    var cancelBtn = document.getElementById('form-cancel-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', hideForm);
    }

    // --- Form submission ---
    // Intercept the form's submit event so we can send data
    // via fetch() instead of a traditional page reload.
    var form = document.getElementById('webhook-form');
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }

    // --- Delete modal buttons ---
    var confirmDeleteBtn = document.getElementById('confirm-delete-btn');
    if (confirmDeleteBtn) {
        confirmDeleteBtn.addEventListener('click', handleConfirmDelete);
    }

    var cancelDeleteBtn = document.getElementById('cancel-delete-btn');
    if (cancelDeleteBtn) {
        cancelDeleteBtn.addEventListener('click', hideDeleteModal);
    }

    // --- Event Delegation ---
    // Instead of adding listeners to each button individually,
    // we listen on the parent container and check which button
    // was clicked. This works for buttons that exist now AND
    // any buttons added later (after AJAX creates new cards).
    //
    // JAVASCRIPT CONCEPT — Event Delegation:
    //   When a child element is clicked, the event "bubbles up"
    //   to parent elements. We catch it at the parent level and
    //   check event.target to find which specific button was clicked.
    var webhooksList = document.getElementById('webhooks-list');
    if (webhooksList) {
        webhooksList.addEventListener('click', function(event) {
            var target = event.target;
            var button = target.closest('button');
            if (!button) return;

            if (typeof isUserAuthenticated === 'function' && !isUserAuthenticated()) {
                openLoginModal('Log in as administrator to manage webhooks.');
                return;
            }

            var webhookId = button.dataset.webhookId || button.dataset.id;
            var webhookName = button.dataset.name || button.dataset.webhookName;

            if (button.classList.contains('btn-test')) {
                handleTestWebhook(webhookId);
            } else if (button.classList.contains('btn-edit')) {
                handleEditWebhook(button);
            } else if (button.classList.contains('btn-delete')) {
                showDeleteModal(webhookId, webhookName);
            }
        });

        webhooksList.addEventListener('change', function(event) {
            if (event.target.classList.contains('toggle-input')) {
                if (typeof isUserAuthenticated === 'function' && !isUserAuthenticated()) {
                    event.target.checked = !event.target.checked;
                    openLoginModal('Log in as administrator to toggle webhooks.');
                    return;
                }
                var webhookId = event.target.dataset.webhookId || event.target.dataset.id;
                handleToggleWebhook(webhookId);
            }
        });
    }

    // --- Schedule Toggle ---
    var scheduleToggle = document.getElementById('schedule-toggle');
    if (scheduleToggle) {
        scheduleToggle.addEventListener('change', function(e) {
            if (typeof isUserAuthenticated === 'function' && !isUserAuthenticated()) {
                e.preventDefault();
                scheduleToggle.checked = !scheduleToggle.checked;
                openLoginModal('Log in as administrator to change auto-refresh schedules.');
                return;
            }
            saveScheduleSettings();
        });
    }

    // --- Schedule Interval Radio Buttons ---
    var intervalRadios = document.querySelectorAll('input[name="schedule-interval"]');
    intervalRadios.forEach(function(radio) {
        radio.addEventListener('change', function(e) {
            if (typeof isUserAuthenticated === 'function' && !isUserAuthenticated()) {
                e.preventDefault();
                openLoginModal('Log in as administrator to change refresh intervals.');
                return;
            }
            document.querySelectorAll('.interval-option').forEach(function(opt) {
                opt.classList.remove('active');
            });
            radio.closest('.interval-option').classList.add('active');

            saveScheduleSettings();
        });
    });

    // --- RSS Feed Form ---
    var addFeedForm = document.getElementById('add-feed-form');
    if (addFeedForm) {
        addFeedForm.addEventListener('submit', handleAddFeed);
    }

    // --- RSS Feed List Event Delegation (Toggle & Delete) ---
    var rssFeedsList = document.getElementById('rss-feeds-list');
    if (rssFeedsList) {
        rssFeedsList.addEventListener('click', function(event) {
            var button = event.target.closest('button');
            if (button && button.classList.contains('feed-delete-btn')) {
                handleDeleteFeed(button.dataset.feedId, button.dataset.feedName);
            }
        });

        rssFeedsList.addEventListener('change', function(event) {
            if (event.target.classList.contains('feed-toggle')) {
                handleToggleFeed(event.target.dataset.feedId);
            }
        });
    }
});


// =============================================================
// FORM: SHOW / HIDE
// =============================================================

function showForm(mode, data) {
    /**
     * Show the webhook form in either "add" or "edit" mode.
     */
    var container = document.getElementById('webhook-form-card') || document.getElementById('webhook-form-container');
    if (!container) return;

    var formTitle = document.getElementById('form-title');
    var submitBtn = document.getElementById('form-submit-btn');
    var idInput = document.getElementById('webhook-id');
    var nameInput = document.getElementById('webhook-name');
    var platformInput = document.getElementById('webhook-platform');
    var urlInput = document.getElementById('webhook-url');
    var critInput = document.getElementById('notify-critical');
    var highInput = document.getElementById('notify-high');
    var cisaInput = document.getElementById('notify-cisa');

    if (mode === 'edit' && data) {
        // Populate form with existing data for editing
        if (formTitle) formTitle.textContent = 'Edit Webhook';
        if (submitBtn) submitBtn.textContent = '💾 Update Webhook';
        editingWebhookId = data.id;

        if (idInput) idInput.value = data.id || '';
        if (nameInput) nameInput.value = data.name || '';
        if (platformInput) platformInput.value = data.platform || 'slack';
        if (urlInput) urlInput.value = data.url || '';
        if (critInput) critInput.checked = data.critical === '1' || data.critical === 'True' || data.critical === true;
        if (highInput) highInput.checked = data.high === '1' || data.high === 'True' || data.high === true;
        if (cisaInput) cisaInput.checked = data.cisa === '1' || data.cisa === 'True' || data.cisa === true;
    } else {
        // Reset form for new webhook
        if (formTitle) formTitle.textContent = 'Add New Webhook';
        if (submitBtn) submitBtn.textContent = '💾 Save Webhook';
        editingWebhookId = null;

        var form = document.getElementById('webhook-form');
        if (form) form.reset();
        if (idInput) idInput.value = '';
    }

    container.style.display = 'block';

    // Smooth scroll to the form
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}


function hideForm() {
    /** Hide the webhook form and reset state. */
    var container = document.getElementById('webhook-form-card') || document.getElementById('webhook-form-container');
    if (container) container.style.display = 'none';
    editingWebhookId = null;
}


// =============================================================
// FORM: SUBMIT (Create or Update)
// =============================================================

async function handleFormSubmit(event) {
    /**
     * Handle form submission — either create or update a webhook.
     *
     * JAVASCRIPT CONCEPT — event.preventDefault():
     *   By default, submitting a form causes a full page reload.
     *   preventDefault() stops that behavior so we can handle
     *   the submission with JavaScript (fetch) instead.
     *
     * JAVASCRIPT CONCEPT — async/await:
     *   "async" before a function means it can use "await" inside.
     *   "await" pauses execution until a Promise resolves (e.g.,
     *   waiting for a network request to complete).
     */
    event.preventDefault();

    // Collect form values into a JavaScript object.
    // This object will be converted to JSON and sent to the server.
    var webhookData = {
        name: document.getElementById('webhook-name').value,
        platform: document.getElementById('webhook-platform').value,
        webhook_url: document.getElementById('webhook-url').value,
        is_active: true,
        notify_critical_cves: document.getElementById('notify-critical').checked,
        notify_high_cves: document.getElementById('notify-high').checked,
        notify_cisa_exploits: document.getElementById('notify-cisa').checked,
    };

    // Determine the URL and HTTP method based on whether
    // we're creating a new webhook or updating an existing one.
    var url = '/api/webhooks';
    var method = 'POST';

    if (editingWebhookId) {
        url = '/api/webhooks/' + editingWebhookId;
        method = 'PUT';
    }

    try {
        // fetch() sends the HTTP request.
        // JSON.stringify() converts our JavaScript object to a
        // JSON string like: {"name":"My Hook","platform":"slack",...}
        var response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(webhookData),
        });

        if (response.ok) {
            showToast(
                editingWebhookId ? 'Webhook updated!' : 'Webhook created!',
                'success'
            );
            hideForm();
            // Reload the page to show the updated list.
            // In a more advanced app, we'd update the DOM directly.
            window.location.reload();
        } else {
            var errorData = await response.json();
            showToast('Error: ' + (errorData.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


// =============================================================
// EDIT WEBHOOK
// =============================================================

function handleEditWebhook(button) {
    /**
     * Populate the form with data from the clicked webhook card.
     */
    showForm('edit', {
        id: button.dataset.webhookId || button.dataset.id,
        name: button.dataset.name || '',
        platform: button.dataset.platform || 'slack',
        url: button.dataset.url || '',
        critical: button.dataset.critical,
        high: button.dataset.high,
        cisa: button.dataset.cisa,
    });
}


// =============================================================
// DELETE WEBHOOK (with confirmation modal)
// =============================================================

function showDeleteModal(webhookId, webhookName) {
    /** Show the delete confirmation modal. */
    deletingWebhookId = webhookId;
    document.getElementById('delete-webhook-name').textContent = webhookName;
    document.getElementById('delete-modal').style.display = 'flex';
}


function hideDeleteModal() {
    /** Hide the delete confirmation modal. */
    deletingWebhookId = null;
    document.getElementById('delete-modal').style.display = 'none';
}


async function handleConfirmDelete() {
    /**
     * Send a DELETE request to remove the webhook.
     *
     * JAVASCRIPT CONCEPT — HTTP DELETE Method:
     *   REST APIs use the DELETE method to remove resources.
     *   The server identifies which resource to delete by the
     *   ID in the URL path: DELETE /api/webhooks/3
     */
    if (!deletingWebhookId) return;

    try {
        var response = await fetch('/api/webhooks/' + deletingWebhookId, {
            method: 'DELETE',
        });

        if (response.ok) {
            showToast('Webhook deleted!', 'success');
            hideDeleteModal();

            // Remove the card from the DOM without a page reload.
            // querySelector finds the card element by its data attribute.
            var card = document.querySelector(
                '.webhook-card[data-webhook-id="' + deletingWebhookId + '"]'
            );
            if (card) {
                // CSS transition for smooth removal
                card.style.opacity = '0';
                card.style.transform = 'scale(0.95)';
                setTimeout(function() {
                    card.remove();
                    updateWebhookCount();
                }, 300);
            }
        } else {
            showToast('Failed to delete webhook.', 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


// =============================================================
// TOGGLE ACTIVE/INACTIVE
// =============================================================

async function handleToggleWebhook(webhookId) {
    /**
     * Toggle a webhook between active and inactive states.
     *
     * We send a POST to /api/webhooks/{id}/toggle and the
     * server flips the is_active flag.
     */
    try {
        var response = await fetch('/api/webhooks/' + webhookId + '/toggle', {
            method: 'POST',
        });

        if (response.ok) {
            var data = await response.json();
            showToast(
                data.is_active ? 'Webhook activated!' : 'Webhook paused.',
                'success'
            );
        } else {
            showToast('Failed to toggle webhook.', 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


// =============================================================
// TEST WEBHOOK
// =============================================================

async function handleTestWebhook(webhookId) {
    /**
     * Send a test notification to the specified webhook.
     *
     * The button shows a loading state while the request is
     * in progress to provide visual feedback.
     */
    // Find the test button and show loading state
    var button = document.querySelector(
        '.btn-test[data-webhook-id="' + webhookId + '"], .btn-test[data-id="' + webhookId + '"]'
    );
    if (button) {
        button.textContent = '⏳ Sending...';
        button.disabled = true;
    }

    try {
        var response = await fetch('/api/webhooks/' + webhookId + '/test', {
            method: 'POST',
        });

        var data = await response.json();

        if (response.ok) {
            showToast('Test notification sent! ✅', 'success');
        } else {
            showToast('Test failed: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    } finally {
        // Reset button state regardless of success/failure.
        // "finally" always runs, even if there was an error.
        if (button) {
            button.textContent = '🧪 Test';
            button.disabled = false;
        }
    }
}


// =============================================================
// SCHEDULE: Save Settings
// =============================================================

async function saveScheduleSettings() {
    /**
     * Read the current schedule UI state and POST it to the server.
     *
     * This function is called whenever the user toggles the
     * schedule on/off OR changes the interval. It sends the
     * updated settings to the API, which saves them to the
     * database and restarts the background scheduler thread.
     */
    var enabled = document.getElementById('schedule-toggle').checked;

    // Find the currently selected radio button.
    // querySelector returns the FIRST matching element.
    var selectedRadio = document.querySelector(
        'input[name="schedule-interval"]:checked'
    );
    var intervalHours = selectedRadio ? parseInt(selectedRadio.value) : 24;

    try {
        var response = await fetch('/api/schedule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: enabled,
                interval_hours: intervalHours,
            }),
        });

        var data = await response.json();

        if (response.ok) {
            // Update the status display
            var statusText = document.getElementById('schedule-status-text');
            if (statusText) {
                if (data.enabled) {
                    statusText.innerHTML = '<span class="status-dot status-dot-active"></span> Running';
                } else {
                    statusText.innerHTML = '<span class="status-dot status-dot-inactive"></span> Disabled';
                }
            }

            showToast(
                enabled
                    ? 'Schedule enabled — refreshing every ' + intervalHours + ' hours'
                    : 'Schedule disabled',
                'success'
            );
        } else {
            showToast('Error: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


// =============================================================
// RSS FEEDS: Add, Delete, Toggle
// =============================================================

async function handleAddFeed(event) {
    /**
     * Add a new RSS feed source via POST /api/rss-feeds.
     */
    event.preventDefault();

    var nameInput = document.getElementById('feed-name-input');
    var urlInput = document.getElementById('feed-url-input');

    var name = nameInput.value.trim();
    var url = urlInput.value.trim();

    if (!name || !url) return;

    try {
        var response = await fetch('/api/rss-feeds', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: name, url: url }),
        });

        var data = await response.json();

        if (response.ok) {
            showToast('RSS feed added successfully!', 'success');
            nameInput.value = '';
            urlInput.value = '';
            window.location.reload();
        } else {
            showToast('Error: ' + (data.error || 'Failed to add feed'), 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


async function handleDeleteFeed(feedId, feedName) {
    /**
     * Remove an RSS feed source via DELETE /api/rss-feeds/{id}.
     */
    if (!confirm('Are you sure you want to remove "' + feedName + '"?')) {
        return;
    }

    try {
        var response = await fetch('/api/rss-feeds/' + feedId, {
            method: 'DELETE',
        });

        if (response.ok) {
            showToast('RSS feed removed.', 'success');
            var feedRow = document.querySelector('.feed-row[data-feed-id="' + feedId + '"]');
            if (feedRow) {
                feedRow.style.opacity = '0';
                feedRow.style.transform = 'scale(0.95)';
                setTimeout(function() {
                    feedRow.remove();
                    updateFeedCount();
                }, 300);
            }
        } else {
            showToast('Failed to remove RSS feed.', 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


async function handleToggleFeed(feedId) {
    /**
     * Toggle an RSS feed active/inactive via POST /api/rss-feeds/{id}/toggle.
     */
    try {
        var response = await fetch('/api/rss-feeds/' + feedId + '/toggle', {
            method: 'POST',
        });

        if (response.ok) {
            showToast('RSS feed updated.', 'success');
        } else {
            showToast('Failed to update feed status.', 'error');
        }
    } catch (error) {
        showToast('Network error: ' + error.message, 'error');
    }
}


function updateFeedCount() {
    /** Update feed count badge and empty state visibility. */
    var rows = document.querySelectorAll('.feed-row');
    var countEl = document.getElementById('feed-count');
    if (countEl) {
        countEl.textContent = rows.length;
    }

    var emptyState = document.getElementById('feeds-empty-state');
    if (emptyState) {
        emptyState.style.display = rows.length === 0 ? 'block' : 'none';
    }
}


// =============================================================
// USER MANAGEMENT HANDLERS (Admin Only)
// =============================================================

let deletingUsername = null;

function openAddUserModal() {
    var modal = document.getElementById('user-modal');
    var form = document.getElementById('add-user-form');
    var err = document.getElementById('user-form-error');
    if (err) err.style.display = 'none';
    if (form) form.reset();
    if (modal) modal.style.display = 'flex';
}

function closeAddUserModal() {
    var modal = document.getElementById('user-modal');
    if (modal) modal.style.display = 'none';
}

async function handleCreateUserSubmit(event) {
    event.preventDefault();
    var username = document.getElementById('new-username-input').value.trim();
    var password = document.getElementById('new-user-password-input').value;
    var role = document.getElementById('new-user-role-select').value;
    var err = document.getElementById('user-form-error');
    var btn = document.getElementById('create-user-submit-btn');

    if (!username || !password) return;

    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Creating...';
    }

    try {
        var res = await fetch('/api/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username, password: password, role: role })
        });
        var data = await res.json();
        if (res.ok) {
            showToast('User ' + username + ' created successfully!', 'success');
            closeAddUserModal();
            setTimeout(function() { window.location.reload(); }, 600);
        } else {
            if (err) {
                err.textContent = data.error || 'Failed to create user.';
                err.style.display = 'block';
            }
        }
    } catch (e) {
        if (err) {
            err.textContent = 'Network error while creating user.';
            err.style.display = 'block';
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Create User';
        }
    }
}

async function handleUpdateUserRole(username, newRole) {
    try {
        var res = await fetch('/api/users/' + encodeURIComponent(username) + '/role', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ role: newRole })
        });
        if (res.ok) {
            showToast('Updated ' + username + ' role to ' + newRole.toUpperCase(), 'success');
            setTimeout(function() { window.location.reload(); }, 600);
        } else {
            var data = await res.json();
            showToast(data.error || 'Failed to update role', 'error');
        }
    } catch (e) {
        showToast('Error updating role.', 'error');
    }
}

function openDeleteUserModal(username) {
    deletingUsername = username;
    var modal = document.getElementById('delete-user-modal');
    var nameEl = document.getElementById('delete-user-name');
    if (nameEl) nameEl.textContent = username;
    if (modal) modal.style.display = 'flex';
}

function closeDeleteUserModal() {
    deletingUsername = null;
    var modal = document.getElementById('delete-user-modal');
    if (modal) modal.style.display = 'none';
}

async function handleConfirmDeleteUser() {
    if (!deletingUsername) return;
    try {
        var res = await fetch('/api/users/' + encodeURIComponent(deletingUsername), {
            method: 'DELETE'
        });
        if (res.ok) {
            showToast('Deleted user ' + deletingUsername, 'success');
            closeDeleteUserModal();
            setTimeout(function() { window.location.reload(); }, 600);
        } else {
            var data = await res.json();
            showToast(data.error || 'Failed to delete user.', 'error');
        }
    } catch (e) {
        showToast('Error deleting user.', 'error');
    }
}


// =============================================================
// AUDIT LEDGER HANDLERS (Analyst & Admin)
// =============================================================

async function handleVerifyAuditChain() {
    var btn = document.getElementById('verify-audit-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Verifying Hash Chain...';
    }

    try {
        var res = await fetch('/api/audit-logs/verify');
        var data = await res.json();
        var banner = document.getElementById('audit-integrity-banner');
        var msgEl = document.getElementById('audit-integrity-msg');

        if (data.is_valid) {
            showToast('Audit Ledger: Cryptographic chain verified valid!', 'success');
            if (banner) {
                banner.className = 'alert alert-success-glass';
            }
        } else {
            showToast('Audit Ledger: Cryptographic chain broken at record #' + data.tampered_record_id, 'error');
            if (banner) {
                banner.className = 'alert alert-danger-glass';
            }
        }
        if (msgEl) msgEl.textContent = data.message;
    } catch (e) {
        showToast('Failed to verify audit ledger integrity.', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '🔍 Verify Cryptographic Chain';
        }
    }
}

let auditSearchTimer = null;
function debounceAuditSearch() {
    clearTimeout(auditSearchTimer);
    auditSearchTimer = setTimeout(loadAuditLogs, 300);
}

async function loadAuditLogs() {
    var searchInput = document.getElementById('audit-search-input');
    var actionSelect = document.getElementById('audit-action-filter');
    var tableBody = document.getElementById('audit-table-body');
    var countBadge = document.getElementById('audit-count');

    var search = searchInput ? searchInput.value.trim() : '';
    var action = actionSelect ? actionSelect.value : 'ALL';

    var params = new URLSearchParams();
    if (action && action !== 'ALL') params.append('action', action);
    if (search) params.append('search', search);

    try {
        var res = await fetch('/api/audit-logs?' + params.toString());
        if (!res.ok) return;
        var logs = await res.json();

        if (countBadge) countBadge.textContent = logs.length;
        if (!tableBody) return;

        if (logs.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding: 2rem; color:#9ca3af;">No audit records found matching criteria.</td></tr>';
            return;
        }

        tableBody.innerHTML = '';
        var fragment = document.createDocumentFragment();

        logs.forEach(function(log) {
            var tr = document.createElement('tr');
            var statusClass = log.status === 'SUCCESS' ? 'status-low' : (log.status === 'FAILED' ? 'status-critical' : 'status-med');
            var hashShort = (log.integrity_hash || '').substring(0, 12) + '…';

            tr.innerHTML = '<td style="font-size: 0.8rem; color: #9ca3af; white-space: nowrap;">' + escapeHtml(log.timestamp) + '</td>'
                 + '<td><strong style="color: #f3f4f6;">' + escapeHtml(log.username) + '</strong><span style="display: block; font-size: 0.7rem; color: #60a5fa; text-transform: uppercase;">' + escapeHtml(log.role) + '</span></td>'
                 + '<td><span class="audit-action-tag action-' + escapeHtml((log.action || '').toLowerCase()) + '">' + escapeHtml(log.action) + '</span></td>'
                 + '<td style="font-size: 0.8rem; color: #cbd5e1;">' + escapeHtml(log.resource_type || '-') + (log.resource_id ? ' <span style="color: #93c5fd;">(' + escapeHtml(log.resource_id) + ')</span>' : '') + '</td>'
                 + '<td><span class="actor-status-badge ' + statusClass + '">' + escapeHtml(log.status) + '</span></td>'
                 + '<td style="font-family: var(--font-mono); font-size: 0.75rem; color: #94a3b8;">' + escapeHtml(log.ip_address || '127.0.0.1') + '</td>'
                 + '<td style="font-size: 0.8rem; color: #cbd5e1; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="' + escapeHtml(log.details || '') + '">' + escapeHtml(log.details || '-') + '</td>'
                 + '<td style="font-family: var(--font-mono); font-size: 0.7rem; color: #a7f3d0;" title="' + escapeHtml(log.integrity_hash || '') + '">' + hashShort + '</td>';

            fragment.appendChild(tr);
        });

        tableBody.appendChild(fragment);
    } catch (e) {
        console.error('Failed to load audit logs:', e);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// =============================================================
// TAB SWITCHING
// =============================================================

function switchSettingsTab(tabName) {
    var buttons = document.querySelectorAll('.settings-tab-btn');
    var panels = document.querySelectorAll('.settings-tab-panel');

    buttons.forEach(function(btn) {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    panels.forEach(function(panel) {
        if (panel.id === 'panel-' + tabName) {
            panel.classList.add('active');
        } else {
            panel.classList.remove('active');
        }
    });

    if (tabName === 'api') {
        initApiExplorer();
    }

    try {
        history.replaceState(null, null, '#' + tabName);
        localStorage.setItem('cyberdash_settings_tab', tabName);
    } catch (e) {}
}

function initSettingsTabs() {
    var urlParams = new URLSearchParams(window.location.search);
    var tabParam = urlParams.get('tab');
    var hashTab = window.location.hash.replace('#', '');
    var savedTab = null;
    try { savedTab = localStorage.getItem('cyberdash_settings_tab'); } catch (e) {}

    var targetTab = tabParam || hashTab || savedTab || 'webhooks';
    var targetPanel = document.getElementById('panel-' + targetTab);
    if (targetPanel) {
        switchSettingsTab(targetTab);
    } else {
        switchSettingsTab('webhooks');
    }
}


// =============================================================
// PASSWORD POLICY & SECURITY HANDLERS
// =============================================================

async function handleSavePasswordPolicy(event) {
    event.preventDefault();
    var minLen = parseInt(document.getElementById('policy-min-length').value, 10) || 10;
    var reqUpper = document.getElementById('policy-require-upper').checked;
    var reqLower = document.getElementById('policy-require-lower').checked;
    var reqNum = document.getElementById('policy-require-numbers').checked;
    var reqSpecial = document.getElementById('policy-require-special').checked;
    var saveBtn = document.getElementById('save-policy-btn');

    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving Policy...';
    }

    try {
        var res = await fetch('/api/security/password-policy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                min_length: minLen,
                require_uppercase: reqUpper,
                require_lowercase: reqLower,
                require_numbers: reqNum,
                require_special: reqSpecial
            })
        });
        var data = await res.json();
        if (res.ok) {
            showToast('Security password policy updated successfully!', 'success');
            var checkLenNum = document.getElementById('check-length-num');
            if (checkLenNum) checkLenNum.textContent = minLen;
            checkPasswordAgainstLivePolicy();
        } else {
            showToast(data.error || 'Failed to update password policy.', 'error');
        }
    } catch (e) {
        showToast('Error updating policy.', 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = '💾 Save Security Policy';
        }
    }
}

function checkPasswordAgainstLivePolicy() {
    var pwdInput = document.getElementById('tester-input');
    var val = pwdInput ? pwdInput.value : '';

    var minLenEl = document.getElementById('policy-min-length');
    var minLen = minLenEl ? parseInt(minLenEl.value, 10) || 10 : 10;
    var reqUpper = document.getElementById('policy-require-upper') ? document.getElementById('policy-require-upper').checked : true;
    var reqLower = document.getElementById('policy-require-lower') ? document.getElementById('policy-require-lower').checked : true;
    var reqNum = document.getElementById('policy-require-numbers') ? document.getElementById('policy-require-numbers').checked : true;
    var reqSpecial = document.getElementById('policy-require-special') ? document.getElementById('policy-require-special').checked : true;

    var checkLen = document.getElementById('check-length');
    var checkUpper = document.getElementById('check-upper');
    var checkLower = document.getElementById('check-lower');
    var checkNumber = document.getElementById('check-number');
    var checkSpecial = document.getElementById('check-special');
    var verdictEl = document.getElementById('tester-verdict');

    if (!val) {
        if (verdictEl) {
            verdictEl.textContent = 'Enter a password above to evaluate compliance';
            verdictEl.style.color = '#94a3b8';
            verdictEl.style.background = 'rgba(255,255,255,0.04)';
        }
        if (checkLen) { checkLen.textContent = '⚪ Minimum ' + minLen + ' Characters'; checkLen.style.color = '#94a3b8'; }
        if (checkUpper) { checkUpper.textContent = (reqUpper ? '⚪' : '➖') + ' Uppercase Letter (A-Z)'; checkUpper.style.color = '#94a3b8'; }
        if (checkLower) { checkLower.textContent = (reqLower ? '⚪' : '➖') + ' Lowercase Letter (a-z)'; checkLower.style.color = '#94a3b8'; }
        if (checkNumber) { checkNumber.textContent = (reqNum ? '⚪' : '➖') + ' Numeric Digit (0-9)'; checkNumber.style.color = '#94a3b8'; }
        if (checkSpecial) { checkSpecial.textContent = (reqSpecial ? '⚪' : '➖') + ' Special Character (!@#$%...)'; checkSpecial.style.color = '#94a3b8'; }
        return;
    }

    var passLen = val.length >= minLen;
    var passUpper = !reqUpper || /[A-Z]/.test(val);
    var passLower = !reqLower || /[a-z]/.test(val);
    var passNum = !reqNum || /[0-9]/.test(val);
    var passSpecial = !reqSpecial || /[!@#$%^&*()_+\-=[\]{}|;:,.<>?/~`]/.test(val);

    updateCheckItem(checkLen, passLen, 'Minimum ' + minLen + ' Characters');
    updateCheckItem(checkUpper, passUpper, 'Uppercase Letter (A-Z)', !reqUpper);
    updateCheckItem(checkLower, passLower, 'Lowercase Letter (a-z)', !reqLower);
    updateCheckItem(checkNumber, passNum, 'Numeric Digit (0-9)', !reqNum);
    updateCheckItem(checkSpecial, passSpecial, 'Special Character (!@#$%...)', !reqSpecial);

    var allPassed = passLen && passUpper && passLower && passNum && passSpecial;
    if (verdictEl) {
        if (allPassed) {
            verdictEl.textContent = '✅ Policy Compliant: Strong Password';
            verdictEl.style.color = '#34d399';
            verdictEl.style.background = 'rgba(16, 185, 129, 0.15)';
        } else {
            verdictEl.textContent = '❌ Non-Compliant: Fails one or more requirements';
            verdictEl.style.color = '#f87171';
            verdictEl.style.background = 'rgba(239, 68, 68, 0.15)';
        }
    }
}

function updateCheckItem(el, passed, label, notRequired) {
    if (!el) return;
    if (notRequired) {
        el.textContent = '➖ ' + label + ' (Optional)';
        el.style.color = '#64748b';
    } else if (passed) {
        el.textContent = '✅ ' + label;
        el.style.color = '#34d399';
    } else {
        el.textContent = '❌ ' + label;
        el.style.color = '#f87171';
    }
}

async function handleGenerateCompliantPassword() {
    try {
        var res = await fetch('/api/security/generate-password');
        var data = await res.json();
        if (data.password) {
            var input = document.getElementById('tester-input');
            if (input) {
                input.value = data.password;
                checkPasswordAgainstLivePolicy();
            }
            if (navigator.clipboard) {
                await navigator.clipboard.writeText(data.password);
                showToast('Generated & copied compliant password!', 'success');
            } else {
                showToast('Generated compliant password: ' + data.password, 'success');
            }
        }
    } catch (e) {
        showToast('Failed to generate password.', 'error');
    }
}

async function generateUserModalPassword() {
    try {
        var res = await fetch('/api/security/generate-password');
        var data = await res.json();
        if (data.password) {
            var input = document.getElementById('new-user-password-input');
            if (input) {
                input.value = data.password;
                input.type = 'text'; // Show temporarily so admin can see/copy
            }
            if (navigator.clipboard) {
                await navigator.clipboard.writeText(data.password);
                showToast('Generated & copied strong password!', 'success');
            } else {
                showToast('Generated password: ' + data.password, 'success');
            }
        }
    } catch (e) {
        showToast('Failed to generate password.', 'error');
    }
}

// =============================================================
// API & DEVELOPER ACCESS MANAGEMENT
// =============================================================

function copyApiBaseUrl() {
    var origin = window.location.origin;
    var fullBaseUrl = origin + '/api';
    if (navigator.clipboard) {
        navigator.clipboard.writeText(fullBaseUrl).then(function() {
            showToast('Copied Base URL to clipboard!', 'success');
        });
    } else {
        var input = document.getElementById('api-base-url-input');
        if (input) {
            input.select();
            document.execCommand('copy');
            showToast('Copied Base URL!', 'success');
        }
    }
}

function initApiExplorer() {
    var origin = window.location.origin;
    var baseUrlInput = document.getElementById('api-base-url-input');
    if (baseUrlInput) {
        baseUrlInput.value = origin + '/api';
    }
    handleEndpointSelection();
}

function handleEndpointSelection() {
    var select = document.getElementById('api-endpoint-select');
    if (!select) return;

    var endpointId = select.value;
    var endpointsElem = document.getElementById('endpoints-data');
    var catalog = [];
    if (endpointsElem) {
        try {
            catalog = JSON.parse(endpointsElem.textContent);
        } catch (e) {
            catalog = [];
        }
    }

    var ep = catalog.find(function(item) { return item.id === endpointId; });
    if (!ep) return;

    var methodBadge = document.getElementById('endpoint-method-badge');
    var pathText = document.getElementById('endpoint-path-text');
    var descText = document.getElementById('endpoint-desc-text');
    var authText = document.getElementById('endpoint-auth-text');
    var samplePreview = document.getElementById('sample-response-preview');

    if (methodBadge) {
        methodBadge.textContent = ep.method;
        methodBadge.style.background = ep.method === 'POST' ? '#10b981' : (ep.method === 'DELETE' ? '#ef4444' : '#0284c7');
    }
    if (pathText) pathText.textContent = ep.path;
    if (descText) descText.textContent = ep.description;
    if (authText) authText.textContent = ep.auth_required;
    if (samplePreview) samplePreview.textContent = ep.sample_response || '{}';

    updateCurlPreview();
}

function updateCurlPreview() {
    var select = document.getElementById('api-endpoint-select');
    if (!select) return;

    var endpointsElem = document.getElementById('endpoints-data');
    var catalog = [];
    if (endpointsElem) {
        try {
            catalog = JSON.parse(endpointsElem.textContent);
        } catch (e) {
            catalog = [];
        }
    }

    var ep = catalog.find(function(item) { return item.id === select.value; });
    if (!ep) return;

    var tokenInput = document.getElementById('curl-api-token-input');
    var tokenVal = (tokenInput && tokenInput.value.trim()) ? tokenInput.value.trim() : 'cd_live_YOUR_API_TOKEN';

    var origin = window.location.origin;
    var curlCmd = '';

    if (ep.method === 'POST') {
        var sampleBody = ep.id === 'investigate' ? '{"ioc": "198.51.100.44"}' : '{}';
        curlCmd = 'curl -X POST "' + origin + ep.path + '" \\\n'
                + '  -H "X-API-Key: ' + tokenVal + '" \\\n'
                + '  -H "Content-Type: application/json" \\\n'
                + "  -d '" + sampleBody + "'";
    } else {
        curlCmd = 'curl -X GET "' + origin + ep.path + '" \\\n'
                + '  -H "X-API-Key: ' + tokenVal + '"';
    }

    var curlPreview = document.getElementById('curl-command-preview');
    if (curlPreview) {
        curlPreview.textContent = curlCmd;
    }
}

function copyCurlCommand() {
    var curlPreview = document.getElementById('curl-command-preview');
    if (!curlPreview) return;
    var cmd = curlPreview.textContent;

    if (navigator.clipboard) {
        navigator.clipboard.writeText(cmd).then(function() {
            showToast('Copied cURL command to clipboard!', 'success');
        });
    } else {
        showToast('cURL copied!', 'success');
    }
}

function openCreateTokenModal() {
    var modal = document.getElementById('create-token-modal');
    var errorDiv = document.getElementById('create-token-error');
    if (errorDiv) errorDiv.style.display = 'none';
    var form = document.getElementById('create-token-form');
    if (form) form.reset();
    if (modal) modal.style.display = 'flex';
}

function closeCreateTokenModal() {
    var modal = document.getElementById('create-token-modal');
    if (modal) modal.style.display = 'none';
}

async function handleCreateTokenSubmit(event) {
    event.preventDefault();
    var nameInput = document.getElementById('token-name-input');
    var roleSelect = document.getElementById('token-role-select');
    var expirySelect = document.getElementById('token-expiry-select');
    var rateLimitInput = document.getElementById('token-rate-limit-input');
    var submitBtn = document.getElementById('create-token-submit-btn');
    var errorDiv = document.getElementById('create-token-error');

    var name = nameInput ? nameInput.value.trim() : '';
    var role = roleSelect ? roleSelect.value : 'viewer';
    var expiryDays = expirySelect ? parseInt(expirySelect.value, 10) : 90;
    var rateLimit = rateLimitInput ? parseInt(rateLimitInput.value, 10) : 60;

    if (!name) {
        if (errorDiv) {
            errorDiv.textContent = 'Token name is required.';
            errorDiv.style.display = 'block';
        }
        return;
    }

    if (submitBtn) submitBtn.disabled = true;

    try {
        var res = await fetch('/api/tokens', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: name,
                role: role,
                expires_in_days: expiryDays > 0 ? expiryDays : null,
                rate_limit_per_min: rateLimit
            })
        });

        var data = await res.json();
        if (!res.ok) {
            if (errorDiv) {
                errorDiv.textContent = data.error || 'Failed to create API token.';
                errorDiv.style.display = 'block';
            }
            return;
        }

        closeCreateTokenModal();
        openRevealTokenModal(data.token);
        showToast('API token created!', 'success');
        refreshApiTokensList();
    } catch (e) {
        if (errorDiv) {
            errorDiv.textContent = 'An error occurred while generating the API token.';
            errorDiv.style.display = 'block';
        }
    } finally {
        if (submitBtn) submitBtn.disabled = false;
    }
}

function openRevealTokenModal(rawToken) {
    var modal = document.getElementById('reveal-token-modal');
    var input = document.getElementById('reveal-token-input');
    var example = document.getElementById('reveal-header-example');

    if (input) input.value = rawToken;
    if (example) {
        example.textContent = 'X-API-Key: ' + rawToken + '\n# or\nAuthorization: Bearer ' + rawToken;
    }
    if (modal) modal.style.display = 'flex';
}

function closeRevealTokenModal() {
    var modal = document.getElementById('reveal-token-modal');
    if (modal) modal.style.display = 'none';
}

function copyRevealedToken() {
    var input = document.getElementById('reveal-token-input');
    if (!input) return;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(input.value).then(function() {
            showToast('Copied secret token to clipboard!', 'success');
        });
    } else {
        input.select();
        document.execCommand('copy');
        showToast('Copied token!', 'success');
    }
}

async function handleRevokeApiToken(tokenId, tokenName) {
    if (!confirm('Are you sure you want to revoke API token "' + tokenName + '"? Automated integrations using this key will immediately fail.')) {
        return;
    }

    try {
        var res = await fetch('/api/tokens/' + tokenId + '/revoke', { method: 'POST' });
        var data = await res.json();
        if (!res.ok) {
            showToast(data.error || 'Failed to revoke token.', 'error');
            return;
        }
        showToast('API token revoked.', 'success');
        refreshApiTokensList();
    } catch (e) {
        showToast('Error revoking API token.', 'error');
    }
}

async function handleDeleteApiToken(tokenId, tokenName) {
    if (!confirm('Are you sure you want to permanently delete API token "' + tokenName + '"?')) {
        return;
    }

    try {
        var res = await fetch('/api/tokens/' + tokenId, { method: 'DELETE' });
        var data = await res.json();
        if (!res.ok) {
            showToast(data.error || 'Failed to delete token.', 'error');
            return;
        }
        showToast('API token deleted.', 'success');
        refreshApiTokensList();
    } catch (e) {
        showToast('Error deleting API token.', 'error');
    }
}

async function refreshApiTokensList() {
    try {
        var res = await fetch('/api/tokens');
        if (!res.ok) return;
        var tokens = await res.json();

        var badge = document.getElementById('tab-badge-api');
        if (badge) badge.textContent = tokens.length;

        var count = document.getElementById('api-token-count');
        if (count) count.textContent = tokens.length;

        var tbody = document.getElementById('api-tokens-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';
        var fragment = document.createDocumentFragment();

        if (tokens.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 2rem; color: #94a3b8;">No API tokens created yet.</td></tr>';
            return;
        }

        tokens.forEach(function(tok) {
            var tr = document.createElement('tr');
            tr.id = 'token-row-' + tok.id;

            var roleLabel = tok.role === 'admin' ? '👑 Admin' : (tok.role === 'analyst' ? '🕵️ Analyst' : '👁️ Viewer');
            var statusBadge = tok.is_active ? '<span class="actor-status-badge status-low">Active</span>' : '<span class="actor-status-badge status-critical">Revoked</span>';

            tr.innerHTML = '<td><strong style="color: #f1f5f9;">' + escapeHtml(tok.name) + '</strong><span style="display: block; font-size: 0.7rem; color: #94a3b8;">By ' + escapeHtml(tok.created_by) + '</span></td>'
                         + '<td style="font-family: var(--font-mono); font-size: 0.8rem; color: #38bdf8;">' + escapeHtml(tok.token_prefix) + '</td>'
                         + '<td><span class="role-badge role-' + escapeHtml(tok.role) + '">' + roleLabel + '</span></td>'
                         + '<td style="font-size: 0.8rem; color: #cbd5e1;">' + escapeHtml(String(tok.rate_limit_per_min)) + ' req/min</td>'
                         + '<td>' + statusBadge + '</td>'
                         + '<td style="font-size: 0.8rem; color: #94a3b8;">' + escapeHtml(tok.expires_at || 'Never') + '</td>'
                         + '<td style="font-size: 0.8rem; color: #94a3b8;">' + escapeHtml(tok.last_used_at || 'Never') + '</td>'
                         + '<td style="text-align: right; white-space: nowrap;">'
                         + (tok.is_active ? '<button type="button" class="btn btn-secondary btn-sm" data-id="' + tok.id + '" data-name="' + escapeHtml(tok.name) + '" onclick="handleRevokeApiToken(this.dataset.id, this.dataset.name)" style="margin-right: 4px;">🚫 Revoke</button>' : '')
                         + '<button type="button" class="btn btn-danger btn-sm" data-id="' + tok.id + '" data-name="' + escapeHtml(tok.name) + '" onclick="handleDeleteApiToken(this.dataset.id, this.dataset.name)">🗑️</button>'
                         + '</td>';

            fragment.appendChild(tr);
        });

        tbody.appendChild(fragment);
    } catch (e) {
        console.error('Failed to refresh tokens:', e);
    }
}

// Wire tab initialization to DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
    initSettingsTabs();
    checkPasswordAgainstLivePolicy();
    initApiExplorer();
});



