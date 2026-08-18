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
            var button = event.target.closest('button');
            if (!button) return;

            if (typeof isUserAuthenticated === 'function' && !isUserAuthenticated()) {
                openLoginModal('Log in as administrator to manage webhooks.');
                return;
            }

            var webhookId = button.dataset.webhookId || button.dataset.id;
            var webhookName = button.dataset.name || button.dataset.webhookName;

            if (button.classList.contains('webhook-test-btn') || button.classList.contains('btn-test')) {
                handleTestWebhook(webhookId, button);
            } else if (button.classList.contains('webhook-edit-btn') || button.classList.contains('btn-edit')) {
                handleEditWebhook(button);
            } else if (button.classList.contains('webhook-delete-btn') || button.classList.contains('btn-delete')) {
                showDeleteModal(webhookId, webhookName);
            }
        });

        webhooksList.addEventListener('change', function(event) {
            if (event.target.classList.contains('webhook-toggle-status') || event.target.classList.contains('toggle-input')) {
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
    var feedsList = document.getElementById('feeds-list') || document.getElementById('rss-feeds-list');
    if (feedsList) {
        feedsList.addEventListener('click', function(event) {
            var button = event.target.closest('button');
            if (button && (button.classList.contains('feed-delete-btn') || button.classList.contains('btn-delete'))) {
                handleDeleteFeed(button.dataset.feedId || button.dataset.id, button.dataset.feedName || button.dataset.name);
            }
        });

        feedsList.addEventListener('change', function(event) {
            if (event.target.classList.contains('feed-toggle-status') || event.target.classList.contains('feed-toggle')) {
                handleToggleFeed(event.target.dataset.feedId || event.target.dataset.id);
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

// =============================================================
// WEBHOOK COUNT HELPER
// =============================================================

function updateWebhookCount() {
    var cards = document.querySelectorAll('.webhook-card');
    var countElem = document.getElementById('webhook-count');
    if (countElem) countElem.textContent = cards.length;

    var rssCards = document.querySelectorAll('.feed-card');
    var badge = document.getElementById('tab-badge-alerts');
    if (badge) badge.textContent = cards.length + rssCards.length;

    var emptyState = document.getElementById('webhooks-empty-state');
    if (emptyState) {
        emptyState.style.display = cards.length === 0 ? 'block' : 'none';
    }
}


// =============================================================
// EDIT WEBHOOK
// =============================================================

async function handleEditWebhook(button) {
    /**
     * Populate the form with data from the clicked webhook card.
     */
    if (!button) return;
    var webhookId = button.dataset ? (button.dataset.webhookId || button.dataset.id) : button;

    var name = button.dataset ? (button.dataset.name || button.dataset.webhookName) : '';
    var platform = button.dataset ? button.dataset.platform : '';
    var url = button.dataset ? button.dataset.url : '';
    var critical = button.dataset ? button.dataset.critical : null;
    var high = button.dataset ? button.dataset.high : null;
    var cisa = button.dataset ? button.dataset.cisa : null;

    if (name && url) {
        showForm('edit', {
            id: webhookId,
            name: name,
            platform: platform || 'slack',
            url: url,
            critical: critical,
            high: high,
            cisa: cisa
        });
        return;
    }

    try {
        var res = await fetch('/api/webhooks');
        if (res.ok) {
            var webhooks = await res.json();
            var wh = webhooks.find(function(w) { return String(w.id) === String(webhookId); });
            if (wh) {
                showForm('edit', {
                    id: wh.id,
                    name: wh.name,
                    platform: wh.platform,
                    url: wh.masked_url || wh.webhook_url,
                    critical: wh.notify_critical_cves,
                    high: wh.notify_high_cves,
                    cisa: wh.notify_cisa_exploits
                });
                return;
            }
        }
    } catch (e) {
        console.error('Error fetching webhook for edit:', e);
    }
}


// =============================================================
// DELETE WEBHOOK (with confirmation modal)
// =============================================================

function showDeleteModal(webhookId, webhookName) {
    /** Show the delete confirmation modal. */
    deletingWebhookId = webhookId;
    var nameElem = document.getElementById('delete-webhook-name');
    if (nameElem) nameElem.textContent = webhookName || 'this webhook';
    var modal = document.getElementById('delete-modal');
    if (modal) modal.style.display = 'flex';
}


function hideDeleteModal() {
    /** Hide the delete confirmation modal. */
    deletingWebhookId = null;
    var modal = document.getElementById('delete-modal');
    if (modal) modal.style.display = 'none';
}


async function handleConfirmDelete() {
    if (!deletingWebhookId) return;

    try {
        var response = await fetch('/api/webhooks/' + deletingWebhookId, {
            method: 'DELETE',
        });

        if (response.ok) {
            showToast('Webhook deleted!', 'success');
            hideDeleteModal();

            var card = document.querySelector(
                '.webhook-card[data-id="' + deletingWebhookId + '"], .webhook-card[data-webhook-id="' + deletingWebhookId + '"]'
            );
            if (card) {
                card.style.opacity = '0';
                card.style.transform = 'scale(0.95)';
                setTimeout(function() {
                    card.remove();
                    updateWebhookCount();
                }, 300);
            } else {
                updateWebhookCount();
            }
        } else {
            var data = await response.json();
            showToast(data.error || 'Failed to delete webhook.', 'error');
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

async function handleTestWebhook(webhookId, btnElem) {
    /**
     * Send a test notification to the specified webhook.
     */
    if (!webhookId) return;

    var button = btnElem || document.querySelector(
        '.webhook-test-btn[data-id="' + webhookId + '"], .btn-test[data-id="' + webhookId + '"]'
    );

    // Prevent double clicking / concurrent calls
    if (button && (button.disabled || button.dataset.loading === 'true')) {
        return;
    }

    if (button) {
        button.dataset.loading = 'true';
        button.disabled = true;
        button.innerHTML = '⏳ Testing...';
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
        if (button) {
            button.dataset.loading = 'false';
            button.disabled = false;
            button.innerHTML = '🔔 Test Alert';
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


function updateFeedCount() {
    var cards = document.querySelectorAll('.feed-card');
    var countElem = document.getElementById('feeds-count');
    if (countElem) countElem.textContent = cards.length;

    var webhookCards = document.querySelectorAll('.webhook-card');
    var badge = document.getElementById('tab-badge-alerts');
    if (badge) badge.textContent = webhookCards.length + cards.length;

    var emptyState = document.getElementById('feeds-empty-state');
    if (emptyState) {
        emptyState.style.display = cards.length === 0 ? 'block' : 'none';
    }
}

async function handleDeleteFeed(feedId, feedName) {
    /**
     * Remove an RSS feed source via DELETE /api/rss-feeds/{id}.
     */
    if (!confirm('Are you sure you want to remove "' + (feedName || 'this RSS feed') + '"?')) {
        return;
    }

    try {
        var response = await fetch('/api/rss-feeds/' + feedId, {
            method: 'DELETE',
        });

        if (response.ok) {
            showToast('RSS feed removed.', 'success');
            var feedCard = document.querySelector(
                '.feed-card[data-id="' + feedId + '"], .feed-card[data-feed-id="' + feedId + '"], .feed-row[data-feed-id="' + feedId + '"]'
            );
            if (feedCard) {
                feedCard.style.opacity = '0';
                feedCard.style.transform = 'scale(0.95)';
                setTimeout(function() {
                    feedCard.remove();
                    updateFeedCount();
                }, 300);
            } else {
                updateFeedCount();
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
    // Map legacy/alias tab names
    if (tabName === 'webhooks' || tabName === 'feeds' || tabName === 'automation') tabName = 'alerts';
    if (tabName === 'users') tabName = 'security';

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

    var rawTab = tabParam || hashTab || savedTab || 'alerts';
    if (rawTab === 'webhooks' || rawTab === 'feeds' || rawTab === 'automation') rawTab = 'alerts';
    if (rawTab === 'users' || rawTab === 'appearance') rawTab = 'security';

    var targetPanel = document.getElementById('panel-' + rawTab);
    if (targetPanel) {
        switchSettingsTab(rawTab);
    } else {
        switchSettingsTab('alerts');
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

var DEFAULT_ENDPOINTS_CATALOG = [
    {
        id: "summary",
        name: "Dashboard Summary Metrics",
        method: "GET",
        path: "/api/summary",
        description: "Real-time vulnerability counts, active CISA zero-days, RSS articles, and threat indicators.",
        auth_required: "Viewer / Optional",
        params: [
            { name: "start_date", type: "string", example: "2026-01-01", desc: "Filter by start date (YYYY-MM-DD)" },
            { name: "end_date", type: "string", example: "2026-08-14", desc: "Filter by end date (YYYY-MM-DD)" }
        ],
        sample_response: '{\n  "total_cves": 142,\n  "critical_cves": 28,\n  "high_cves": 54,\n  "active_exploits": 19,\n  "total_articles": 85,\n  "total_threats": 42\n}'
    },
    {
        id: "cves",
        name: "Vulnerability Intelligence Feed",
        method: "GET",
        path: "/api/cves",
        description: "Paginated CVE disclosures with EPSS scores, CVSS v3.1 vectors, Ransomware Campaign tags, and CISA flags.",
        auth_required: "Viewer / Optional",
        params: [
            { name: "limit", type: "integer", example: "25", desc: "Max records to return (1-200)" },
            { name: "severity", type: "string", example: "CRITICAL", desc: "CRITICAL, HIGH, MEDIUM, LOW" },
            { name: "search", type: "string", example: "Fortinet", desc: "Keyword or CVE ID search" }
        ],
        sample_response: '[\n  {\n    "cve_id": "CVE-2026-1135",\n    "severity": "CRITICAL",\n    "cvss_score": 9.8,\n    "epss_score": 0.942,\n    "is_cisa_kev": true,\n    "ransomware_campaign": "LockBit 3.0"\n  }\n]'
    },
    {
        id: "cisa",
        name: "CISA Known Exploited Vulnerabilities",
        method: "GET",
        path: "/api/cisa",
        description: "Curated catalog of actively exploited vulnerabilities compiled by CISA.",
        auth_required: "Viewer / Optional",
        params: [
            { name: "limit", type: "integer", example: "50", desc: "Max records to return" }
        ],
        sample_response: '[\n  {\n    "cve_id": "CVE-2026-2291",\n    "vendor_project": "Microsoft",\n    "product": "Windows Kernel",\n    "date_added": "2026-08-10"\n  }\n]'
    },
    {
        id: "threats",
        name: "Threat Actor Indicators & IoCs",
        method: "GET",
        path: "/api/threats",
        description: "Active malicious IPs, domains, and hashes tracked across global telemetry sources.",
        auth_required: "Viewer / Optional",
        params: [
            { name: "limit", type: "integer", example: "50", desc: "Max records to return" },
            { name: "type", type: "string", example: "ip", desc: "ip, url, domain, hash" }
        ],
        sample_response: '[\n  {\n    "indicator_type": "ip",\n    "indicator_value": "198.51.100.44",\n    "threat_type": "Command and Control",\n    "source": "Abuse.ch"\n  }\n]'
    },
    {
        id: "investigate",
        name: "IOC Threat Investigation & Enrichment",
        method: "POST",
        path: "/api/investigate",
        description: "Correlates submitted IP addresses, domains, and file hashes against threat intelligence databases and Mitre ATT&CK.",
        auth_required: "Viewer / Analyst",
        params: [
            { name: "ioc", type: "string (JSON body)", example: '{"ioc": "198.51.100.44"}', desc: "Target indicator string" }
        ],
        sample_response: '{\n  "ioc": "198.51.100.44",\n  "type": "ipv4",\n  "verdict": "MALICIOUS",\n  "threat_score": 92,\n  "associated_actors": ["APT29", "Cozy Bear"],\n  "matched_rules": ["Sigma-C2-Beaconing"]\n}'
    },
    {
        id: "rules",
        name: "Detection Rules Repository",
        method: "GET",
        path: "/api/rules",
        description: "Enterprise Sigma and YARA rules mapped to MITRE ATT&CK techniques with SIEM deployment guidelines.",
        auth_required: "Viewer / Analyst",
        params: [
            { name: "rule_type", type: "string", example: "SIGMA", desc: "SIGMA or YARA" },
            { name: "severity", type: "string", example: "CRITICAL", desc: "CRITICAL, HIGH, MEDIUM" }
        ],
        sample_response: '[\n  {\n    "id": 1,\n    "title": "PsExec Lateral Movement Detection",\n    "rule_type": "SIGMA",\n    "severity": "HIGH",\n    "mitre_id": "T1021.002"\n  }\n]'
    },
    {
        id: "audit_logs",
        name: "Cryptographic Audit Ledger",
        method: "GET",
        path: "/api/audit-logs",
        description: "Cryptographically chained audit trail verifying governance integrity, authentication events, and administrative changes.",
        auth_required: "Analyst / Admin",
        params: [
            { name: "action", type: "string", example: "USER_ROLE_UPDATED", desc: "Action filter" },
            { name: "search", type: "string", example: "admin", desc: "Search keyword" }
        ],
        sample_response: '[\n  {\n    "id": 114,\n    "username": "admin",\n    "role": "admin",\n    "action": "API_TOKEN_CREATED",\n    "status": "SUCCESS",\n    "integrity_hash": "a8f3b29..."\n  }\n]'
    }
];

function getEndpointsCatalog() {
    var endpointsElem = document.getElementById('endpoints-data');
    if (endpointsElem && endpointsElem.textContent) {
        try {
            var parsed = JSON.parse(endpointsElem.textContent.trim());
            if (Array.isArray(parsed) && parsed.length > 0) {
                return parsed;
            }
        } catch (e) {
            console.warn('Could not parse embedded endpoints catalog JSON, using defaults:', e);
        }
    }
    return DEFAULT_ENDPOINTS_CATALOG;
}

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

    var catalog = getEndpointsCatalog();
    var select = document.getElementById('explorer-endpoint-select');
    if (select) {
        select.innerHTML = '';
        catalog.forEach(function(ep) {
            var opt = document.createElement('option');
            opt.value = ep.id;
            opt.textContent = '[' + ep.method + '] ' + ep.path + ' — ' + ep.name;
            select.appendChild(opt);
        });
    }

    handleExplorerEndpointChange();
    renderEndpointsCatalogTable();
}

function handleExplorerEndpointChange() {
    var select = document.getElementById('explorer-endpoint-select');
    if (!select) return;

    var catalog = getEndpointsCatalog();
    var ep = catalog.find(function(item) { return item.id === select.value; }) || catalog[0];
    if (!ep) return;

    // Update Method Badge
    var methodBadge = document.getElementById('explorer-method-badge');
    if (methodBadge) {
        methodBadge.textContent = ep.method;
        if (ep.method === 'POST') {
            methodBadge.style.background = 'rgba(16, 185, 129, 0.15)';
            methodBadge.style.color = '#34d399';
            methodBadge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
        } else if (ep.method === 'DELETE') {
            methodBadge.style.background = 'rgba(239, 68, 68, 0.15)';
            methodBadge.style.color = '#f87171';
            methodBadge.style.borderColor = 'rgba(239, 68, 68, 0.3)';
        } else {
            methodBadge.style.background = 'rgba(34, 211, 238, 0.15)';
            methodBadge.style.color = '#22d3ee';
            methodBadge.style.borderColor = 'rgba(34, 211, 238, 0.3)';
        }
    }

    // Update Params / Body Container
    var paramsContainer = document.getElementById('explorer-params-container');
    var paramsInput = document.getElementById('explorer-params-input');
    var paramsLabel = document.getElementById('explorer-params-label');

    if (paramsContainer && paramsInput) {
        if (ep.method === 'POST') {
            paramsContainer.style.display = 'block';
            if (paramsLabel) paramsLabel.textContent = 'JSON Request Body (application/json):';
            paramsInput.placeholder = '{"ioc": "198.51.100.44"}';
            paramsInput.value = '{"ioc": "198.51.100.44"}';
        } else if (ep.params && ep.params.length > 0) {
            paramsContainer.style.display = 'block';
            if (paramsLabel) paramsLabel.textContent = 'Optional URL Query Parameters (e.g. key=value&key2=value2):';
            var firstParam = ep.params[0];
            paramsInput.placeholder = 'e.g. ' + firstParam.name + '=' + firstParam.example;
            paramsInput.value = '';
        } else {
            paramsContainer.style.display = 'none';
            paramsInput.value = '';
        }
    }

    // Reset status and show sample response
    var statusBadge = document.getElementById('explorer-status-badge');
    if (statusBadge) {
        statusBadge.textContent = 'Ready (Sample Preview)';
        statusBadge.style.color = '#94a3b8';
    }

    var responseBody = document.getElementById('explorer-response-body');
    if (responseBody) {
        responseBody.textContent = ep.sample_response || '// Click "Send Request" to execute live query...';
    }
}

async function handleSendExplorerRequest() {
    var select = document.getElementById('explorer-endpoint-select');
    if (!select) return;

    var catalog = getEndpointsCatalog();
    var ep = catalog.find(function(item) { return item.id === select.value; }) || catalog[0];
    if (!ep) return;

    var statusBadge = document.getElementById('explorer-status-badge');
    var responseBody = document.getElementById('explorer-response-body');
    var paramsInput = document.getElementById('explorer-params-input');
    var sendBtn = document.getElementById('explorer-send-btn');

    if (statusBadge) {
        statusBadge.textContent = '⏳ Fetching live telemetry...';
        statusBadge.style.color = '#38bdf8';
    }
    if (responseBody) {
        responseBody.textContent = 'Executing query to ' + ep.path + '...';
    }
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.textContent = '⏳ Sending...';
    }

    var url = ep.path;
    var fetchOptions = {
        method: ep.method,
        headers: {
            'Accept': 'application/json'
        }
    };

    if (ep.method === 'GET' && paramsInput && paramsInput.value.trim()) {
        var q = paramsInput.value.trim();
        url += (url.includes('?') ? '&' : '?') + q;
    } else if (ep.method === 'POST') {
        var bodyStr = (paramsInput && paramsInput.value.trim()) ? paramsInput.value.trim() : '{}';
        fetchOptions.headers['Content-Type'] = 'application/json';
        fetchOptions.body = bodyStr;
    }

    var startTime = performance.now();

    try {
        var res = await fetch(url, fetchOptions);
        var endTime = performance.now();
        var latency = Math.round(endTime - startTime);

        var contentType = res.headers.get('content-type') || '';
        var formatted = '';

        if (contentType.includes('application/json')) {
            var data = await res.json();
            formatted = JSON.stringify(data, null, 2);
        } else {
            formatted = await res.text();
        }

        if (responseBody) {
            responseBody.textContent = formatted;
        }

        if (statusBadge) {
            statusBadge.textContent = res.status + ' ' + (res.statusText || 'OK') + ' (' + latency + 'ms)';
            statusBadge.style.color = res.ok ? '#34d399' : '#f87171';
        }
    } catch (err) {
        if (responseBody) {
            responseBody.textContent = 'Network or Execution Error: ' + err.message;
        }
        if (statusBadge) {
            statusBadge.textContent = 'Request Failed';
            statusBadge.style.color = '#f87171';
        }
    } finally {
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.textContent = '🚀 Send Request';
        }
    }
}

function copyExplorerResponse() {
    var responseBody = document.getElementById('explorer-response-body');
    if (!responseBody) return;

    var text = responseBody.textContent;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function() {
            showToast('Copied API response JSON to clipboard!', 'success');
        });
    } else {
        showToast('Response copied!', 'success');
    }
}

function renderEndpointsCatalogTable() {
    var tbody = document.getElementById('endpoints-table-body');
    if (!tbody) return;

    var catalog = getEndpointsCatalog();
    tbody.innerHTML = '';
    var fragment = document.createDocumentFragment();

    catalog.forEach(function(ep) {
        var tr = document.createElement('tr');

        var methodBadgeStyle = ep.method === 'POST'
            ? 'background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);'
            : (ep.method === 'DELETE'
                ? 'background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);'
                : 'background: rgba(34, 211, 238, 0.15); color: #22d3ee; border: 1px solid rgba(34, 211, 238, 0.3);');

        var rolePill = '<span class="role-pill role-pill-viewer">Viewer</span>';
        if (ep.auth_required && ep.auth_required.includes('Admin')) {
            rolePill = '<span class="role-pill role-pill-admin">Admin</span>';
        } else if (ep.auth_required && ep.auth_required.includes('Analyst')) {
            rolePill = '<span class="role-pill role-pill-analyst">Analyst</span>';
        }

        var paramsHtml = '';
        if (ep.params && ep.params.length > 0) {
            paramsHtml = '<div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px;">' +
                ep.params.map(function(p) {
                    return '<span class="badge" style="font-size: 0.7rem; background: rgba(255,255,255,0.05); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1); font-family: var(--font-mono);">' +
                        escapeHtml(p.name) + ' (' + escapeHtml(p.type) + ')' +
                    '</span>';
                }).join('') +
            '</div>';
        }

        tr.innerHTML = '<td><span class="badge" style="font-family: var(--font-mono); font-weight: bold; ' + methodBadgeStyle + '">' + escapeHtml(ep.method) + '</span></td>'
                     + '<td><code style="color: #38bdf8; font-weight: 600; font-size: 0.85rem;">' + escapeHtml(ep.path) + '</code><div style="font-size: 0.75rem; color: #94a3b8; margin-top: 2px;">' + escapeHtml(ep.name) + '</div></td>'
                     + '<td>' + rolePill + '</td>'
                     + '<td style="color: #e2e8f0; font-size: 0.8rem;">' + escapeHtml(ep.description) + paramsHtml + '</td>';

        fragment.appendChild(tr);
    });

    tbody.appendChild(fragment);
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



