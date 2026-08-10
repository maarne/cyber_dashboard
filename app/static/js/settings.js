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

            // Find the closest button (handles clicking on emoji inside button)
            var button = target.closest('button');
            if (!button) return;

            var webhookId = button.dataset.webhookId;

            if (button.classList.contains('btn-test')) {
                handleTestWebhook(webhookId);
            } else if (button.classList.contains('btn-edit')) {
                handleEditWebhook(button);
            } else if (button.classList.contains('btn-delete')) {
                showDeleteModal(webhookId, button.dataset.name);
            }
        });

        // Toggle switch listener (delegated)
        webhooksList.addEventListener('change', function(event) {
            if (event.target.classList.contains('toggle-input')) {
                handleToggleWebhook(event.target.dataset.webhookId);
            }
        });
    }

    // --- Schedule Toggle ---
    // When the user toggles the schedule on/off, immediately
    // send the updated settings to the server.
    var scheduleToggle = document.getElementById('schedule-toggle');
    if (scheduleToggle) {
        scheduleToggle.addEventListener('change', function() {
            saveScheduleSettings();
        });
    }

    // --- Schedule Interval Radio Buttons ---
    // When the user clicks a different interval, update the
    // active pill styling and save the new settings.
    var intervalRadios = document.querySelectorAll('input[name="schedule-interval"]');
    intervalRadios.forEach(function(radio) {
        radio.addEventListener('change', function() {
            // Update the visual "active" state on the pills
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
     *
     * JAVASCRIPT CONCEPT — Ternary Operator:
     *   condition ? valueIfTrue : valueIfFalse
     *   It's a compact if/else in a single expression.
     *
     * Args:
     *   mode: "add" or "edit"
     *   data: (optional) Object with webhook data for editing.
     */
    var container = document.getElementById('webhook-form-container');
    var formTitle = document.getElementById('form-title');
    var submitBtn = document.getElementById('form-submit-btn');

    if (mode === 'edit' && data) {
        // Populate form with existing data for editing
        formTitle.textContent = 'Edit Webhook';
        submitBtn.textContent = '💾 Update Webhook';
        editingWebhookId = data.id;

        document.getElementById('webhook-id').value = data.id;
        document.getElementById('webhook-name').value = data.name;
        document.getElementById('webhook-platform').value = data.platform;
        document.getElementById('webhook-url').value = data.url;
        document.getElementById('notify-critical').checked = data.critical === '1' || data.critical === 'True';
        document.getElementById('notify-high').checked = data.high === '1' || data.high === 'True';
        document.getElementById('notify-cisa').checked = data.cisa === '1' || data.cisa === 'True';
    } else {
        // Reset form for new webhook
        formTitle.textContent = 'Add New Webhook';
        submitBtn.textContent = '💾 Save Webhook';
        editingWebhookId = null;

        document.getElementById('webhook-form').reset();
        document.getElementById('webhook-id').value = '';
    }

    container.style.display = 'block';

    // Smooth scroll to the form
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}


function hideForm() {
    /** Hide the webhook form and reset state. */
    var container = document.getElementById('webhook-form-container');
    container.style.display = 'none';
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
     *
     * JAVASCRIPT CONCEPT — data-* Attributes:
     *   HTML elements can store custom data in attributes like
     *   data-name="My Webhook". In JavaScript, these are accessed
     *   via element.dataset.name (camelCase for multi-word attrs).
     */
    showForm('edit', {
        id: button.dataset.webhookId,
        name: button.dataset.name,
        platform: button.dataset.platform,
        url: button.dataset.url,
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
        '.btn-test[data-webhook-id="' + webhookId + '"]'
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
// HELPERS
// =============================================================

function updateWebhookCount() {
    /** Update the webhook count badge after adding/removing. */
    var cards = document.querySelectorAll('.webhook-card');
    var countEl = document.getElementById('webhook-count');
    if (countEl) {
        countEl.textContent = cards.length;
    }

    // Show/hide the empty state
    var emptyState = document.getElementById('empty-state');
    if (emptyState) {
        emptyState.style.display = cards.length === 0 ? 'block' : 'none';
    }
}


function showToast(message, type) {
    /**
     * Show a toast notification.
     *
     * This reuses the toast container from base.html.
     * "type" is either "success" or "error" for styling.
     */
    var container = document.getElementById('toast-container');
    if (!container) return;

    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;

    container.appendChild(toast);

    // Trigger CSS animation by adding the "show" class
    // after a tiny delay (allows the browser to register
    // the initial state for the transition).
    setTimeout(function() {
        toast.classList.add('show');
    }, 10);

    // Auto-remove after 4 seconds
    setTimeout(function() {
        toast.classList.remove('show');
        setTimeout(function() {
            toast.remove();
        }, 300);
    }, 4000);
}
