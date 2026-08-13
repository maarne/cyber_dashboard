/* =============================================================
   app/static/js/dashboard.js — Dashboard Client-Side Logic
   =============================================================

   This file handles all the interactive behavior in the browser:
   - Switching between tabs (CVEs, CISA, News, Threats)
   - Searching and filtering data
   - Refreshing data from the server
   - Toast notifications

   JAVASCRIPT CONCEPTS FOR BEGINNERS:
   -----------------------------------
   - document.querySelector(): Find HTML elements
   - addEventListener(): React to user clicks/typing
   - fetch(): Make HTTP requests from the browser
   - async/await: Handle asynchronous operations
   - Template literals (`...${variable}...`): Embed variables in strings
   ============================================================= */


// =============================================================
// TAB SWITCHING
// =============================================================
// When the user clicks a tab button, we:
// 1. Remove "active" from all tab buttons and panels
// 2. Add "active" to the clicked tab button and its panel
//
// JAVASCRIPT CONCEPT — querySelectorAll():
//   Returns a list of ALL elements matching the CSS selector.
//   We can loop over this list with .forEach()
// =============================================================

function initTabs() {
    // Find all tab buttons in the navigation
    const tabButtons = document.querySelectorAll('.tab-btn');

    // .forEach() loops over each button and runs the function
    // inside the parentheses for each one.
    tabButtons.forEach(function(button) {

        // addEventListener() says: "When this button is clicked,
        // run this function." This is called an "event listener".
        button.addEventListener('click', function() {

            // Remove "active" class from ALL tab buttons
            tabButtons.forEach(function(btn) {
                btn.classList.remove('active');
            });

            // Remove "active" class from ALL tab panels
            document.querySelectorAll('.tab-panel').forEach(function(panel) {
                panel.classList.remove('active');
            });

            // Add "active" to the button that was clicked
            button.classList.add('active');

            // Find the corresponding panel using the data-tab attribute.
            // HTML: <button data-tab="cves">  →  #panel-cves
            //
            // JAVASCRIPT CONCEPT — dataset:
            //   HTML attributes starting with "data-" are accessible
            //   in JavaScript via element.dataset.
            //   <button data-tab="cves">  →  button.dataset.tab === "cves"
            var tabName = button.dataset.tab;
            var panel = document.getElementById('panel-' + tabName);
            if (panel) {
                panel.classList.add('active');
            }
        });
    });
}


// =============================================================
// SEARCH & FILTER — CVEs
// =============================================================
// These functions filter the displayed CVE cards based on:
// 1. Text search (CVE ID or description)
// 2. Severity filter pills (CRITICAL, HIGH, MEDIUM, LOW)
// =============================================================

// Keep track of the currently active severity filter
var activeSeverityFilter = 'ALL';

function initSearchAndFilter() {
    // --- Search Input ---
    var searchInput = document.getElementById('cve-search');
    if (searchInput) {
        // "input" event fires every time the user types a character
        searchInput.addEventListener('input', function() {
            filterCVECards();
        });
    }

    // --- Severity Filter Pills ---
    var filterPills = document.querySelectorAll('.filter-pill[data-severity]');
    filterPills.forEach(function(pill) {
        pill.addEventListener('click', function() {
            // Remove "active" from all pills
            filterPills.forEach(function(p) {
                p.classList.remove('active');
            });
            // Activate the clicked pill
            pill.classList.add('active');
            // Update the global filter variable
            activeSeverityFilter = pill.dataset.severity;
            // Re-filter the cards
            filterCVECards();
        });
    });

    // --- News Source Filter ---
    var sourceSelect = document.getElementById('news-source-filter');
    if (sourceSelect) {
        sourceSelect.addEventListener('change', function() {
            filterNewsCards();
        });
    }

    // --- News Search ---
    var newsSearch = document.getElementById('news-search');
    if (newsSearch) {
        newsSearch.addEventListener('input', function() {
            filterNewsCards();
        });
    }
}


function filterCVECards() {
    // Get the search text and convert to lowercase for
    // case-insensitive matching.
    //
    // JAVASCRIPT CONCEPT — Chaining methods:
    //   searchInput.value.toLowerCase().trim()
    //   Each method returns a value, and the next method
    //   is called on THAT value. Like a pipeline!
    var searchInput = document.getElementById('cve-search');
    var searchText = searchInput ? searchInput.value.toLowerCase().trim() : '';

    // Find all CVE cards
    var cards = document.querySelectorAll('#panel-cves .data-card');

    cards.forEach(function(card) {
        // Get the card's severity from its data attribute
        var cardSeverity = card.dataset.severity || '';
        // Get all text content of the card for searching
        var cardText = card.textContent.toLowerCase();

        // Determine visibility based on BOTH filters:
        // 1. Severity must match (or filter is "ALL")
        // 2. Search text must appear in the card's text
        var matchesSeverity = (activeSeverityFilter === 'ALL') ||
                               (cardSeverity === activeSeverityFilter);
        var matchesSearch = (searchText === '') ||
                            cardText.includes(searchText);

        // Show or hide the card.
        // "display: none" hides an element completely.
        // "display: ''" resets it to the default (visible).
        if (matchesSeverity && matchesSearch) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}


function filterNewsCards() {
    var sourceSelect = document.getElementById('news-source-filter');
    var searchInput = document.getElementById('news-search');

    var selectedSource = sourceSelect ? sourceSelect.value : 'ALL';
    var searchText = searchInput ? searchInput.value.toLowerCase().trim() : '';

    var cards = document.querySelectorAll('#panel-news .data-card');

    cards.forEach(function(card) {
        var cardSource = card.dataset.source || '';
        var cardText = card.textContent.toLowerCase();

        var matchesSource = (selectedSource === 'ALL') || (cardSource === selectedSource);
        var matchesSearch = (searchText === '') || cardText.includes(searchText);

        if (matchesSource && matchesSearch) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}


// =============================================================
// AUTHENTICATION & LOGIN MODAL HANDLERS
// =============================================================

function isUserAuthenticated() {
    return document.body.dataset.isAuthenticated === 'true';
}

function openLoginModal(message) {
    var modal = document.getElementById('login-modal');
    var errorMsg = document.getElementById('login-error-msg');
    var subtitle = document.querySelector('.modal-subtitle');
    if (errorMsg) errorMsg.style.display = 'none';
    if (subtitle && message) {
        subtitle.textContent = message;
    } else if (subtitle) {
        subtitle.textContent = 'Log in as administrator to modify settings and refresh feeds.';
    }
    if (modal) modal.style.display = 'flex';
}

function closeLoginModal() {
    var modal = document.getElementById('login-modal');
    if (modal) modal.style.display = 'none';
}

async function submitLogin(event) {
    event.preventDefault();
    var usernameInput = document.getElementById('login-username');
    var passwordInput = document.getElementById('login-password');
    var errorMsg = document.getElementById('login-error-msg');
    var submitBtn = document.getElementById('login-submit-btn');

    if (!usernameInput || !passwordInput) return;

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Logging in...';
    }

    try {
        var response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: usernameInput.value.trim(),
                password: passwordInput.value
            })
        });

        var data = await response.json();
        if (response.ok && data.status === 'success') {
            showToast('Logged in successfully!', 'success');
            closeLoginModal();
            setTimeout(function() { window.location.reload(); }, 500);
        } else {
            if (errorMsg) {
                errorMsg.textContent = data.message || 'Invalid username or password.';
                errorMsg.style.display = 'block';
            }
        }
    } catch (err) {
        if (errorMsg) {
            errorMsg.textContent = 'Login failed. Network error.';
            errorMsg.style.display = 'block';
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Log In';
        }
    }
}

async function handleLogout() {
    try {
        var response = await fetch('/api/auth/logout', { method: 'POST' });
        if (response.ok) {
            showToast('Logged out successfully.', 'info');
            setTimeout(function() { window.location.reload(); }, 500);
        }
    } catch (err) {
        console.error('Logout error:', err);
    }
}


// =============================================================
// REFRESH DATA — Fetch fresh data from the server
// =============================================================
async function refreshAllFeeds() {
    if (!isUserAuthenticated()) {
        openLoginModal('Admin authentication required to refresh feeds.');
        return;
    }

    // Get the refresh button and disable it to prevent double-clicks
    var refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.disabled = true;
        refreshBtn.textContent = '⏳ Refreshing...';
    }

    // Show the loading spinner overlay
    showSpinner();

    try {
        var response = await fetch('/api/refresh', {
            method: 'POST'
        });

        if (response.status === 401) {
            hideSpinner();
            if (refreshBtn) {
                refreshBtn.disabled = false;
                refreshBtn.textContent = '🔄 Refresh Feeds';
            }
            openLoginModal('Session expired. Please log in again.');
            return;
        }

        // Check if the server responded successfully
        if (response.ok) {
            var data = await response.json();
            showToast('Data refreshed successfully!', 'success');

            // Reload the page after a short delay to show the new data
            setTimeout(function() {
                // window.location.reload() refreshes the entire page,
                // which will re-render all the templates with fresh data
                window.location.reload();
            }, 1000);
        } else {
            showToast('Error refreshing data. Please try again.', 'error');
        }

    } catch (error) {
        // "catch" handles any errors (network failure, etc.)
        // This is JavaScript's version of Python's "except".
        console.error('Refresh error:', error);
        showToast('Network error. Please check your connection.', 'error');
    } finally {
        // "finally" runs whether the try succeeded or failed.
        // We always want to hide the spinner and re-enable the button.
        hideSpinner();
        if (refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.textContent = '🔄 Refresh Feeds';
        }
    }
}


// =============================================================
// SPINNER (Loading Overlay)
// =============================================================

function showSpinner() {
    var overlay = document.getElementById('spinner-overlay');
    if (overlay) {
        overlay.classList.add('active');
    }
}

function hideSpinner() {
    var overlay = document.getElementById('spinner-overlay');
    if (overlay) {
        overlay.classList.remove('active');
    }
}


// =============================================================
// TOAST NOTIFICATIONS
// =============================================================
// Toasts are small popup messages that appear briefly at the
// bottom-right of the screen to give the user feedback.
// =============================================================

function showToast(message, type) {
    // "type" can be "success", "error", or "info"
    type = type || 'info';

    var container = document.getElementById('toast-container');
    if (!container) return;

    // Create a new HTML element for the toast.
    // document.createElement() creates an element in memory
    // (it's not visible yet until we add it to the page).
    var toast = document.createElement('div');
    toast.className = 'toast ' + type;
    toast.textContent = message;

    // Add the toast to the container (makes it visible)
    container.appendChild(toast);

    // Remove the toast after 4 seconds.
    // setTimeout() runs a function after a delay (in milliseconds).
    // 4000 milliseconds = 4 seconds.
    setTimeout(function() {
        toast.remove();
    }, 4000);
}


// =============================================================
// DATE PRESET BUTTONS
// =============================================================

function initDatePresets() {
    var presetBtns = document.querySelectorAll('.preset-btn');
    var startDateInput = document.getElementById('start-date');
    var endDateInput = document.getElementById('end-date');
    var dateForm = document.getElementById('date-filter-form');

    function formatDate(d) {
        var year = d.getFullYear();
        var month = String(d.getMonth() + 1).padStart(2, '0');
        var day = String(d.getDate()).padStart(2, '0');
        return year + '-' + month + '-' + day;
    }

    presetBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            var preset = btn.dataset.preset;
            var today = new Date();
            var endStr = formatDate(today);
            var startStr = endStr;

            if (preset === 'today') {
                startStr = endStr;
            } else if (preset === '7days') {
                var d7 = new Date();
                d7.setDate(today.getDate() - 7);
                startStr = formatDate(d7);
            } else if (preset === '30days') {
                var d30 = new Date();
                d30.setDate(today.getDate() - 30);
                startStr = formatDate(d30);
            }

            if (startDateInput && endDateInput) {
                startDateInput.value = startStr;
                endDateInput.value = endStr;
                if (dateForm) {
                    dateForm.submit();
                }
            }
        });
    });
}


// =============================================================
// INITIALIZATION
// =============================================================
// DOMContentLoaded fires when the HTML has been fully parsed.
// This is the safest place to run our initialization code
// because all HTML elements are guaranteed to exist by then.
// =============================================================

document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initSearchAndFilter();
    initDatePresets();

    // Wire up the refresh button
    var refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshAllFeeds);
    }
});
