/**
 * app/static/js/theme.js — CyberDash Multi-Theme Engine
 *
 * Provides instant theme switching, localStorage persistence,
 * system preference fallbacks, and UI synchronization.
 */

(function() {
    'use strict';

    var STORAGE_KEY = 'cyberdash_theme';

    var THEMES = [
        {
            id: 'dark',
            name: 'Cyber Night',
            badge: 'Default',
            icon: '🌙',
            desc: 'Sleek dark slate aesthetic with glowing indigo & cyan accents.',
            colors: ['#0a0e1a', '#111827', '#818cf8', '#22d3ee']
        },
        {
            id: 'light',
            name: 'Daylight SOC',
            badge: 'Day Mode',
            icon: '☀️',
            desc: 'Crisp, high-contrast daylight theme for well-lit security operations centers.',
            colors: ['#f8fafc', '#ffffff', '#4f46e5', '#0284c7']
        },
        {
            id: 'matrix',
            name: 'Terminal Matrix',
            badge: 'Hacker',
            icon: '📟',
            desc: 'Phosphor green matrix terminal aesthetic with deep black canvas.',
            colors: ['#050805', '#0a100a', '#22c55e', '#00ff66']
        },
        {
            id: 'cyberpunk',
            name: 'Synthwave Neon',
            badge: 'High Voltage',
            icon: '🔮',
            desc: 'Retro-futuristic violet canvas with radiant magenta and neon cyan.',
            colors: ['#0c0517', '#170b2c', '#ec4899', '#06b6d4']
        },
        {
            id: 'midnight',
            name: 'Midnight Abyss',
            badge: 'Deep Ocean',
            icon: '🌌',
            desc: 'Deep oceanic navy abyss with electric cobalt and sky-blue highlights.',
            colors: ['#030712', '#0b1329', '#38bdf8', '#0ea5e9']
        },
        {
            id: 'oled',
            name: 'OLED Stealth',
            badge: 'True Black',
            icon: '⬛',
            desc: 'Pure pitch-black (#000000) canvas with high-contrast monochrome minimalism.',
            colors: ['#000000', '#0a0a0a', '#ffffff', '#e2e8f0']
        }
    ];

    function getThemeInfo(themeId) {
        return THEMES.find(function(t) { return t.id === themeId; }) || THEMES[0];
    }

    function getCurrentTheme() {
        var current = document.documentElement.getAttribute('data-theme');
        if (!current) {
            current = localStorage.getItem(STORAGE_KEY) || 'dark';
        }
        return current;
    }

    function setTheme(themeId, persist) {
        if (persist === undefined) persist = true;
        var validTheme = THEMES.some(function(t) { return t.id === themeId; });
        if (!validTheme) {
            themeId = 'dark';
        }

        document.documentElement.setAttribute('data-theme', themeId);
        if (persist) {
            try {
                localStorage.setItem(STORAGE_KEY, themeId);
            } catch (e) {}
        }

        updateThemeUI(themeId);

        // Dispatch custom event for charts or dynamic components
        var event = new CustomEvent('cyberdash:themechange', { detail: { theme: themeId, info: getThemeInfo(themeId) } });
        document.dispatchEvent(event);
    }

    function updateThemeUI(activeThemeId) {
        var info = getThemeInfo(activeThemeId);

        // Update header toggle button text & icon
        var toggleBtn = document.getElementById('theme-dropdown-btn');
        if (toggleBtn) {
            var iconSpan = toggleBtn.querySelector('.theme-btn-icon');
            var textSpan = toggleBtn.querySelector('.theme-btn-text');
            if (iconSpan) iconSpan.textContent = info.icon;
            if (textSpan) textSpan.textContent = info.name;
        }

        // Update active class in dropdown menu
        var menuOptions = document.querySelectorAll('.theme-option-item');
        menuOptions.forEach(function(opt) {
            if (opt.dataset.themeId === activeThemeId) {
                opt.classList.add('active');
            } else {
                opt.classList.remove('active');
            }
        });

        // Update active class in Settings Theme Gallery
        var galleryCards = document.querySelectorAll('.theme-card');
        galleryCards.forEach(function(card) {
            if (card.dataset.themeId === activeThemeId) {
                card.classList.add('active');
                var activeBadge = card.querySelector('.theme-card-selected-badge');
                if (activeBadge) activeBadge.style.display = 'inline-flex';
            } else {
                card.classList.remove('active');
                var activeBadge = card.querySelector('.theme-card-selected-badge');
                if (activeBadge) activeBadge.style.display = 'none';
            }
        });
    }

    function toggleThemeDropdown(e) {
        if (e) e.stopPropagation();
        var menu = document.getElementById('theme-dropdown-menu');
        if (!menu) return;
        var isShown = menu.style.display === 'block';
        closeAllHeaderDropdowns();
        menu.style.display = isShown ? 'none' : 'block';
    }

    function closeThemeDropdown() {
        var menu = document.getElementById('theme-dropdown-menu');
        if (menu) menu.style.display = 'none';
    }

    function closeAllHeaderDropdowns() {
        var userMenu = document.getElementById('user-dropdown-menu');
        if (userMenu) userMenu.style.display = 'none';
        var themeMenu = document.getElementById('theme-dropdown-menu');
        if (themeMenu) themeMenu.style.display = 'none';
    }

    // Initialize listeners on DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        var savedTheme = getCurrentTheme();
        setTheme(savedTheme, false);

        // Global click listener to close dropdowns when clicking outside
        document.addEventListener('click', function(e) {
            var themeContainer = document.querySelector('.theme-dropdown-container');
            if (themeContainer && !themeContainer.contains(e.target)) {
                closeThemeDropdown();
            }
        });
    });

    // Expose global CyberDashTheme object
    window.CyberDashTheme = {
        THEMES: THEMES,
        getThemeInfo: getThemeInfo,
        getCurrentTheme: getCurrentTheme,
        setTheme: setTheme,
        toggleThemeDropdown: toggleThemeDropdown,
        closeThemeDropdown: closeThemeDropdown
    };
})();
