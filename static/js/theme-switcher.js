/**
 * PortGuardian - Theme Switcher
 * Handles switching between light and dark themes
 */

document.addEventListener('DOMContentLoaded', function() {
    // Get theme toggle button
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');

    // Check for saved theme preference or respect OS preference
    const savedTheme = localStorage.getItem('theme');
    const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');

    // Function to set theme
    function setTheme(isDark) {
        if (isDark) {
            document.body.classList.add('dark-mode');
            if (themeIcon) {
                themeIcon.classList.remove('fa-moon');
                themeIcon.classList.add('fa-sun');
            }
            localStorage.setItem('theme', 'dark');

            // Save preference to server if user is logged in
            saveThemePreference('dark');
        } else {
            document.body.classList.remove('dark-mode');
            if (themeIcon) {
                themeIcon.classList.remove('fa-sun');
                themeIcon.classList.add('fa-moon');
            }
            localStorage.setItem('theme', 'light');

            // Save preference to server if user is logged in
            saveThemePreference('light');
        }
    }

    // Function to save theme preference to server
    function saveThemePreference(theme) {
        // Only attempt to save if user is logged in (check for logout link as a proxy)
        if (document.querySelector('a[href="/logout"]')) {
            fetch('/api/save-theme', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ theme: theme }),
            })
            .then(response => response.json())
            .catch(error => console.error('Error saving theme preference:', error));
        }
    }

    // Set initial theme based on saved preference or OS preference
    if (savedTheme === 'dark' || (savedTheme === null && prefersDarkScheme.matches)) {
        setTheme(true);
    } else {
        setTheme(false);
    }

    // Toggle theme when button is clicked
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const isDarkMode = document.body.classList.contains('dark-mode');
            setTheme(!isDarkMode);
        });
    }

    // Listen for OS theme preference changes
    prefersDarkScheme.addEventListener('change', function(e) {
        // Only change theme automatically if user hasn't set a preference
        if (localStorage.getItem('theme') === null) {
            setTheme(e.matches);
        }
    });
});
