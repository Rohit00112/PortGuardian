function showFlash(message, level = "info") {
    const stack = document.querySelector(".flash-stack");
    if (!stack) {
        window.alert(message);
        return;
    }

    const card = document.createElement("div");
    card.className = `flash-card flash-${level}`;
    card.innerHTML = `<div>${message}</div><button class="flash-dismiss" type="button" aria-label="Dismiss">&times;</button>`;
    stack.prepend(card);
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        headers: {
            "Content-Type": "application/json",
            ...options.headers,
        },
        ...options,
    });

    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    if (!response.ok) {
        throw new Error(data.message || data.error || `Request failed (${response.status})`);
    }
    return data;
}

function resolveTheme(userTheme) {
    if (userTheme === "dark") {
        return "dark";
    }
    if (userTheme === "light") {
        return "light";
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(userTheme) {
    const body = document.body;
    const resolvedTheme = resolveTheme(userTheme);
    body.dataset.userTheme = userTheme;
    body.dataset.theme = resolvedTheme;

    const icon = document.getElementById("themeIcon");
    if (icon) {
        icon.classList.toggle("fa-moon", resolvedTheme === "light");
        icon.classList.toggle("fa-sun", resolvedTheme === "dark");
    }
}

async function persistTheme(userTheme) {
    localStorage.setItem("trustscan-theme", userTheme);
    if (document.body.dataset.authenticated === "true") {
        try {
            await requestJson("/api/save-theme", {
                method: "POST",
                body: JSON.stringify({ theme: userTheme }),
            });
        } catch (error) {
            console.error("Failed to save theme:", error);
        }
    }
}

function bindFlashDismissals() {
    document.querySelectorAll(".flash-dismiss").forEach((button) => {
        button.addEventListener("click", () => {
            button.closest(".flash-card")?.remove();
        });
    });
}

function bindSidebarToggle() {
    const button = document.getElementById("sidebarToggle");
    if (!button) {
        return;
    }
    button.addEventListener("click", () => {
        document.getElementById("appShell")?.classList.toggle("sidebar-open");
    });
}

function bindGlobalFilter() {
    const input = document.getElementById("globalFilter");
    if (!input) {
        return;
    }
    input.addEventListener("input", () => {
        const term = input.value.trim().toLowerCase();
        document.querySelectorAll("[data-filter-item]").forEach((item) => {
            const haystack = (item.dataset.filterItem || item.textContent || "").toLowerCase();
            item.classList.toggle("hidden", Boolean(term) && !haystack.includes(term));
        });
    });
}

async function loadNotificationPreview() {
    if (document.body.dataset.authenticated !== "true") {
        return;
    }

    const preview = document.getElementById("notificationPreview");
    const count = document.getElementById("notificationCount");
    if (!preview) {
        return;
    }

    try {
        const response = await requestJson("/api/notifications?limit=5");
        const data = response.data;
        count.textContent = data.unread_count;
        count.classList.toggle("hidden", !data.unread_count);
        if (!data.items.length) {
            preview.innerHTML = '<div class="empty-panel">No recent notifications.</div>';
            return;
        }
        preview.innerHTML = data.items
            .map((item) => {
                const severity = item.severity || "info";
                return `
                    <div class="notification-preview-item" data-filter-item="${item.title} ${item.message}">
                        <div class="toolbar-row">
                            <span class="severity-badge severity-${severity}">${severity}</span>
                            <span class="context-kicker">${item.source}</span>
                        </div>
                        <strong>${item.title}</strong>
                        <div class="muted">${item.message}</div>
                    </div>
                `;
            })
            .join("");
    } catch (error) {
        preview.innerHTML = '<div class="empty-panel">Failed to load notifications.</div>';
    }
}

function bindNotificationPanel() {
    const toggle = document.getElementById("notificationToggle");
    const panel = document.getElementById("notificationPanel");
    if (!toggle || !panel) {
        return;
    }

    toggle.addEventListener("click", async (event) => {
        event.stopPropagation();
        panel.classList.toggle("open");
        if (panel.classList.contains("open")) {
            await loadNotificationPreview();
        }
    });

    document.addEventListener("click", (event) => {
        if (!panel.contains(event.target) && !toggle.contains(event.target)) {
            panel.classList.remove("open");
        }
    });
}

function bindThemeToggle() {
    const toggle = document.getElementById("themeToggle");
    if (!toggle) {
        return;
    }

    const localTheme = localStorage.getItem("trustscan-theme");
    const initialUserTheme = localTheme || document.body.dataset.userTheme || "system";
    applyTheme(initialUserTheme);

    toggle.addEventListener("click", async () => {
        const currentResolved = document.body.dataset.theme;
        const nextUserTheme = currentResolved === "dark" ? "light" : "dark";
        applyTheme(nextUserTheme);
        await persistTheme(nextUserTheme);
    });

    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
        if ((document.body.dataset.userTheme || "system") === "system") {
            applyTheme("system");
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    bindFlashDismissals();
    bindSidebarToggle();
    bindGlobalFilter();
    bindNotificationPanel();
    bindThemeToggle();
    loadNotificationPreview();
});

window.TrustScan = {
    requestJson,
    showFlash,
    loadNotificationPreview,
};
