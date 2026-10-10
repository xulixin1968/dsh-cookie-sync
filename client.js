/**
 * dsh-cookie-sync — Client half: settings UI for cookie sync.
 *
 * Provides a settings page where users can:
 * - View sync status
 * - Add/remove auto-sync domains
 * - Toggle auto-sync on navigate
 * - Manually trigger a sync
 */

const name = "dsh-cookie-sync";

async function applyClient(ctx) {
  // Register a settings section
  ctx.inject(["settings"], (sctx) => {
    const settings = sctx.settings;
    if (!settings) return;

    // Register the cookie sync settings section
    settings.registerSection({
      id: "cookie-sync",
      title: "Cookie Sync",
      order: 50,
      render: (container) => {
        container.innerHTML = `
          <div class="cookie-sync-settings" style="padding: 16px; max-width: 600px;">
            <h3 style="margin: 0 0 12px; font-size: 16px;">Cookie Sync</h3>
            <p style="margin: 0 0 16px; color: var(--text-secondary, #888); font-size: 14px;">
              Sync cookies from Edge browser to the DSH sidebar browser. When you open a supported
              website in the sidebar, your existing login session is automatically applied — no need to log in again.
            </p>

            <div style="margin-bottom: 16px;">
              <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 14px;">
                <input type="checkbox" id="cookie-sync-auto" checked
                  style="width: 18px; height: 18px; cursor: pointer;" />
                Auto-sync on page navigation
              </label>
            </div>

            <div style="margin-bottom: 16px;">
              <label style="display: block; margin-bottom: 6px; font-size: 14px; font-weight: 500;">
                Auto-sync domains:
              </label>
              <div id="cookie-sync-domains" style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px;"></div>
              <div style="display: flex; gap: 6px;">
                <input type="text" id="cookie-sync-new-domain" placeholder="example.com"
                  style="flex: 1; padding: 6px 10px; border: 1px solid var(--border-color, #ddd); border-radius: 6px; font-size: 13px;" />
                <button id="cookie-sync-add-domain"
                  style="padding: 6px 14px; border: none; border-radius: 6px; background: var(--primary, #1a73e8); color: white; cursor: pointer; font-size: 13px;">
                  Add
                </button>
              </div>
            </div>

            <div style="margin-bottom: 16px;">
              <button id="cookie-sync-now"
                style="padding: 8px 16px; border: 1px solid var(--border-color, #ddd); border-radius: 6px; cursor: pointer; font-size: 14px; background: var(--bg-secondary, #f5f5f5);">
                Sync cookies for this page
              </button>
            </div>

            <div id="cookie-sync-status"
              style="padding: 12px; border-radius: 6px; background: var(--bg-secondary, #f5f5f5); font-size: 13px; font-family: monospace; white-space: pre-wrap;">
              Loading status...
            </div>
          </div>
        `;

        // Load current domains
        const defaultDomains = ["github.com", "raw.githubusercontent.com", "api.github.com", "localhost", "127.0.0.1"];
        const domainsContainer = container.querySelector("#cookie-sync-domains");
        const newDomainInput = container.querySelector("#cookie-sync-new-domain");
        const addDomainBtn = container.querySelector("#cookie-sync-add-domain");
        const autoSyncCheckbox = container.querySelector("#cookie-sync-auto");
        const syncNowBtn = container.querySelector("#cookie-sync-now");
        const statusDiv = container.querySelector("#cookie-sync-status");

        let domains = [...defaultDomains];

        function renderDomains() {
          domainsContainer.innerHTML = "";
          for (const domain of domains) {
            const chip = document.createElement("span");
            chip.style.cssText = "display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 12px; background: var(--bg-tertiary, #e8e8e8); font-size: 12px;";
            chip.textContent = domain;
            const removeBtn = document.createElement("button");
            removeBtn.textContent = "×";
            removeBtn.style.cssText = "border: none; background: none; cursor: pointer; font-size: 14px; padding: 0; color: var(--text-secondary, #888);";
            removeBtn.onclick = () => {
              domains = domains.filter((d) => d !== domain);
              renderDomains();
            };
            chip.appendChild(removeBtn);
            domainsContainer.appendChild(chip);
          }
        }
        renderDomains();

        addDomainBtn.onclick = () => {
          const val = newDomainInput.value.trim();
          if (val && !domains.includes(val)) {
            domains.push(val);
            newDomainInput.value = "";
            renderDomains();
          }
        };

        newDomainInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter") addDomainBtn.click();
        });

        // Load status
        async function loadStatus() {
          try {
            const resp = await fetch("/api/cookie-sync/cookies?host=" + encodeURIComponent(location.hostname), {
              credentials: "include",
            });
            const data = await resp.json();
            if (data.synced) {
              statusDiv.textContent = `✅ Synced ${data.count} cookie(s) for ${location.hostname}`;
            } else {
              statusDiv.textContent = `ℹ️ ${data.reason || "No cookies available for this domain"}`;
            }
          } catch {
            statusDiv.textContent = "⚠️ Cookie sync service unavailable";
          }
        }
        loadStatus();

        syncNowBtn.onclick = async () => {
          syncNowBtn.textContent = "Syncing...";
          syncNowBtn.disabled = true;
          await loadStatus();
          syncNowBtn.textContent = "Sync cookies for this page";
          syncNowBtn.disabled = false;
        };
      },
    });
  });
}

export default applyClient;
