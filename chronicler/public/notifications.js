// /var/www/chronicler/public/notifications.js
(() => {
  const $ = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  function isActive(alert) {
    return alert.is_active === true || ['t', 'true', '1'].includes(String(alert.is_active).toLowerCase());
  }

  function dismissalKey(userId) {
    return `chronicler.dismissedAlerts.${userId}`;
  }

  function getDismissals(userId) {
    try {
      const dismissals = JSON.parse(localStorage.getItem(dismissalKey(userId)) || '{"throughId":0,"ids":[]}');
      if (!dismissals || typeof dismissals !== 'object' || !Array.isArray(dismissals.ids)) {
        return { throughId: 0, ids: [] };
      }
      return dismissals;
    } catch (e) {
      console.error('Failed to read dismissed alerts:', e);
      return { throughId: 0, ids: [] };
    }
  }

  function saveDismissals(userId, dismissals) {
    try {
      localStorage.setItem(dismissalKey(userId), JSON.stringify(dismissals));
    } catch (e) {
      console.error('Failed to save dismissed alerts:', e);
    }
  }

  function isDismissed(alert, dismissals) {
    const id = Number(alert.id);
    return id <= Number(dismissals.throughId || 0) ||
      (!isActive(alert) && dismissals.ids.includes(id));
  }

  async function loadGlobalNotifications() {
    try {
      const r = await fetch('/api/notifications.php', { cache: 'no-store' });
      const d = await r.json();
      if (!d || !d.ok) return;

      const list = $('notiList');
      if (!list) return;

      const userId = Number(d.user_id);
      const dismissals = getDismissals(userId);
      const items = (d.alerts || []).filter(alert => !isDismissed(alert, dismissals));
      const activeCount = items.filter(isActive).length;
      const badge = $('notiBadge');
      if (badge) {
        badge.textContent = activeCount;
        badge.style.display = activeCount > 0 ? 'inline-block' : 'none';
      }
      const header = $('notiMenu')?.querySelector('.dropdown-header');
      if (header) {
        header.innerHTML = `<span>Alerts</span><span style="display:flex;gap:5px;">
          <button id="notiClearInactive" class="btn small" type="button"
            style="font-size:11px;padding:2px 6px;">Clear inactive</button>
          <button id="notiClearAll" class="btn small" type="button"
            style="font-size:11px;padding:2px 6px;">Clear All</button>
        </span>`;
        header.style.display = 'flex';
        header.style.justifyContent = 'space-between';
        header.style.alignItems = 'center';

        $('notiClearInactive')?.addEventListener('click', e => {
          e.stopPropagation();
          const inactiveIds = (d.alerts || [])
            .filter(alert => !isActive(alert))
            .map(alert => Number(alert.id));
          dismissals.ids = [...new Set([...dismissals.ids, ...inactiveIds])];
          saveDismissals(userId, dismissals);
          loadGlobalNotifications();
        });
        $('notiClearAll')?.addEventListener('click', e => {
          e.stopPropagation();
          const latestId = (d.alerts || []).reduce((max, alert) => Math.max(max, Number(alert.id) || 0), 0);
          saveDismissals(userId, { throughId: latestId, ids: [] });
          loadGlobalNotifications();
        });
      }

      if (!items.length) {
        list.innerHTML = '<div style="color:#4a6a8a;padding:10px;font-size:12px;">No alerts</div>';
        return;
      }

      list.innerHTML = items.map(alert => {
        const active = isActive(alert);
        const source = alert.source_ip || 'Unknown source';
        const count = Number(alert.count) > 1 ? ` · ${alert.count} hits` : '';
        const assigned = alert.assigned_username ? ` · Assigned to ${alert.assigned_username}` : '';
        const date = alert.assigned_at || alert.acknowledged_time || '';

        return `
          <div class="dropdown-item" data-alert-row="${alert.id}"
               style="padding:8px 12px;border-bottom:1px solid #1c2434;cursor:pointer;${active ? 'background:#131c2a;' : 'opacity:.55;'}">
            <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
              <div style="font-size:12px;color:${active ? '#c5d8f0' : '#7b8796'};font-weight:${active ? 'bold' : 'normal'}">
                ${esc(alert.alert_type)} — ${esc(source)}${esc(count)}
              </div>
              ${active ? '' : `<button class="btn small" type="button" data-clear-alert="${alert.id}"
                style="font-size:10px;padding:2px 6px;">Clear</button>`}
            </div>
            <div style="font-size:11px;color:${active ? '#4a6a8a' : '#66717f'};margin-top:2px;">
              #${esc(alert.id)} · ${esc(alert.severity)} · ${esc(alert.status)}${esc(assigned)}
            </div>
            ${date ? `<div style="font-size:10px;color:#4a6a8a;margin-top:2px;">${esc(date.slice(0,16))}</div>` : ''}
          </div>`;
      }).join('');

      list.querySelectorAll('[data-clear-alert]').forEach(button => {
        button.addEventListener('click', e => {
          e.stopPropagation();
          dismissals.ids = [...new Set([...dismissals.ids, Number(button.dataset.clearAlert)])];
          saveDismissals(userId, dismissals);
          loadGlobalNotifications();
        });
      });

      list.querySelectorAll('[data-alert-row]').forEach(row => {
        row.addEventListener('click', () => {
          window.location.href = `/alerts.html?id=${encodeURIComponent(row.dataset.alertRow)}`;
        });
      });
    } catch (e) {
      console.error('Failed to load notifications:', e);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    loadGlobalNotifications();
    setInterval(loadGlobalNotifications, 10000);

    $('notiBell')?.addEventListener('click', (e) => {
      e.stopPropagation();
      $('notiMenu')?.classList.toggle('hidden');
    });

    document.addEventListener('click', (e) => {
      const bell = $('notiBell');
      const menu = $('notiMenu');
      if (menu && bell && !menu.contains(e.target) && !bell.contains(e.target)) {
        menu.classList.add('hidden');
      }
    });
  });
})();
