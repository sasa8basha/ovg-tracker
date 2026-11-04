/**
 * shell.js — OVG Tracker v8 Shell
 * Never destroys document.body.
 * Features:
 *   - Money Pulse Game (heartbeat + trend)
 *   - Attention Engine (sidebar badge + title)
 *   - Quick Actions (hover menu + undo)
 */
(function () {
  'use strict';

  const S = {
    user: null,
    sites: [],
    currentSite: null,
    active: null,
    lang: 'ar',
    mounted: false,
    cmdOpen: false,
    cmdItems: [],
    cmdSelected: 0,
    cmdQuery: '',
    baseTitle: document.title,
    attentionTimer: null,
    pulseTimer: null,
    quickActionsEl: null,
    quickActionsTarget: null,
  };

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));

  const fmtNum = (n) => Number(n || 0).toLocaleString('en-US');
  const fmtMoney = (n) => {
    const v = Number(n || 0);
    const sign = v > 0 ? '+' : (v < 0 ? '-' : '');
    return sign + '$' + Math.abs(v).toFixed(2);
  };
  const fmtPct = (n, d = 1) => Number(n || 0).toFixed(d) + '%';

  function localDateStr(d) {
    const dt = d || new Date();
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  }

  async function api(url, opts = {}) {
    const res = await fetch(url, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      ...opts,
    });
    if (res.status === 401) { window.location.href = '/'; throw new Error('Unauthorized'); }
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const j = await res.json(); msg = j.detail || msg; } catch (_) {}
      throw new Error(msg);
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  // ============ ICONS ============
  const ICON = {
    dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
    radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/><path d="M12 2 L12 8"/></svg>',
    visits: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    labeling: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>',
    money: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>',
    analytics: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
    dataquality: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>',
    logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>',
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>',
    ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    scale: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>',
  };

  // ============ NAV ============
  const NAV = {
    ar: [
      { group: 'التحليل', items: [
        { id: 'dashboard', label: 'لوحة التحكم', icon: 'dashboard', href: '/dashboard' },
        { id: 'radar',     label: 'Radar',        icon: 'radar',     href: '/radar' },
        { id: 'visits',    label: 'الزيارات',     icon: 'visits',    href: '/visits', needsSite: true },
        { id: 'labeling',  label: 'المراجعة',     icon: 'labeling',  href: '/labeling', badge: 'labeling' },
      ]},
      { group: 'المال', items: [
        { id: 'smart',     label: 'التقارير الذكية', icon: 'money',     href: '/smart-reports', needsSite: true },
        { id: 'analytics', label: 'Zone Analytics',  icon: 'analytics', href: '/zone-analytics', needsSite: true },
      ]},
      { group: 'النظام', items: [
        { id: 'dataquality', label: 'جودة البيانات', icon: 'dataquality', href: '/data-quality' },
        { id: 'settings',    label: 'الإعدادات',     icon: 'settings',    href: '/settings' },
      ]},
    ],
    en: [
      { group: 'Analyze', items: [
        { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', href: '/dashboard' },
        { id: 'radar',     label: 'Radar',     icon: 'radar',     href: '/radar' },
        { id: 'visits',    label: 'Visits',    icon: 'visits',    href: '/visits', needsSite: true },
        { id: 'labeling',  label: 'Labeling',  icon: 'labeling',  href: '/labeling', badge: 'labeling' },
      ]},
      { group: 'Money', items: [
        { id: 'smart',     label: 'Smart Reports',  icon: 'money',     href: '/smart-reports', needsSite: true },
        { id: 'analytics', label: 'Zone Analytics', icon: 'analytics', href: '/zone-analytics', needsSite: true },
      ]},
      { group: 'System', items: [
        { id: 'dataquality', label: 'Data Quality', icon: 'dataquality', href: '/data-quality' },
        { id: 'settings',    label: 'Settings',     icon: 'settings',    href: '/settings' },
      ]},
    ],
  };

  const T = {
    ar: {
      search: 'بحث سريع',
      searchPlaceholder: 'اكتب للبحث...',
      collapse: 'طوي القائمة',
      empty: 'لا توجد نتائج',
      nav: 'تنقّل',
      user: 'الحساب',
      logout: 'خروج',
      attnTooltip: 'محتاج انتباه',
    },
    en: {
      search: 'Quick search',
      searchPlaceholder: 'Type to search...',
      collapse: 'Collapse',
      empty: 'No results',
      nav: 'Navigate',
      user: 'Account',
      logout: 'Logout',
      attnTooltip: 'Needs attention',
    },
  };

  // ============ SIDEBAR BUILDER ============
  function buildSidebar() {
    const L = T[S.lang];
    const nav = NAV[S.lang] || NAV.ar;
    let itemsHtml = '';
    nav.forEach(group => {
      itemsHtml += `<div class="sh-nav-group"><div class="sh-nav-label">${esc(group.group)}</div>`;
      group.items.forEach(it => {
        const needsSite = it.needsSite && S.currentSite;
        const href = needsSite ? `${it.href}?site=${encodeURIComponent(S.currentSite.site_key)}` : it.href;
        const isActive = S.active === it.id ? 'active' : '';
        const disabled = it.needsSite && !S.currentSite;
        const style = disabled ? 'opacity:0.4;pointer-events:none;' : '';
        const badgeHtml = it.badge
          ? `<span class="sh-nav-badge" data-badge="${esc(it.badge)}" style="display:none;">0</span>`
          : '';
        itemsHtml += `
          <a href="${esc(href)}" class="sh-nav-item ${isActive}" style="${style}" data-nav="${esc(it.id)}">
            ${ICON[it.icon] || ''}
            <span class="label">${esc(it.label)}</span>
            ${badgeHtml}
          </a>`;
      });
      itemsHtml += `</div>`;
    });

    const initial = (S.user && S.user.username ? S.user.username[0] : '?').toUpperCase();
    const username = S.user ? S.user.username : '—';

    return `
      <aside class="sh-sidebar" id="shSidebar">
        <div class="sh-sidebar-head">
          <div class="sh-logo">O</div>
          <div class="sh-logo-text">
            <div class="t1">OVG Tracker</div>
            <div class="t2">v8 · PRO</div>
          </div>
        </div>
        <nav class="sh-nav">${itemsHtml}</nav>
        <div class="sh-sidebar-foot">
          <a href="/settings" class="sh-user">
            <div class="sh-avatar">${esc(initial)}</div>
            <div class="sh-user-info">
              <div class="n">${esc(username)}</div>
              <div class="r">${esc(L.user)}</div>
            </div>
          </a>
        </div>
        <button class="sh-collapse-btn" id="shCollapseBtn" aria-label="${esc(L.collapse)}" title="${esc(L.collapse)}">
          ${ICON.chevron}
        </button>
      </aside>`;
  }

  // ============ TOPBAR ============
  function buildTopbar() {
    const L = T[S.lang];
    return `
      <header class="sh-topbar">
        <div class="sh-breadcrumb" id="shBreadcrumb"></div>
        <div class="sh-topbar-spacer"></div>
        <button class="sh-topbar-btn sh-search-btn" id="shSearchBtn" type="button">
          ${ICON.search}
          <span>${esc(L.search)}</span>
          <kbd>⌘K</kbd>
        </button>
        <button class="sh-money-pulse zero" id="shMoneyPulse" title="P&L اليوم" type="button">
          <span class="pulse-dot"></span>
          <span class="sh-mp-value">$0.00</span>
          <span class="sh-mp-trend flat">—</span>
        </button>
        <button class="sh-topbar-btn" id="shThemeBtn" title="Theme" aria-label="Toggle theme" type="button">
          ${ICON.moon}
        </button>
      </header>`;
  }

  function buildStatusbar() {
    return `
      <footer class="sh-statusbar">
        <span class="sh-status-item"><span class="sh-status-dot"></span>LIVE</span>
        <span class="sh-status-item" id="shStatusVisits">— اليوم</span>
        <span class="sh-status-item" id="shStatusProfit">—</span>
        <span class="sh-status-spacer"></span>
        <span class="sh-status-item">⌘K بحث</span>
        <span class="sh-status-item">?</span>
      </footer>`;
  }

  function buildMobileNav() {
    const nav = (NAV[S.lang] || NAV.ar)[0].items.slice(0, 5);
    return `
      <nav class="sh-mobile-nav">
        ${nav.map(it => {
          const badge = it.badge ? `<span class="sh-mobile-badge" data-mbadge="${esc(it.badge)}" style="display:none;">0</span>` : '';
          return `
            <a href="${esc(it.href)}" class="sh-mobile-nav-item ${S.active === it.id ? 'active' : ''}">
              ${ICON[it.icon] || ''}
              <span>${esc(it.label)}</span>
              ${badge}
            </a>`;
        }).join('')}
      </nav>`;
  }

  // ============ COMMAND PALETTE ============
  function buildCmdPalette() {
    return `
      <div class="sh-cmd-overlay" id="shCmdOverlay">
        <div class="sh-cmd">
          <div class="sh-cmd-input-wrap">
            ${ICON.search}
            <input type="text" class="sh-cmd-input" id="shCmdInput" placeholder="${esc(T[S.lang].searchPlaceholder)}" autocomplete="off">
            <kbd style="padding:2px 6px;background:var(--sh-canvas);border:1px solid var(--sh-line-2);border-radius:3px;font-family:var(--sh-font-mono);font-size:9px;color:var(--sh-ink-mute);">ESC</kbd>
          </div>
          <div class="sh-cmd-results" id="shCmdResults"></div>
        </div>
      </div>`;
  }

  function buildCommands() {
    const nav = (NAV[S.lang] || NAV.ar).flatMap(g => g.items);
    const cmds = [];
    nav.forEach(it => {
      if (it.needsSite && !S.currentSite) return;
      const href = it.needsSite ? `${it.href}?site=${encodeURIComponent(S.currentSite.site_key)}` : it.href;
      cmds.push({ group: T[S.lang].nav, label: it.label, icon: it.icon, action: () => { window.location.href = href; } });
    });
    if (S.sites && S.sites.length) {
      S.sites.forEach(s => {
        cmds.push({
          group: T[S.lang].nav, label: s.name, desc: '🌐',
          action: () => { window.location.href = '/dashboard?site=' + encodeURIComponent(s.site_key); },
        });
      });
    }
    cmds.push({
      group: T[S.lang].user, label: T[S.lang].logout, icon: 'logout',
      action: async () => {
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
        window.location.href = '/';
      },
    });
    return cmds;
  }

  function renderCmdResults() {
    const container = document.getElementById('shCmdResults');
    if (!container) return;
    const q = S.cmdQuery.trim().toLowerCase();
    const all = buildCommands();
    const filtered = q
      ? all.filter(c => c.label.toLowerCase().includes(q) || (c.desc || '').toLowerCase().includes(q))
      : all.slice(0, 12);
    S.cmdItems = filtered;
    if (S.cmdSelected >= filtered.length) S.cmdSelected = Math.max(0, filtered.length - 1);
    if (!filtered.length) {
      container.innerHTML = `<div class="sh-cmd-empty">${esc(T[S.lang].empty)}</div>`;
      return;
    }
    let html = '';
    let lastGroup = null;
    filtered.forEach((c, i) => {
      if (c.group !== lastGroup) {
        html += `<div class="sh-cmd-group-label">${esc(c.group)}</div>`;
        lastGroup = c.group;
      }
      const sel = i === S.cmdSelected ? 'selected' : '';
      html += `
        <div class="sh-cmd-item ${sel}" data-idx="${i}">
          ${c.icon ? ICON[c.icon] || '' : '<span style="width:14px;"></span>'}
          <span>${esc(c.label)}</span>
          ${c.desc ? `<span class="desc">${esc(c.desc)}</span>` : ''}
        </div>`;
    });
    container.innerHTML = html;
    container.querySelectorAll('.sh-cmd-item').forEach(el => {
      el.addEventListener('click', () => {
        const i = Number(el.dataset.idx);
        const c = S.cmdItems[i];
        if (c && c.action) { closeCmd(); setTimeout(c.action, 80); }
      });
      el.addEventListener('mouseenter', () => {
        S.cmdSelected = Number(el.dataset.idx);
        renderCmdResults();
      });
    });
  }

  function openCmd() {
    S.cmdOpen = true; S.cmdQuery = ''; S.cmdSelected = 0;
    const ov = document.getElementById('shCmdOverlay');
    if (!ov) return;
    ov.classList.add('is-open');
    const inp = document.getElementById('shCmdInput');
    if (inp) { inp.value = ''; setTimeout(() => inp.focus(), 30); }
    renderCmdResults();
  }
  function closeCmd() {
    S.cmdOpen = false;
    const ov = document.getElementById('shCmdOverlay');
    if (ov) ov.classList.remove('is-open');
  }
  function bindCmd() {
    const inp = document.getElementById('shCmdInput');
    if (!inp) return;
    inp.addEventListener('input', (e) => { S.cmdQuery = e.target.value; S.cmdSelected = 0; renderCmdResults(); });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { closeCmd(); e.preventDefault(); }
      else if (e.key === 'ArrowDown') { S.cmdSelected = Math.min(S.cmdSelected + 1, S.cmdItems.length - 1); renderCmdResults(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { S.cmdSelected = Math.max(S.cmdSelected - 1, 0); renderCmdResults(); e.preventDefault(); }
      else if (e.key === 'Enter') { const c = S.cmdItems[S.cmdSelected]; if (c && c.action) { closeCmd(); setTimeout(c.action, 80); } e.preventDefault(); }
    });
    const overlay = document.getElementById('shCmdOverlay');
    if (overlay) overlay.addEventListener('click', (e) => { if (e.target.id === 'shCmdOverlay') closeCmd(); });
  }

  // ============ TOAST (with undo support) ============
  function ensureToastContainer() {
    let c = document.querySelector('.sh-toast-container');
    if (!c) {
      c = document.createElement('div');
      c.className = 'sh-toast-container';
      document.body.appendChild(c);
    }
    return c;
  }

  function toast(msg, type = 'info', duration = 2600, opts = {}) {
    const c = ensureToastContainer();
    const el = document.createElement('div');
    el.className = `sh-toast ${type}`;
    el.style.position = 'relative';
    el.style.overflow = 'hidden';

    const iconChar = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
    el.innerHTML = `
      <span class="sh-toast-icon">${iconChar}</span>
      <span class="sh-toast-body">${esc(msg)}</span>
      ${opts.undoLabel ? `<button class="sh-toast-undo" type="button">${esc(opts.undoLabel)}</button>` : ''}
      ${opts.undoLabel ? `<span class="sh-toast-timer" style="--sh-toast-dur:${duration}ms;"></span>` : ''}
    `;
    c.appendChild(el);

    if (opts.undoLabel && typeof opts.onUndo === 'function') {
      const btn = el.querySelector('.sh-toast-undo');
      if (btn) btn.addEventListener('click', () => {
        try { opts.onUndo(); } catch (e) { console.warn(e); }
        el.classList.add('hiding');
        setTimeout(() => el.remove(), 200);
      });
    }

    setTimeout(() => {
      if (el.parentNode) {
        el.classList.add('hiding');
        setTimeout(() => el.remove(), 200);
      }
    }, duration);
  }

  // ============ THEME ============
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-sh-theme', theme);
    const btn = document.getElementById('shThemeBtn');
    if (btn) btn.innerHTML = theme === 'dark' ? ICON.moon : ICON.sun;
    const root = document.documentElement;
    if (theme === 'light') {
      root.style.setProperty('--sh-canvas', '#F8FAFC');
      root.style.setProperty('--sh-surface', '#FFFFFF');
      root.style.setProperty('--sh-elevated', '#F1F5F9');
      root.style.setProperty('--sh-raised', '#E2E8F0');
      root.style.setProperty('--sh-line-1', '#E2E8F0');
      root.style.setProperty('--sh-line-2', '#CBD5E1');
      root.style.setProperty('--sh-line-3', '#94A3B8');
      root.style.setProperty('--sh-ink-hi', '#0F172A');
      root.style.setProperty('--sh-ink-md', '#334155');
      root.style.setProperty('--sh-ink-lo', '#64748B');
      root.style.setProperty('--sh-ink-mute', '#94A3B8');
    } else {
      root.style.setProperty('--sh-canvas', '#08090D');
      root.style.setProperty('--sh-surface', '#0F1117');
      root.style.setProperty('--sh-elevated', '#161822');
      root.style.setProperty('--sh-raised', '#1C1F2E');
      root.style.setProperty('--sh-line-1', '#1A1D29');
      root.style.setProperty('--sh-line-2', '#232734');
      root.style.setProperty('--sh-line-3', '#2E3446');
      root.style.setProperty('--sh-ink-hi', '#F8FAFC');
      root.style.setProperty('--sh-ink-md', '#CBD5E1');
      root.style.setProperty('--sh-ink-lo', '#7B8496');
      root.style.setProperty('--sh-ink-mute', '#4A5263');
    }
  }
  function initTheme() {
    const saved = localStorage.getItem('sh_theme') || 'dark';
    applyTheme(saved);
    const btn = document.getElementById('shThemeBtn');
    if (btn) btn.addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-sh-theme') || 'dark';
      const next = cur === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      localStorage.setItem('sh_theme', next);
    });
  }

  // ============ COLLAPSE ============
  function initCollapse() {
    const key = 'sh_sidebar_collapsed';
    const shell = document.querySelector('.sh-shell');
    if (!shell) return;
    if (localStorage.getItem(key) === '1') shell.classList.add('is-collapsed');
    const btn = document.getElementById('shCollapseBtn');
    if (btn) btn.addEventListener('click', () => {
      shell.classList.toggle('is-collapsed');
      localStorage.setItem(key, shell.classList.contains('is-collapsed') ? '1' : '0');
    });
  }

  // ============ BREADCRUMB ============
  function setBreadcrumb(items) {
    const el = document.getElementById('shBreadcrumb');
    if (!el) return;
    if (!items || !items.length) { el.innerHTML = ''; return; }
    el.innerHTML = items.map((it, i) => {
      const isLast = i === items.length - 1;
      const crumb = it.href
        ? `<a href="${esc(it.href)}" class="crumb" style="color:inherit;text-decoration:none;">${esc(it.label)}</a>`
        : `<span class="crumb ${isLast ? 'active' : ''}">${esc(it.label)}</span>`;
      return (i > 0 ? '<span class="sep">/</span>' : '') + crumb;
    }).join('');
  }

  // ============ MONEY PULSE GAME ============
  async function refreshMoneyPulse() {
    try {
      const siteParam = S.currentSite ? '&site=' + encodeURIComponent(S.currentSite.site_key) : '';
      const today = localDateStr();
      const yest = localDateStr(new Date(Date.now() - 86400000));

      const [todayTotal, todayValid, yestTotal, yestValid] = await Promise.all([
        api(`/api/visits?from_date=${today}&to_date=${today}&per_page=1${siteParam}`).then(r => r.total || 0).catch(() => 0),
        api(`/api/visits?from_date=${today}&to_date=${today}&verdict=valid&per_page=1${siteParam}`).then(r => r.total || 0).catch(() => 0),
        api(`/api/visits?from_date=${yest}&to_date=${yest}&per_page=1${siteParam}`).then(r => r.total || 0).catch(() => 0),
        api(`/api/visits?from_date=${yest}&to_date=${yest}&verdict=valid&per_page=1${siteParam}`).then(r => r.total || 0).catch(() => 0),
      ]);

      const buyCpm = Number(S.user?.cpm_buy ?? 1.0);
      const sellCpm = Number(S.user?.cpm_sell ?? 1.5);
      const todayProfit = (todayValid * sellCpm / 1000) - (todayTotal * buyCpm / 1000);
      const yestProfit = (yestValid * sellCpm / 1000) - (yestTotal * buyCpm / 1000);

      let trendPct = 0;
      let trendDir = 'flat';
      if (Math.abs(yestProfit) > 0.01) {
        trendPct = ((todayProfit - yestProfit) / Math.abs(yestProfit)) * 100;
        if (trendPct > 5) trendDir = 'up';
        else if (trendPct < -5) trendDir = 'down';
      } else if (todayProfit > 0.01) trendDir = 'up';
      else if (todayProfit < -0.01) trendDir = 'down';

      const pulse = document.getElementById('shMoneyPulse');
      if (pulse) {
        const cls = todayProfit > 0.01 ? 'pos' : todayProfit < -0.01 ? 'neg' : 'zero';
        pulse.className = `sh-money-pulse ${cls}`;
        const valEl = pulse.querySelector('.sh-mp-value');
        if (valEl) valEl.textContent = fmtMoney(todayProfit);
        const trendEl = pulse.querySelector('.sh-mp-trend');
        if (trendEl) {
          if (trendDir === 'flat') {
            trendEl.textContent = '—';
            trendEl.className = 'sh-mp-trend flat';
          } else {
            const arrow = trendDir === 'up' ? '↑' : '↓';
            trendEl.textContent = `${arrow}${Math.abs(trendPct).toFixed(0)}%`;
            trendEl.className = `sh-mp-trend ${trendDir}`;
          }
        }
      }

      const visitsEl = document.getElementById('shStatusVisits');
      if (visitsEl) visitsEl.textContent = fmtNum(todayTotal) + ' زيارة';
      const profitEl = document.getElementById('shStatusProfit');
      if (profitEl) {
        profitEl.textContent = fmtMoney(todayProfit);
        profitEl.style.color = todayProfit > 0 ? 'var(--sh-green)' : todayProfit < 0 ? 'var(--sh-rose)' : 'var(--sh-ink-lo)';
      }
    } catch (err) {
      // silent
    }
  }

  // ============ ATTENTION ENGINE ============
  async function refreshAttentionCount() {
    try {
      const data = await api('/api/zones/actions/attention-count');
      const total = Number(data.total || 0);

      // Sidebar badges
      document.querySelectorAll('.sh-nav-badge').forEach(badge => {
        if (badge.dataset.badge === 'labeling') {
          if (data.labeling > 0) {
            badge.style.display = '';
            badge.textContent = data.labeling > 99 ? '99+' : data.labeling;
            const tier = data.labeling >= 10 ? 'tier-3' : data.labeling >= 5 ? 'tier-2' : 'tier-1';
            badge.className = 'sh-nav-badge ' + tier;
          } else {
            badge.style.display = 'none';
          }
        }
      });

      // Mobile badges
      document.querySelectorAll('.sh-mobile-badge').forEach(badge => {
        if (badge.dataset.mbadge === 'labeling') {
          if (data.labeling > 0) {
            badge.style.display = '';
            badge.textContent = data.labeling > 9 ? '9+' : data.labeling;
          } else {
            badge.style.display = 'none';
          }
        }
      });

      // Browser title
      if (total > 0) {
        document.title = `(${total}) ${S.baseTitle}`;
      } else {
        document.title = S.baseTitle;
      }
    } catch (err) {
      // silent
    }
  }

  // ============ QUICK ACTIONS ============
  function ensureQuickActions() {
    if (S.quickActionsEl) return S.quickActionsEl;
    const el = document.createElement('div');
    el.className = 'sh-qactions';
    el.id = 'shQactions';
    document.body.appendChild(el);
    S.quickActionsEl = el;
    return el;
  }

  function buildQuickActionsHTML(zoneId, zoneInfo) {
    const actions = [];
    const grade = zoneInfo.grade || '';
    const trust = zoneInfo.trust;

    // Conditional actions
    if (grade === 'F' || grade === 'D' || (trust !== undefined && trust < 40)) {
      actions.push({ id: 'blacklist', icon: 'ban', label: 'حظر فوري', cls: 'danger', kbd: 'X' });
    }
    actions.push({ id: 'pause', icon: 'pause', label: 'Pause 24h', cls: 'warn', kbd: 'P' });
    if (grade === 'S' || grade === 'A' || (trust !== undefined && trust > 70)) {
      actions.push({ id: 'scale', icon: 'scale', label: 'Scale +30%', cls: 'success', kbd: '+' });
    }
    actions.push({ id: 'details', icon: 'eye', label: 'التفاصيل', cls: '', kbd: '↵' });

    return `
      <div class="sh-qactions-head">${esc(zoneId)}</div>
      ${actions.map(a => `
        <button type="button" class="sh-qactions-item ${a.cls}" data-action="${a.id}">
          ${ICON[a.icon] || ''}
          <span>${esc(a.label)}</span>
          ${a.kbd ? `<span class="kbd">${esc(a.kbd)}</span>` : ''}
        </button>
      `).join('')}
    `;
  }

  function showQuickActions(targetEl) {
    const zoneId = targetEl.dataset.zoneId;
    if (!zoneId) return;

    const zoneInfo = {
      grade: targetEl.dataset.zoneGrade || '',
      trust: targetEl.dataset.zoneTrust ? Number(targetEl.dataset.zoneTrust) : undefined,
    };

    const menu = ensureQuickActions();
    menu.innerHTML = buildQuickActionsHTML(zoneId, zoneInfo);

    // Position
    const rect = targetEl.getBoundingClientRect();
    const menuW = 200;
    let left = rect.left - menuW - 8;
    if (left < 8) left = rect.right + 8;
    let top = rect.top;
    if (top + 200 > window.innerHeight) top = window.innerHeight - 210;

    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
    menu.classList.add('is-open');
    S.quickActionsTarget = targetEl;

    // Bind actions
    menu.querySelectorAll('.sh-qactions-item').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = btn.dataset.action;
        hideQuickActions();
        applyZoneAction(targetEl, zoneId, action);
      });
    });
  }

  function hideQuickActions() {
    if (S.quickActionsEl) S.quickActionsEl.classList.remove('is-open');
    S.quickActionsTarget = null;
  }

  async function applyZoneAction(targetEl, zoneId, action) {
    if (action === 'details') {
      window.location.href = `/smart-reports?zone=${encodeURIComponent(zoneId)}`;
      return;
    }

    // Optimistic UI
    const prev = targetEl.style.opacity;
    targetEl.style.opacity = '0.5';

    try {
      const res = await api(`/api/zones/${encodeURIComponent(zoneId)}/action`, {
        method: 'POST',
        body: JSON.stringify({
          action,
          reason: 'Quick Action',
          metadata: action === 'scale' ? { percent: 30 } : action === 'pause' ? { hours: 24 } : {},
        }),
      });

      const actionLabels = { blacklist: 'حظر', pause: 'Pause', scale: 'Scale +30%' };
      targetEl.classList.add('sh-action-applied');

      toast(`${actionLabels[action] || action} — ${zoneId}`, 'success', 5000, {
        undoLabel: 'تراجع',
        onUndo: async () => {
          try {
            await api(`/api/zones/${encodeURIComponent(zoneId)}/action/${res.id}`, { method: 'DELETE' });
            targetEl.classList.remove('sh-action-applied');
            targetEl.style.opacity = prev;
            toast('تم التراجع', 'info');
          } catch (e) {
            toast('فشل التراجع: ' + e.message, 'error');
          }
        },
      });
    } catch (err) {
      targetEl.style.opacity = prev;
      toast('فشل: ' + err.message, 'error');
    }
  }

  function initQuickActions() {
    let hoverTimer = null;
    let currentEl = null;

    document.addEventListener('mouseover', (e) => {
      const target = e.target.closest('[data-zone-id]');
      if (!target || target === currentEl) return;
      if (e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('#shQactions')) return;
      clearTimeout(hoverTimer);
      currentEl = target;
      hoverTimer = setTimeout(() => showQuickActions(target), 200);
    }, true);

    document.addEventListener('mouseout', (e) => {
      const target = e.target.closest('[data-zone-id]');
      if (!target) return;
      if (e.relatedTarget && (
        (e.relatedTarget.closest && e.relatedTarget.closest('#shQactions')) ||
        e.relatedTarget.closest?.('[data-zone-id]') === target
      )) return;
      clearTimeout(hoverTimer);
      hoverTimer = setTimeout(hideQuickActions, 250);
    }, true);

    // Keep open on menu hover
    document.addEventListener('mouseover', (e) => {
      if (e.target.closest && e.target.closest('#shQactions')) clearTimeout(hoverTimer);
    }, true);

    document.addEventListener('mouseout', (e) => {
      if (e.target.closest && e.target.closest('#shQactions') && !e.relatedTarget?.closest?.('#shQactions')) {
        clearTimeout(hoverTimer);
        hoverTimer = setTimeout(hideQuickActions, 250);
      }
    }, true);

    // Close on scroll
    window.addEventListener('scroll', hideQuickActions, { passive: true });
  }

  // ============ MOUNT ============
  async function mount(opts = {}) {
    if (S.mounted) return;
    S.active = opts.active || 'dashboard';
    S.lang = opts.lang || 'ar';
    S.currentSite = opts.currentSite || null;
    S.baseTitle = opts.title || document.title;

    document.body.classList.add('sh-body');
    if (S.lang === 'ar') {
      document.body.classList.add('ar');
      document.documentElement.setAttribute('dir', 'rtl');
      document.documentElement.setAttribute('lang', 'ar');
    }

    try { S.user = await api('/api/auth/me'); }
    catch (e) { throw new Error('فشل تحميل بيانات المستخدم: ' + e.message); }
    try { S.sites = await api('/api/sites'); }
    catch (e) { S.sites = []; }

    const appRoot = document.getElementById('shAppRoot');
    const contentEl = document.getElementById('shContent');
    if (!appRoot) throw new Error('Missing #shAppRoot in HTML');
    if (!contentEl) throw new Error('Missing #shContent in HTML');

    const innerContent = contentEl.innerHTML;
    appRoot.innerHTML = `
      <div class="sh-shell">
        ${buildSidebar()}
        <div class="sh-main">
          ${buildTopbar()}
          <main class="sh-content" id="shContentInner">${innerContent}</main>
          ${buildStatusbar()}
        </div>
        ${buildMobileNav()}
      </div>`;

    const cmdWrapper = document.createElement('div');
    cmdWrapper.innerHTML = buildCmdPalette();
    document.body.appendChild(cmdWrapper.firstElementChild);

    ensureToastContainer();
    initTheme();
    initCollapse();
    bindCmd();
    initQuickActions();

    const searchBtn = document.getElementById('shSearchBtn');
    if (searchBtn) searchBtn.addEventListener('click', openCmd);

    const moneyPulse = document.getElementById('shMoneyPulse');
    if (moneyPulse) {
      moneyPulse.addEventListener('click', () => {
        const today = localDateStr();
        const href = S.currentSite
          ? `/smart-reports?site=${encodeURIComponent(S.currentSite.site_key)}&from_date=${today}&to_date=${today}`
          : `/smart-reports?from_date=${today}&to_date=${today}`;
        window.location.href = href;
      });
    }

    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        openCmd();
      }
    });

    setBreadcrumb(opts.breadcrumb || [{ label: T[S.lang].nav }]);

    // Start polling
    refreshMoneyPulse();
    refreshAttentionCount();
    setInterval(refreshMoneyPulse, 30000);
    setInterval(refreshAttentionCount, 60000);

    S.mounted = true;
    return appRoot;
  }

  // ============ PUBLIC ============
  window.Shell = {
    mount,
    toast,
    openCmd,
    closeCmd,
    api,
    setBreadcrumb,
    refreshMoneyPulse,
    refreshAttentionCount,
    applyTheme,
    esc, fmtNum, fmtMoney, fmtPct, localDateStr,
    ICON,
    state: S,
  };
})();
