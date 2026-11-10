/**
 * neo-shell.js — OVG Tracker Neo Shell (v1.0)
 * Public API: window.Neo
 * Depends on: neo/tokens.css, neo/utilities.css, neo/components.css, neo/shell.css
 */
(function () {
  'use strict';

  const S = {
    user: null,
    campaigns: [],
    active: null,
    lang: 'ar',
    mounted: false,

    theme: 'dark',
    sidebarCollapsed: false,

    cmdOpen: false,
    cmdItems: [],
    cmdSelected: 0,
    cmdQuery: '',

    modalStack: [],
    drawer: null,

    pulse: null,
    pulseTimer: null,
    attentionTimer: null,

    quickActionsEl: null,
    quickActionsTarget: null,

    baseTitle: document.title,
    sse: null,
  };

  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmtNum = (n) => Number(n || 0).toLocaleString('en-US');
  const fmtMoney = (n) => {
    const v = Number(n || 0);
    if (Math.abs(v) < 0.005) return '$0.00';
    const sign = v > 0 ? '+' : (v < 0 ? '-' : '');
    return sign + '$' + Math.abs(v).toFixed(2);
  };
  const fmtPct = (n, d = 1) => Number(n || 0).toFixed(d) + '%';
  const localDateStr = (d) => {
    const dt = d || new Date();
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const day = String(dt.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  };

  // =========================================================
  // ICONS
  // =========================================================
  const ICON = {
    dashboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
    live: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2" fill="currentColor"/><circle cx="12" cy="12" r="6" opacity="0.6"/><circle cx="12" cy="12" r="10" opacity="0.3"/></svg>',
    radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/><path d="M12 2 L12 8"/></svg>',
    visits: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    sessions: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    labeling: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>',
    campaigns: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2" fill="currentColor"/></svg>',
    money: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>',
    analytics: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
    dataquality: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>',
    logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>',
    ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    pause: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>',
    scale: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>',
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    map: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>',
    refund: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>',
    award: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>',
    activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    history: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/></svg>',
    palette: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="13.5" cy="6.5" r="1.5" fill="currentColor"/><circle cx="17.5" cy="10.5" r="1.5" fill="currentColor"/><circle cx="8.5" cy="7.5" r="1.5" fill="currentColor"/><circle cx="6.5" cy="12.5" r="1.5" fill="currentColor"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125 0-.921.77-1.688 1.688-1.688h1.781C18.719 16.375 22 13.281 22 9.5 22 5.359 17.5 2 12 2z"/></svg>',
  };

  // =========================================================
  // NAV STRUCTURE
  // =========================================================
  const NAV = {
    ar: [
      { group: 'التحليل', items: [
        { id: 'dashboard',  label: 'لوحة التحكم', icon: 'dashboard',  href: '/v2/dashboard' },
        { id: 'live',       label: 'المراقبة المباشرة', icon: 'live',       href: '/live' },
        { id: 'radar',      label: 'الرادار',        icon: 'radar',      href: '/radar' },
        { id: 'visits',     label: 'الزيارات',     icon: 'visits',     href: '/visits' },
        { id: 'labeling',   label: 'المراجعة',     icon: 'labeling',   href: '/labeling', badge: 'labeling' },
        { id: 'sessions',   label: 'الجلسات',     icon: 'sessions',   href: '/sessions' },
      ]},
      { group: 'التحليل المتقدم', items: [
        { id: 'ip-lists', label: 'قوائم IP',          icon: 'shield', href: '/ip-lists' },
        { id: 'reports',  label: 'الخريطة والتقارير', icon: 'map',    href: '/reports' },
      ]},
      { group: 'الحملات', items: [
        { id: 'campaigns', label: 'كل الحملات',      icon: 'campaigns', href: '/campaigns' },
        { id: 'smart',     label: 'التقارير الذكية', icon: 'money',     href: '/v2/reports' },
        { id: 'analytics', label: 'تحليل المناطق',  icon: 'analytics', href: '/zone-analytics' },
      ]},
      { group: 'التقارير والإثباتات', items: [
        { id: 'popads-report',   label: 'استرداد PopAds', icon: 'refund', href: '/popads-report' },
        { id: 'adsterra-report', label: 'شهادة Adsterra',  icon: 'award',  href: '/adsterra-report' },
      ]},
      { group: 'النظام', items: [
        { id: 'system-health', label: 'حالة النظام',   icon: 'activity',    href: '/system-health' },
        { id: 'audit-log',     label: 'سجل الإجراءات', icon: 'history',     href: '/audit-log' },
        { id: 'dataquality',   label: 'جودة البيانات', icon: 'dataquality', href: '/data-quality' },
        { id: 'components',    label: 'مكتبة المكونات', icon: 'palette',     href: '/v2/components' },
        { id: 'settings',      label: 'الإعدادات',     icon: 'settings',    href: '/settings' },
      ]},
    ],
    en: [
      { group: 'Analyze', items: [
        { id: 'dashboard',  label: 'Dashboard',    icon: 'dashboard',  href: '/v2/dashboard' },
        { id: 'live',       label: 'Live Monitor', icon: 'live',       href: '/live' },
        { id: 'radar',      label: 'Radar',        icon: 'radar',      href: '/radar' },
        { id: 'visits',     label: 'Visits',       icon: 'visits',     href: '/visits' },
        { id: 'labeling',   label: 'Labeling',     icon: 'labeling',   href: '/labeling', badge: 'labeling' },
        { id: 'sessions',   label: 'Sessions',     icon: 'sessions',   href: '/sessions' },
      ]},
      { group: 'Deep Analysis', items: [
        { id: 'ip-lists', label: 'IP Lists',      icon: 'shield', href: '/ip-lists' },
        { id: 'reports',  label: 'Map & Reports', icon: 'map',    href: '/reports' },
      ]},
      { group: 'Campaigns', items: [
        { id: 'campaigns', label: 'All Campaigns',  icon: 'campaigns', href: '/campaigns' },
        { id: 'smart',     label: 'Smart Reports',  icon: 'money',     href: '/v2/reports' },
        { id: 'analytics', label: 'Zone Analytics', icon: 'analytics', href: '/zone-analytics' },
      ]},
      { group: 'Reports & Proofs', items: [
        { id: 'popads-report',   label: 'PopAds Refund',  icon: 'refund', href: '/popads-report' },
        { id: 'adsterra-report', label: 'Adsterra Proof', icon: 'award',  href: '/adsterra-report' },
      ]},
      { group: 'System', items: [
        { id: 'system-health', label: 'System Health',   icon: 'activity',    href: '/system-health' },
        { id: 'audit-log',     label: 'Audit Log',       icon: 'history',     href: '/audit-log' },
        { id: 'dataquality',   label: 'Data Quality',    icon: 'dataquality', href: '/data-quality' },
        { id: 'components',    label: 'Component Library', icon: 'palette',   href: '/v2/components' },
        { id: 'settings',      label: 'Settings',        icon: 'settings',    href: '/settings' },
      ]},
    ],
  };

  const T = {
    ar: { search: 'بحث سريع', searchPlaceholder: 'اكتب للبحث...', collapse: 'طوي القائمة', empty: 'لا توجد نتائج', nav: 'تنقّل', user: 'الحساب', logout: 'خروج' },
    en: { search: 'Quick search', searchPlaceholder: 'Type to search...', collapse: 'Collapse', empty: 'No results', nav: 'Navigate', user: 'Account', logout: 'Logout' },
  };

  // =========================================================
  // API
  // =========================================================
  async function api(url, opts = {}) {
    const res = await fetch(url, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      ...opts,
    });
    if (res.status === 401) {
      window.location.href = '/';
      throw new Error('Unauthorized');
    }
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const j = await res.json(); msg = j.detail || msg; } catch (_) {}
      throw new Error(msg);
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  // =========================================================
  // TOAST
  // =========================================================
  function ensureToastContainer() {
    let c = document.querySelector('.neo-toast-container');
    if (!c) {
      c = document.createElement('div');
      c.className = 'neo-toast-container';
      document.body.appendChild(c);
    }
    return c;
  }

  function toast(msg, type = 'info', duration = 2600, opts = {}) {
    const c = ensureToastContainer();
    const el = document.createElement('div');
    el.className = `neo-toast neo-${type}`;

    const icons = { success: '✓', error: '✕', info: 'ℹ' };
    const iconChar = icons[type] || 'ℹ';

    el.innerHTML = `
      <span class="neo-toast-icon">${iconChar}</span>
      <span class="neo-toast-body">${esc(msg)}</span>
      ${opts.undoLabel ? `<button class="neo-toast-undo" type="button">${esc(opts.undoLabel)}</button>` : ''}
    `;

    c.appendChild(el);

    if (opts.undoLabel && typeof opts.onUndo === 'function') {
      const btn = el.querySelector('.neo-toast-undo');
      if (btn) {
        btn.addEventListener('click', () => {
          try { opts.onUndo(); } catch (e) { console.warn(e); }
          el.classList.add('neo-hiding');
          setTimeout(() => el.remove(), 200);
        });
      }
    }

    // L-13: pause dismiss on hover
    let remaining = duration;
    let start = Date.now();
    let timer = setTimeout(hide, remaining);
    function hide() {
      if (el.parentNode) {
        el.classList.add('neo-hiding');
        setTimeout(() => el.remove(), 200);
      }
    }
    el.addEventListener('mouseenter', () => {
      clearTimeout(timer);
      remaining -= (Date.now() - start);
    });
    el.addEventListener('mouseleave', () => {
      start = Date.now();
      timer = setTimeout(hide, Math.max(remaining, 800));
    });
  }

  // =========================================================
  // THEME
  // =========================================================
  function setTheme(theme) {
    S.theme = theme === 'light' ? 'light' : 'dark';
    if (S.theme === 'light') {
      document.documentElement.setAttribute('data-neo-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-neo-theme');
    }
    try { localStorage.setItem('neo_theme', S.theme); } catch (e) {}

    const btn = document.getElementById('neoThemeBtn');
    if (btn) btn.innerHTML = S.theme === 'dark' ? ICON.moon : ICON.sun;
  }

  function initTheme() {
    let saved = 'dark';
    try { saved = localStorage.getItem('neo_theme') || 'dark'; } catch (e) {}
    setTheme(saved);

    const btn = document.getElementById('neoThemeBtn');
    if (btn) {
      btn.addEventListener('click', () => {
        setTheme(S.theme === 'dark' ? 'light' : 'dark');
      });
    }
  }

  // =========================================================
  // SIDEBAR COLLAPSE
  // =========================================================
  function initSidebarCollapse() {
    const key = 'neo_sidebar_collapsed';
    const shell = document.querySelector('.neo-shell');
    if (!shell) return;

    try {
      if (localStorage.getItem(key) === '1') {
        shell.classList.add('neo-collapsed');
        S.sidebarCollapsed = true;
      }
    } catch (e) {}

    const btn = document.getElementById('neoCollapseBtn');
    if (btn) {
      btn.addEventListener('click', () => {
        shell.classList.toggle('neo-collapsed');
        S.sidebarCollapsed = shell.classList.contains('neo-collapsed');
        try { localStorage.setItem(key, S.sidebarCollapsed ? '1' : '0'); } catch (e) {}
      });
    }
  }

  // =========================================================
  // BUILD SIDEBAR
  // =========================================================
  function buildSidebar() {
    const L = T[S.lang];
    const nav = NAV[S.lang] || NAV.ar;
    let itemsHtml = '';

    nav.forEach(group => {
      itemsHtml += `<div class="neo-nav-group"><div class="neo-nav-group-label">${esc(group.group)}</div>`;
      group.items.forEach(it => {
        const isActive = S.active === it.id ? 'neo-active' : '';
        const badgeHtml = it.badge ? `<span class="neo-nav-badge" data-badge="${esc(it.badge)}" style="display:none;">0</span>` : '';
        itemsHtml += `<a href="${esc(it.href)}" class="neo-nav-item ${isActive}" data-nav="${esc(it.id)}">${ICON[it.icon] || ''}<span class="neo-nav-item-label">${esc(it.label)}</span>${badgeHtml}</a>`;
      });
      itemsHtml += `</div>`;
    });

    const initial = (S.user && S.user.username ? S.user.username[0] : '?').toUpperCase();
    const username = S.user ? S.user.username : '—';

    return `
      <aside class="neo-sidebar" id="neoSidebar">
        <div class="neo-sidebar-head">
          <div class="neo-logo">O</div>
          <div class="neo-logo-text">
            <div class="neo-logo-text-title">OVG Tracker</div>
            <div class="neo-logo-text-subtitle">v10 · NEO</div>
          </div>
        </div>
        <nav class="neo-nav">${itemsHtml}</nav>
        <div class="neo-sidebar-foot">
          <a href="/settings" class="neo-user">
            <div class="neo-avatar">${esc(initial)}</div>
            <div class="neo-user-info">
              <div class="neo-user-name">${esc(username)}</div>
              <div class="neo-user-role">${esc(L.user)}</div>
            </div>
          </a>
        </div>
        <button class="neo-collapse-btn" id="neoCollapseBtn" aria-label="${esc(L.collapse)}" title="${esc(L.collapse)}">${ICON.chevron}</button>
      </aside>
    `;
  }

  // =========================================================
  // BUILD TOPBAR
  // =========================================================
  function buildTopbar() {
    const L = T[S.lang];
    return `
      <header class="neo-topbar">
        <div class="neo-breadcrumb" id="neoBreadcrumb"></div>
        <div class="neo-topbar-spacer"></div>
        <button class="neo-topbar-btn neo-search-btn" id="neoSearchBtn" type="button">
          ${ICON.search}
          <span>${esc(L.search)}</span>
          <kbd>⌘K</kbd>
        </button>
        <button class="neo-money-pulse neo-zero" id="neoMoneyPulse" title="الربح اليوم" type="button">
          <span class="neo-pulse-dot"></span>
          <span class="neo-mp-value">$0.00</span>
          <span class="neo-mp-trend neo-flat">—</span>
        </button>
        <button class="neo-topbar-btn" id="neoThemeBtn" title="Theme" aria-label="Toggle theme" type="button">${ICON.moon}</button>
      </header>
    `;
  }

  // =========================================================
  // BUILD STATUSBAR
  // =========================================================
  function buildStatusbar() {
    return `
      <footer class="neo-statusbar">
        <span class="neo-status-item"><span class="neo-status-dot"></span>LIVE</span>
        <span class="neo-status-item" id="neoStatusVisits">— اليوم</span>
        <span class="neo-status-item" id="neoStatusProfit">—</span>
        <span class="neo-status-spacer"></span>
        <span class="neo-status-item">⌘K بحث</span>
        <span class="neo-status-item">NEO v1.0</span>
      </footer>
    `;
  }

  // =========================================================
  // BUILD MOBILE NAV
  // =========================================================
  function buildMobileNav() {
    const nav = (NAV[S.lang] || NAV.ar)[0].items.slice(0, 5);
    return `
      <nav class="neo-mobile-nav">
        ${nav.map(it => `
          <a href="${esc(it.href)}" class="neo-mobile-nav-item ${S.active === it.id ? 'neo-active' : ''}">
            ${ICON[it.icon] || ''}<span>${esc(it.label)}</span>
          </a>
        `).join('')}
      </nav>
    `;
  }

  // =========================================================
  // COMMAND PALETTE
  // =========================================================
  function buildCmdPalette() {
    return `
      <div class="neo-cmd-overlay" id="neoCmdOverlay">
        <div class="neo-cmd">
          <div class="neo-cmd-input-wrap">
            ${ICON.search}
            <input type="text" class="neo-cmd-input" id="neoCmdInput" placeholder="${esc(T[S.lang].searchPlaceholder)}" autocomplete="off">
            <kbd style="padding:2px 6px;background:var(--neo-bg-canvas);border:1px solid var(--neo-border-default);border-radius:3px;font-family:var(--neo-font-mono);font-size:9px;color:var(--neo-fg-muted);">ESC</kbd>
          </div>
          <div class="neo-cmd-results" id="neoCmdResults"></div>
        </div>
      </div>
    `;
  }

  function buildCommands() {
    const nav = (NAV[S.lang] || NAV.ar).flatMap(g => g.items);
    const cmds = [];

    nav.forEach(it => {
      cmds.push({
        group: T[S.lang].nav,
        label: it.label,
        icon: it.icon,
        action: () => { window.location.href = it.href; },
      });
    });

    if (S.campaigns && S.campaigns.length) {
      S.campaigns.slice(0, 5).forEach(c => {
        cmds.push({
          group: 'الحملات',
          label: c.name,
          desc: '🎯',
          action: () => { window.location.href = '/campaigns/' + c.id; },
        });
      });
    }

    cmds.push({
      group: T[S.lang].user,
      label: T[S.lang].logout,
      icon: 'logout',
      action: async () => {
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
        window.location.href = '/';
      },
    });

    return cmds;
  }

  function renderCmdResults() {
    const container = document.getElementById('neoCmdResults');
    if (!container) return;

    const q = S.cmdQuery.trim().toLowerCase();
    const all = buildCommands();
    const filtered = q
      ? all.filter(c => c.label.toLowerCase().includes(q) || (c.desc || '').toLowerCase().includes(q))
      : all.slice(0, 12);

    S.cmdItems = filtered;
    if (S.cmdSelected >= filtered.length) S.cmdSelected = Math.max(0, filtered.length - 1);

    if (!filtered.length) {
      container.innerHTML = `<div class="neo-cmd-empty">${esc(T[S.lang].empty)}</div>`;
      return;
    }

    let html = '';
    let lastGroup = null;

    filtered.forEach((c, i) => {
      if (c.group !== lastGroup) {
        html += `<div class="neo-cmd-group-label">${esc(c.group)}</div>`;
        lastGroup = c.group;
      }
      const sel = i === S.cmdSelected ? 'neo-selected' : '';
      html += `<div class="neo-cmd-item ${sel}" data-idx="${i}">${c.icon ? ICON[c.icon] || '' : '<span style="width:14px;"></span>'}<span>${esc(c.label)}</span>${c.desc ? `<span class="neo-desc">${esc(c.desc)}</span>` : ''}</div>`;
    });

    container.innerHTML = html;

    container.querySelectorAll('.neo-cmd-item').forEach(el => {
      el.addEventListener('click', () => {
        const i = Number(el.dataset.idx);
        const c = S.cmdItems[i];
        if (c && c.action) {
          closeCmd();
          setTimeout(c.action, 80);
        }
      });
      el.addEventListener('mouseenter', () => {
        S.cmdSelected = Number(el.dataset.idx);
        renderCmdResults();
      });
    });
  }

  function openCmd() {
    S.cmdOpen = true;
    S.cmdQuery = '';
    S.cmdSelected = 0;
    const ov = document.getElementById('neoCmdOverlay');
    if (!ov) return;
    ov.classList.add('neo-open');
    const inp = document.getElementById('neoCmdInput');
    if (inp) {
      inp.value = '';
      setTimeout(() => inp.focus(), 30);
    }
    renderCmdResults();
  }

  function closeCmd() {
    S.cmdOpen = false;
    const ov = document.getElementById('neoCmdOverlay');
    if (ov) ov.classList.remove('neo-open');
  }

  function bindCmd() {
    const inp = document.getElementById('neoCmdInput');
    if (!inp) return;

    inp.addEventListener('input', (e) => {
      S.cmdQuery = e.target.value;
      S.cmdSelected = 0;
      renderCmdResults();
    });

    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { closeCmd(); e.preventDefault(); }
      else if (e.key === 'ArrowDown') { S.cmdSelected = Math.min(S.cmdSelected + 1, S.cmdItems.length - 1); renderCmdResults(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { S.cmdSelected = Math.max(S.cmdSelected - 1, 0); renderCmdResults(); e.preventDefault(); }
      else if (e.key === 'Enter') { const c = S.cmdItems[S.cmdSelected]; if (c && c.action) { closeCmd(); setTimeout(c.action, 80); } e.preventDefault(); }
    });

    const overlay = document.getElementById('neoCmdOverlay');
    if (overlay) overlay.addEventListener('click', (e) => { if (e.target.id === 'neoCmdOverlay') closeCmd(); });
  }

  // =========================================================
  // BREADCRUMB
  // =========================================================
  function setBreadcrumb(items) {
    const el = document.getElementById('neoBreadcrumb');
    if (!el) return;
    if (!items || !items.length) { el.innerHTML = ''; return; }

    el.innerHTML = items.map((it, i) => {
      const isLast = i === items.length - 1;
      const crumb = it.href
        ? `<a href="${esc(it.href)}" class="neo-crumb" style="color:inherit;text-decoration:none;">${esc(it.label)}</a>`
        : `<span class="neo-crumb ${isLast ? 'neo-active' : ''}">${esc(it.label)}</span>`;
      return (i > 0 ? '<span class="neo-sep">/</span>' : '') + crumb;
    }).join('');
  }

  // =========================================================
  // MONEY PULSE
  // =========================================================
  async function refreshMoneyPulse() {
    try {
      const pulse = await api('/api/stats/pulse');
      S.pulse = pulse;

      const today = pulse.today || {};
      const yest = pulse.yesterday || {};
      const todayProfit = Number(today.profit || 0);
      const yestProfit = Number(yest.profit || 0);
      const source = today.source || 'unknown';
      const integrity = (today.integrity && today.integrity.integrity) || 'unknown';

      let trendPct = 0;
      let trendDir = 'flat';
      if (Math.abs(yestProfit) > 0.01) {
        trendPct = ((todayProfit - yestProfit) / Math.abs(yestProfit)) * 100;
        if (trendPct > 5) trendDir = 'up';
        else if (trendPct < -5) trendDir = 'down';
      } else if (todayProfit > 0.01) trendDir = 'up';
      else if (todayProfit < -0.01) trendDir = 'down';

      const el = document.getElementById('neoMoneyPulse');
      if (el) {
        const cls = todayProfit > 0.01 ? 'neo-pos' : todayProfit < -0.01 ? 'neo-neg' : 'neo-zero';
        el.className = `neo-money-pulse ${cls}`;

        const estimated = (source === 'cpm' || source === 'unknown' || integrity !== 'exact');
        const indicator = estimated ? ' *' : '';

        const valEl = el.querySelector('.neo-mp-value');
        if (valEl) valEl.textContent = fmtMoney(todayProfit) + indicator;

        const trendEl = el.querySelector('.neo-mp-trend');
        if (trendEl) {
          if (trendDir === 'flat') {
            trendEl.textContent = '—';
            trendEl.className = 'neo-mp-trend neo-flat';
          } else {
            const arrow = trendDir === 'up' ? '↑' : '↓';
            trendEl.textContent = `${arrow}${Math.abs(trendPct).toFixed(0)}%`;
            trendEl.className = `neo-mp-trend neo-${trendDir}`;
          }
        }

        let title = `الربح اليوم: ${fmtMoney(todayProfit)}`;
        if (source === 'cpm') title += ' — تقدير بالـ CPM';
        else if (source === 'exact_partial') title += ' — محسوب من BID جزئي';
        else if (source === 'exact') title += ' — محسوب من BID الحقيقي';
        else title += ' — مفيش بيانات كافية';
        el.title = title;
      }

      const visitsEl = document.getElementById('neoStatusVisits');
      if (visitsEl) visitsEl.textContent = fmtNum(today.visits || 0) + ' زيارة';

      const profitEl = document.getElementById('neoStatusProfit');
      if (profitEl) {
        profitEl.textContent = fmtMoney(todayProfit);
        profitEl.style.color = todayProfit > 0
          ? 'var(--neo-success)'
          : todayProfit < 0
            ? 'var(--neo-danger)'
            : 'var(--neo-fg-tertiary)';
      }
    } catch (err) {
      // Silent
    }
  }

  // =========================================================
  // ATTENTION BADGE
  // =========================================================
  async function refreshAttention() {
    try {
      const data = await api('/api/zones/actions/attention-count');
      const total = Number(data.total || 0);

      document.querySelectorAll('.neo-nav-badge').forEach(badge => {
        if (badge.dataset.badge === 'labeling') {
          if (data.labeling > 0) {
            badge.style.display = '';
            badge.textContent = data.labeling > 99 ? '99+' : data.labeling;
            const tier = data.labeling >= 10 ? 'neo-tier-3' : data.labeling >= 5 ? 'neo-tier-2' : 'neo-tier-1';
            badge.className = 'neo-nav-badge ' + tier;
          } else {
            badge.style.display = 'none';
          }
        }
      });

      if (total > 0) {
        document.title = `(${total}) ${S.baseTitle}`;
      } else {
        document.title = S.baseTitle;
      }
    } catch (err) {
      // Silent
    }
  }

  // =========================================================
  // MODAL HELPERS
  // =========================================================
  function openModal(id) {
    const wrap = document.getElementById(id);
    if (!wrap) return;
    wrap.classList.add('neo-open');
    document.body.classList.add('neo-modal-open');
    if (!S.modalStack.includes(id)) S.modalStack.push(id);
  }

  function closeModal(id) {
    const wrap = document.getElementById(id);
    if (!wrap) return;
    wrap.classList.remove('neo-open');
    S.modalStack = S.modalStack.filter(x => x !== id);
    if (S.modalStack.length === 0) {
      document.body.classList.remove('neo-modal-open');
    }
  }

  // =========================================================
  // DRAWER HELPERS
  // =========================================================
  function openDrawer(id) {
    const wrap = document.getElementById(id);
    if (!wrap) return;
    wrap.classList.add('neo-open');
    document.body.classList.add('neo-modal-open');
    S.drawer = id;
  }

  function closeDrawer(id) {
    const targetId = id || S.drawer;
    if (!targetId) return;
    const wrap = document.getElementById(targetId);
    if (wrap) wrap.classList.remove('neo-open');
    S.drawer = null;
    if (S.modalStack.length === 0) {
      document.body.classList.remove('neo-modal-open');
    }
  }

  // =========================================================
  // QUICK ACTIONS (click-based — mobile friendly)
  // =========================================================
  function ensureQuickActions() {
    if (S.quickActionsEl) return S.quickActionsEl;
    const el = document.createElement('div');
    el.className = 'neo-qactions';
    el.id = 'neoQactions';
    document.body.appendChild(el);
    S.quickActionsEl = el;
    return el;
  }

  function buildQuickActionsHTML(zoneId, zoneInfo) {
    const actions = [];
    const grade = zoneInfo.grade || '';
    const trust = zoneInfo.trust;

    if (grade === 'F' || grade === 'D' || (trust !== undefined && trust < 40)) {
      actions.push({ id: 'blacklist', icon: 'ban', label: 'حظر فوري', cls: 'neo-danger', kbd: 'X' });
    }
    actions.push({ id: 'pause', icon: 'pause', label: 'إيقاف 24 ساعة', cls: 'neo-warning', kbd: 'P' });
    if (grade === 'S' || grade === 'A' || (trust !== undefined && trust > 70)) {
      actions.push({ id: 'scale', icon: 'scale', label: 'زيادة 30%', cls: 'neo-success', kbd: '+' });
    }
    actions.push({ id: 'details', icon: 'eye', label: 'التفاصيل', cls: '', kbd: '↵' });

    return `
      <div class="neo-qactions-head">${esc(zoneId)}</div>
      ${actions.map(a => `
        <button type="button" class="neo-qactions-item ${a.cls}" data-action="${a.id}">
          ${ICON[a.icon] || ''}
          <span>${esc(a.label)}</span>
          ${a.kbd ? `<span class="neo-kbd">${esc(a.kbd)}</span>` : ''}
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

    const rect = targetEl.getBoundingClientRect();
    const menuW = 200;
    const menuH = Math.min(menu.offsetHeight || 200, 280);
    let left = rect.left - menuW - 8;
    if (left < 8) left = Math.min(rect.right + 8, window.innerWidth - menuW - 8);
    left = Math.max(8, Math.min(left, window.innerWidth - menuW - 8)); // L-15
    let top = rect.top;
    if (top + menuH > window.innerHeight - 8) top = window.innerHeight - menuH - 8;
    top = Math.max(8, top);

    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
    menu.classList.add('neo-open');
    S.quickActionsTarget = targetEl;

    menu.querySelectorAll('.neo-qactions-item').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = btn.dataset.action;
        hideQuickActions();
        applyZoneAction(targetEl, zoneId, action);
      });
    });
  }

  function hideQuickActions() {
    if (S.quickActionsEl) S.quickActionsEl.classList.remove('neo-open');
    S.quickActionsTarget = null;
  }

  async function applyZoneAction(targetEl, zoneId, action) {
    if (action === 'details') {
      window.location.href = `/v2/reports?zone=${encodeURIComponent(zoneId)}`;
      return;
    }

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

      const actionLabels = { blacklist: 'حظر', pause: 'إيقاف', scale: 'زيادة 30%' };
      targetEl.classList.add('neo-action-applied');

      toast(`${actionLabels[action] || action} — ${zoneId}`, 'success', 5000, {
        undoLabel: 'تراجع',
        onUndo: async () => {
          try {
            await api(`/api/zones/${encodeURIComponent(zoneId)}/action/${res.id}`, { method: 'DELETE' });
            targetEl.classList.remove('neo-action-applied');
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

  function bindQuickActions() {
    // Hover with delay (desktop)
    let hoverTimer = null;
    let currentEl = null;

    document.addEventListener('mouseover', (e) => {
      const target = e.target.closest('[data-zone-id]');
      if (!target || target === currentEl) return;
      if (e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('#neoQactions')) return;
      clearTimeout(hoverTimer);
      currentEl = target;
      hoverTimer = setTimeout(() => showQuickActions(target), 200);
    }, true);

    document.addEventListener('mouseout', (e) => {
      const target = e.target.closest('[data-zone-id]');
      if (!target) return;
      if (e.relatedTarget && ((e.relatedTarget.closest && e.relatedTarget.closest('#neoQactions')) || e.relatedTarget.closest?.('[data-zone-id]') === target)) return;
      clearTimeout(hoverTimer);
      hoverTimer = setTimeout(hideQuickActions, 250);
    }, true);

    document.addEventListener('mouseover', (e) => {
      if (e.target.closest && e.target.closest('#neoQactions')) clearTimeout(hoverTimer);
    }, true);

    document.addEventListener('mouseout', (e) => {
      if (e.target.closest && e.target.closest('#neoQactions') && !e.relatedTarget?.closest?.('#neoQactions')) {
        clearTimeout(hoverTimer);
        hoverTimer = setTimeout(hideQuickActions, 250);
      }
    }, true);

    // Click (mobile + explicit)
    document.addEventListener('click', (e) => {
      // Close if clicking outside
      if (!e.target.closest('#neoQactions') && !e.target.closest('[data-zone-id]')) {
        hideQuickActions();
      }
    });

    // Long-press for mobile
    let longPressTimer = null;
    document.addEventListener('touchstart', (e) => {
      const target = e.target.closest('[data-zone-id]');
      if (!target) return;
      longPressTimer = setTimeout(() => showQuickActions(target), 500);
    }, { passive: true });

    document.addEventListener('touchend', () => {
      if (longPressTimer) clearTimeout(longPressTimer);
    }, { passive: true });

    window.addEventListener('scroll', hideQuickActions, { passive: true });
  }

  // =========================================================
  // SSE HELPERS
  // =========================================================
  function openSSE(url, handlers = {}) {
    closeSSE();
    if (typeof EventSource === 'undefined') {
      console.warn('[Neo SSE] EventSource not supported');
      return null;
    }
    try {
      const es = new EventSource(url, { withCredentials: true });
      S.sse = es;
      if (handlers.onOpen) es.addEventListener('open', handlers.onOpen);
      if (handlers.onVisits) es.addEventListener('visits', (e) => {
        try { handlers.onVisits(JSON.parse(e.data)); } catch (err) { console.error(err); }
      });
      if (handlers.onHeartbeat) es.addEventListener('heartbeat', handlers.onHeartbeat);
      if (handlers.onReconnect) es.addEventListener('reconnect', handlers.onReconnect);
      if (handlers.onError) es.addEventListener('error', handlers.onError);
      return es;
    } catch (e) {
      console.error('[Neo SSE] failed:', e);
      return null;
    }
  }

  function closeSSE() {
    if (S.sse) {
      try { S.sse.close(); } catch (e) {}
      S.sse = null;
    }
  }

  // =========================================================
  // MOUNT
  // =========================================================
  async function mount(opts = {}) {
    // L-12: prevent concurrent mount
    if (S.mounted || S._mounting) return null;
    S._mounting = true;

    S.active = opts.active || 'dashboard';
    S.lang = opts.lang || 'ar';
    S.baseTitle = opts.title || document.title;

    document.body.classList.add('neo-body');
    if (S.lang === 'ar') {
      document.body.classList.add('ar');
      document.documentElement.setAttribute('dir', 'rtl');
      document.documentElement.setAttribute('lang', 'ar');
    } else {
      document.documentElement.setAttribute('dir', 'ltr');
      document.documentElement.setAttribute('lang', 'en');
    }

    // Fetch user + campaigns (parallel)
    try {
      S.user = await api('/api/auth/me');
    } catch (e) {
      throw new Error('فشل تحميل بيانات المستخدم: ' + e.message);
    }

    try {
      S.campaigns = await api('/api/campaigns');
    } catch (e) {
      S.campaigns = [];
    }

    const appRoot = document.getElementById('neoAppRoot');
    const contentEl = document.getElementById('neoContent');
    if (!appRoot) throw new Error('Missing #neoAppRoot in HTML');
    if (!contentEl) throw new Error('Missing #neoContent in HTML');

    const innerContent = contentEl.innerHTML;

    appRoot.innerHTML = `
      <div class="neo-shell">
        ${buildSidebar()}
        <div class="neo-main">
          ${buildTopbar()}
          <main class="neo-content" id="neoContentInner">${innerContent}</main>
          ${buildStatusbar()}
        </div>
        ${buildMobileNav()}
      </div>
    `;

    // Command palette
    const cmdWrapper = document.createElement('div');
    cmdWrapper.innerHTML = buildCmdPalette();
    document.body.appendChild(cmdWrapper.firstElementChild);

    ensureToastContainer();
    initTheme();
    initSidebarCollapse();
    bindCmd();
    bindQuickActions();

    const searchBtn = document.getElementById('neoSearchBtn');
    if (searchBtn) searchBtn.addEventListener('click', openCmd);

    const moneyPulse = document.getElementById('neoMoneyPulse');
    if (moneyPulse) {
      moneyPulse.addEventListener('click', () => {
        window.location.href = '/smart-reports';
      });
    }

    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        openCmd();
      }
    });

    setBreadcrumb(opts.breadcrumb || [{ label: T[S.lang].nav }]);

    refreshMoneyPulse();
    refreshAttention();
    S.pulseTimer = setInterval(function(){ if (!document.hidden) refreshMoneyPulse(); }, 30000);  /* L-14 */
    S.attentionTimer = setInterval(function(){ if (!document.hidden) refreshAttention(); }, 60000);  /* M-53 */

    S.mounted = true; S._mounting = false;
    return appRoot;
  }

  // =========================================================
  // PUBLIC API
  // =========================================================
  window.Neo = {
    mount,
    api,
    toast,
    setBreadcrumb,
    openModal,
    closeModal,
    openDrawer,
    closeDrawer,
    openCmd,
    closeCmd,
    setTheme,
    refreshMoneyPulse,
    refreshAttention,
    openSSE,
    closeSSE,
    formatNumber: fmtNum,
    formatMoney: fmtMoney,
    formatPercent: fmtPct,
    formatDate: localDateStr,
    escape: esc,
    ICON,
    state: S,
  };
})();