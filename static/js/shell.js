/**
 * shell.js — OVG Tracker v9 Shell (Campaign-Centric)
 */
(function () {
  'use strict';

  const S = {
    user: null, campaigns: [], active: null, lang: 'ar',
    mounted: false, cmdOpen: false, cmdItems: [], cmdSelected: 0, cmdQuery: '',
    baseTitle: document.title, attentionTimer: null, pulseTimer: null,
    quickActionsEl: null, quickActionsTarget: null,
    pulse: null,
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
    code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
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

  const NAV = {
    ar: [
      { group: 'التحليل', items: [
        { id: 'dashboard', label: 'لوحة التحكم', icon: 'dashboard', href: '/dashboard' },
        { id: 'live',      label: 'Live Monitor', icon: 'live',      href: '/live' },
        { id: 'radar',     label: 'Radar',        icon: 'radar',     href: '/radar' },
        { id: 'visits',    label: 'الزيارات',     icon: 'visits',    href: '/visits' },
        { id: 'labeling',  label: 'المراجعة',     icon: 'labeling',  href: '/labeling', badge: 'labeling' },
        { id: 'sessions',  label: 'Sessions',     icon: 'sessions',  href: '/sessions' },
      ]},
      { group: 'التحليل المتقدم', items: [
        { id: 'ip-lists',  label: 'قوائم IP',         icon: 'shield',  href: '/ip-lists' },
        { id: 'reports',   label: 'الخريطة والتقارير', icon: 'map',     href: '/reports' },
      ]},
      { group: 'الحملات', items: [
        { id: 'campaigns', label: 'كل الحملات',     icon: 'campaigns', href: '/campaigns' },
        { id: 'smart',     label: 'التقارير الذكية', icon: 'money',     href: '/smart-reports' },
        { id: 'analytics', label: 'Zone Analytics',  icon: 'analytics', href: '/zone-analytics' },
      ]},
      { group: 'التقارير والإثباتات', items: [
        { id: 'popads-report',   label: 'استرداد PopAds',  icon: 'refund', href: '/popads-report' },
        { id: 'adsterra-report', label: 'شهادة Adsterra',   icon: 'award',  href: '/adsterra-report' },
      ]},
      { group: 'النظام', items: [
        { id: 'system-health', label: 'حالة النظام',        icon: 'activity',    href: '/system-health' },
        { id: 'audit-log',     label: 'سجل الإجراءات',      icon: 'history',     href: '/audit-log' },
        { id: 'dataquality',   label: 'جودة البيانات',      icon: 'dataquality', href: '/data-quality' },
        { id: 'components',    label: 'مكتبة المكونات 🆕',  icon: 'palette',     href: '/v2/components' },
        { id: 'settings',      label: 'الإعدادات',          icon: 'settings',    href: '/settings' },
      ]},
    ],
    en: [
      { group: 'Analyze', items: [
        { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', href: '/dashboard' },
        { id: 'live',      label: 'Live Monitor', icon: 'live', href: '/live' },
        { id: 'radar',     label: 'Radar',     icon: 'radar',     href: '/radar' },
        { id: 'visits',    label: 'Visits',    icon: 'visits',    href: '/visits' },
        { id: 'labeling',  label: 'Labeling',  icon: 'labeling',  href: '/labeling', badge: 'labeling' },
        { id: 'sessions',  label: 'Sessions',  icon: 'sessions',  href: '/sessions' },
      ]},
      { group: 'Deep Analysis', items: [
        { id: 'ip-lists',  label: 'IP Lists',      icon: 'shield',  href: '/ip-lists' },
        { id: 'reports',   label: 'Map & Reports', icon: 'map',     href: '/reports' },
      ]},
      { group: 'Campaigns', items: [
        { id: 'campaigns', label: 'All Campaigns',  icon: 'campaigns', href: '/campaigns' },
        { id: 'smart',     label: 'Smart Reports',  icon: 'money',     href: '/smart-reports' },
        { id: 'analytics', label: 'Zone Analytics', icon: 'analytics', href: '/zone-analytics' },
      ]},
      { group: 'Reports & Proofs', items: [
        { id: 'popads-report',   label: 'PopAds Refund',   icon: 'refund', href: '/popads-report' },
        { id: 'adsterra-report', label: 'Adsterra Proof',  icon: 'award',  href: '/adsterra-report' },
      ]},
      { group: 'System', items: [
        { id: 'system-health', label: 'System Health',    icon: 'activity',    href: '/system-health' },
        { id: 'audit-log',     label: 'Audit Log',        icon: 'history',     href: '/audit-log' },
        { id: 'dataquality',   label: 'Data Quality',     icon: 'dataquality', href: '/data-quality' },
        { id: 'components',    label: 'Components 🆕',    icon: 'palette',     href: '/v2/components' },
        { id: 'settings',      label: 'Settings',         icon: 'settings',    href: '/settings' },
      ]},
    ],
  };

  const T = {
    ar: { search: 'بحث سريع', searchPlaceholder: 'اكتب للبحث...', collapse: 'طوي القائمة', empty: 'لا توجد نتائج', nav: 'تنقّل', user: 'الحساب', logout: 'خروج', attnTooltip: 'محتاج انتباه' },
    en: { search: 'Quick search', searchPlaceholder: 'Type to search...', collapse: 'Collapse', empty: 'No results', nav: 'Navigate', user: 'Account', logout: 'Logout', attnTooltip: 'Needs attention' },
  };

  function buildSidebar() {
    const L = T[S.lang]; const nav = NAV[S.lang] || NAV.ar; let itemsHtml = '';
    nav.forEach(group => {
      itemsHtml += `<div class="sh-nav-group"><div class="sh-nav-label">${esc(group.group)}</div>`;
      group.items.forEach(it => {
        const isActive = S.active === it.id ? 'active' : '';
        const badgeHtml = it.badge ? `<span class="sh-nav-badge" data-badge="${esc(it.badge)}" style="display:none;">0</span>` : '';
        const livePulse = it.id === 'live' ? '<span class="sh-nav-live-dot" style="display:inline-block;width:6px;height:6px;border-radius:50%;background:#F43F5E;margin-right:6px;box-shadow:0 0 6px #F43F5E;animation:sh-live-pulse 1.5s ease-in-out infinite;"></span>' : '';
        itemsHtml += `<a href="${esc(it.href)}" class="sh-nav-item ${isActive}" data-nav="${esc(it.id)}">${ICON[it.icon] || ''}<span class="label">${livePulse}${esc(it.label)}</span>${badgeHtml}</a>`;
      });
      itemsHtml += `</div>`;
    });
    const initial = (S.user && S.user.username ? S.user.username[0] : '?').toUpperCase();
    const username = S.user ? S.user.username : '—';
    return `<aside class="sh-sidebar" id="shSidebar"><div class="sh-sidebar-head"><div class="sh-logo">O</div><div class="sh-logo-text"><div class="t1">OVG Tracker</div><div class="t2">v9 · PRO</div></div></div><nav class="sh-nav">${itemsHtml}</nav><div class="sh-sidebar-foot"><a href="/settings" class="sh-user"><div class="sh-avatar">${esc(initial)}</div><div class="sh-user-info"><div class="n">${esc(username)}</div><div class="r">${esc(L.user)}</div></div></a></div><button class="sh-collapse-btn" id="shCollapseBtn" aria-label="${esc(L.collapse)}" title="${esc(L.collapse)}">${ICON.chevron}</button></aside>`;
  }

  function buildTopbar() {
    const L = T[S.lang];
    return `<header class="sh-topbar"><div class="sh-breadcrumb" id="shBreadcrumb"></div><div class="sh-topbar-spacer"></div><button class="sh-topbar-btn sh-search-btn" id="shSearchBtn" type="button">${ICON.search}<span>${esc(L.search)}</span><kbd>⌘K</kbd></button><button class="sh-money-pulse zero" id="shMoneyPulse" title="إجمالي الأرباح" type="button"><span class="pulse-dot"></span><span class="sh-mp-value">$0.00</span><span class="sh-mp-trend flat">—</span></button><button class="sh-topbar-btn" id="shThemeBtn" title="Theme" aria-label="Toggle theme" type="button">${ICON.moon}</button></header>`;
  }

  function buildStatusbar() {
    return `<footer class="sh-statusbar"><span class="sh-status-item"><span class="sh-status-dot"></span>LIVE</span><span class="sh-status-item" id="shStatusVisits">— اليوم</span><span class="sh-status-item" id="shStatusProfit">—</span><span class="sh-status-spacer"></span><span class="sh-status-item">⌘K بحث</span><span class="sh-status-item">?</span></footer>`;
  }

  function buildMobileNav() {
    const nav = (NAV[S.lang] || NAV.ar)[0].items.slice(0, 5);
    return `<nav class="sh-mobile-nav">${nav.map(it => { const badge = it.badge ? `<span class="sh-mobile-badge" data-mbadge="${esc(it.badge)}" style="display:none;">0</span>` : ''; return `<a href="${esc(it.href)}" class="sh-mobile-nav-item ${S.active === it.id ? 'active' : ''}">${ICON[it.icon] || ''}<span>${esc(it.label)}</span>${badge}</a>`; }).join('')}</nav>`;
  }

  function buildCmdPalette() {
    return `<div class="sh-cmd-overlay" id="shCmdOverlay"><div class="sh-cmd"><div class="sh-cmd-input-wrap">${ICON.search}<input type="text" class="sh-cmd-input" id="shCmdInput" placeholder="${esc(T[S.lang].searchPlaceholder)}" autocomplete="off"><kbd style="padding:2px 6px;background:var(--sh-canvas);border:1px solid var(--sh-line-2);border-radius:3px;font-family:var(--sh-font-mono);font-size:9px;color:var(--sh-ink-mute);">ESC</kbd></div><div class="sh-cmd-results" id="shCmdResults"></div></div></div>`;
  }

  function buildCommands() {
    const nav = (NAV[S.lang] || NAV.ar).flatMap(g => g.items); const cmds = [];
    nav.forEach(it => { cmds.push({ group: T[S.lang].nav, label: it.label, icon: it.icon, action: () => { window.location.href = it.href; } }); });
    if (S.campaigns && S.campaigns.length) { S.campaigns.slice(0, 5).forEach(c => { cmds.push({ group: 'الحملات', label: c.name, desc: '🎯', action: () => { window.location.href = '/campaigns/' + c.id; } }); }); }
    cmds.push({ group: T[S.lang].user, label: T[S.lang].logout, icon: 'logout', action: async () => { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); window.location.href = '/'; } });
    return cmds;
  }

  function renderCmdResults() {
    const container = document.getElementById('shCmdResults'); if (!container) return;
    const q = S.cmdQuery.trim().toLowerCase(); const all = buildCommands();
    const filtered = q ? all.filter(c => c.label.toLowerCase().includes(q) || (c.desc || '').toLowerCase().includes(q)) : all.slice(0, 12);
    S.cmdItems = filtered; if (S.cmdSelected >= filtered.length) S.cmdSelected = Math.max(0, filtered.length - 1);
    if (!filtered.length) { container.innerHTML = `<div class="sh-cmd-empty">${esc(T[S.lang].empty)}</div>`; return; }
    let html = ''; let lastGroup = null;
    filtered.forEach((c, i) => {
      if (c.group !== lastGroup) { html += `<div class="sh-cmd-group-label">${esc(c.group)}</div>`; lastGroup = c.group; }
      const sel = i === S.cmdSelected ? 'selected' : '';
      html += `<div class="sh-cmd-item ${sel}" data-idx="${i}">${c.icon ? ICON[c.icon] || '' : '<span style="width:14px;"></span>'}<span>${esc(c.label)}</span>${c.desc ? `<span class="desc">${esc(c.desc)}</span>` : ''}</div>`;
    });
    container.innerHTML = html;
    container.querySelectorAll('.sh-cmd-item').forEach(el => {
      el.addEventListener('click', () => { const i = Number(el.dataset.idx); const c = S.cmdItems[i]; if (c && c.action) { closeCmd(); setTimeout(c.action, 80); } });
      el.addEventListener('mouseenter', () => { S.cmdSelected = Number(el.dataset.idx); renderCmdResults(); });
    });
  }

  function openCmd() { S.cmdOpen = true; S.cmdQuery = ''; S.cmdSelected = 0; const ov = document.getElementById('shCmdOverlay'); if (!ov) return; ov.classList.add('is-open'); const inp = document.getElementById('shCmdInput'); if (inp) { inp.value = ''; setTimeout(() => inp.focus(), 30); } renderCmdResults(); }
  function closeCmd() { S.cmdOpen = false; const ov = document.getElementById('shCmdOverlay'); if (ov) ov.classList.remove('is-open'); }
  function bindCmd() {
    const inp = document.getElementById('shCmdInput'); if (!inp) return;
    inp.addEventListener('input', (e) => { S.cmdQuery = e.target.value; S.cmdSelected = 0; renderCmdResults(); });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { closeCmd(); e.preventDefault(); }
      else if (e.key === 'ArrowDown') { S.cmdSelected = Math.min(S.cmdSelected + 1, S.cmdItems.length - 1); renderCmdResults(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { S.cmdSelected = Math.max(S.cmdSelected - 1, 0); renderCmdResults(); e.preventDefault(); }
      else if (e.key === 'Enter') { const c = S.cmdItems[S.cmdSelected]; if (c && c.action) { closeCmd(); setTimeout(c.action, 80); } e.preventDefault(); }
    });
    const overlay = document.getElementById('shCmdOverlay'); if (overlay) overlay.addEventListener('click', (e) => { if (e.target.id === 'shCmdOverlay') closeCmd(); });
  }

  function ensureToastContainer() { let c = document.querySelector('.sh-toast-container'); if (!c) { c = document.createElement('div'); c.className = 'sh-toast-container'; document.body.appendChild(c); } return c; }

  function toast(msg, type = 'info', duration = 2600, opts = {}) {
    const c = ensureToastContainer(); const el = document.createElement('div');
    el.className = `sh-toast ${type}`; el.style.position = 'relative'; el.style.overflow = 'hidden';
    const iconChar = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
    el.innerHTML = `<span class="sh-toast-icon">${iconChar}</span><span class="sh-toast-body">${esc(msg)}</span>${opts.undoLabel ? `<button class="sh-toast-undo" type="button">${esc(opts.undoLabel)}</button>` : ''}${opts.undoLabel ? `<span class="sh-toast-timer" style="--sh-toast-dur:${duration}ms;"></span>` : ''}`;
    c.appendChild(el);
    if (opts.undoLabel && typeof opts.onUndo === 'function') { const btn = el.querySelector('.sh-toast-undo'); if (btn) btn.addEventListener('click', () => { try { opts.onUndo(); } catch (e) { console.warn(e); } el.classList.add('hiding'); setTimeout(() => el.remove(), 200); }); }
    setTimeout(() => { if (el.parentNode) { el.classList.add('hiding'); setTimeout(() => el.remove(), 200); } }, duration);
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-sh-theme', theme);
    const btn = document.getElementById('shThemeBtn'); if (btn) btn.innerHTML = theme === 'dark' ? ICON.moon : ICON.sun;
    const root = document.documentElement;
    if (theme === 'light') { root.style.setProperty('--sh-canvas', '#F8FAFC'); root.style.setProperty('--sh-surface', '#FFFFFF'); root.style.setProperty('--sh-elevated', '#F1F5F9'); root.style.setProperty('--sh-raised', '#E2E8F0'); root.style.setProperty('--sh-line-1', '#E2E8F0'); root.style.setProperty('--sh-line-2', '#CBD5E1'); root.style.setProperty('--sh-line-3', '#94A3B8'); root.style.setProperty('--sh-ink-hi', '#0F172A'); root.style.setProperty('--sh-ink-md', '#334155'); root.style.setProperty('--sh-ink-lo', '#64748B'); root.style.setProperty('--sh-ink-mute', '#94A3B8'); }
    else { root.style.setProperty('--sh-canvas', '#08090D'); root.style.setProperty('--sh-surface', '#0F1117'); root.style.setProperty('--sh-elevated', '#161822'); root.style.setProperty('--sh-raised', '#1C1F2E'); root.style.setProperty('--sh-line-1', '#1A1D29'); root.style.setProperty('--sh-line-2', '#232734'); root.style.setProperty('--sh-line-3', '#2E3446'); root.style.setProperty('--sh-ink-hi', '#F8FAFC'); root.style.setProperty('--sh-ink-md', '#CBD5E1'); root.style.setProperty('--sh-ink-lo', '#7B8496'); root.style.setProperty('--sh-ink-mute', '#4A5263'); }
  }
  function initTheme() { const saved = localStorage.getItem('sh_theme') || 'dark'; applyTheme(saved); const btn = document.getElementById('shThemeBtn'); if (btn) btn.addEventListener('click', () => { const cur = document.documentElement.getAttribute('data-sh-theme') || 'dark'; const next = cur === 'dark' ? 'light' : 'dark'; applyTheme(next); localStorage.setItem('sh_theme', next); }); }
  function initCollapse() { const key = 'sh_sidebar_collapsed'; const shell = document.querySelector('.sh-shell'); if (!shell) return; if (localStorage.getItem(key) === '1') shell.classList.add('is-collapsed'); const btn = document.getElementById('shCollapseBtn'); if (btn) btn.addEventListener('click', () => { shell.classList.toggle('is-collapsed'); localStorage.setItem(key, shell.classList.contains('is-collapsed') ? '1' : '0'); }); }

  function setBreadcrumb(items) {
    const el = document.getElementById('shBreadcrumb'); if (!el) return; if (!items || !items.length) { el.innerHTML = ''; return; }
    el.innerHTML = items.map((it, i) => { const isLast = i === items.length - 1; const crumb = it.href ? `<a href="${esc(it.href)}" class="crumb" style="color:inherit;text-decoration:none;">${esc(it.label)}</a>` : `<span class="crumb ${isLast ? 'active' : ''}">${esc(it.label)}</span>`; return (i > 0 ? '<span class="sep">/</span>' : '') + crumb; }).join('');
  }

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

      const el = document.getElementById('shMoneyPulse');
      if (el) {
        const cls = todayProfit > 0.01 ? 'pos' : todayProfit < -0.01 ? 'neg' : 'zero';
        el.className = `sh-money-pulse ${cls}`;

        const estimated = (source === 'cpm' || source === 'unknown' || integrity !== 'exact');
        const indicator = estimated ? ' *' : '';

        const valEl = el.querySelector('.sh-mp-value');
        if (valEl) valEl.textContent = fmtMoney(todayProfit) + indicator;

        const trendEl = el.querySelector('.sh-mp-trend');
        if (trendEl) {
          if (trendDir === 'flat') { trendEl.textContent = '—'; trendEl.className = 'sh-mp-trend flat'; }
          else { const arrow = trendDir === 'up' ? '↑' : '↓'; trendEl.textContent = `${arrow}${Math.abs(trendPct).toFixed(0)}%`; trendEl.className = `sh-mp-trend ${trendDir}`; }
        }

        let title = `الربح اليوم: ${fmtMoney(todayProfit)}`;
        if (source === 'cpm') title += ' — تقدير بالـ CPM';
        else if (source === 'exact_partial') title += ' — محسوب من BID جزئي';
        else if (source === 'exact') title += ' — محسوب من BID الحقيقي';
        else title += ' — مفيش بيانات كافية';
        if (integrity === 'partial_warn') title += ' (تحذير: تغطية BID منخفضة)';
        el.title = title;
      }

      const visitsEl = document.getElementById('shStatusVisits');
      if (visitsEl) visitsEl.textContent = fmtNum(today.visits || 0) + ' زيارة';
      const profitEl = document.getElementById('shStatusProfit');
      if (profitEl) {
        profitEl.textContent = fmtMoney(todayProfit);
        profitEl.style.color = todayProfit > 0 ? 'var(--sh-green)' : todayProfit < 0 ? 'var(--sh-rose)' : 'var(--sh-ink-lo)';
      }
    } catch (err) {}
  }

  async function refreshAttentionCount() {
    try {
      const data = await api('/api/zones/actions/attention-count'); const total = Number(data.total || 0);
      document.querySelectorAll('.sh-nav-badge').forEach(badge => {
        if (badge.dataset.badge === 'labeling') {
          if (data.labeling > 0) { badge.style.display = ''; badge.textContent = data.labeling > 99 ? '99+' : data.labeling; const tier = data.labeling >= 10 ? 'tier-3' : data.labeling >= 5 ? 'tier-2' : 'tier-1'; badge.className = 'sh-nav-badge ' + tier; }
          else { badge.style.display = 'none'; }
        }
      });
      document.querySelectorAll('.sh-mobile-badge').forEach(badge => {
        if (badge.dataset.mbadge === 'labeling') {
          if (data.labeling > 0) { badge.style.display = ''; badge.textContent = data.labeling > 9 ? '9+' : data.labeling; }
          else { badge.style.display = 'none'; }
        }
      });
      if (total > 0) { document.title = `(${total}) ${S.baseTitle}`; } else { document.title = S.baseTitle; }
    } catch (err) {}
  }

  function ensureQuickActions() { if (S.quickActionsEl) return S.quickActionsEl; const el = document.createElement('div'); el.className = 'sh-qactions'; el.id = 'shQactions'; document.body.appendChild(el); S.quickActionsEl = el; return el; }

  function buildQuickActionsHTML(zoneId, zoneInfo) {
    const actions = []; const grade = zoneInfo.grade || ''; const trust = zoneInfo.trust;
    if (grade === 'F' || grade === 'D' || (trust !== undefined && trust < 40)) { actions.push({ id: 'blacklist', icon: 'ban', label: 'حظر فوري', cls: 'danger', kbd: 'X' }); }
    actions.push({ id: 'pause', icon: 'pause', label: 'Pause 24h', cls: 'warn', kbd: 'P' });
    if (grade === 'S' || grade === 'A' || (trust !== undefined && trust > 70)) { actions.push({ id: 'scale', icon: 'scale', label: 'Scale +30%', cls: 'success', kbd: '+' }); }
    actions.push({ id: 'details', icon: 'eye', label: 'التفاصيل', cls: '', kbd: '↵' });
    return `<div class="sh-qactions-head">${esc(zoneId)}</div>${actions.map(a => `<button type="button" class="sh-qactions-item ${a.cls}" data-action="${a.id}">${ICON[a.icon] || ''}<span>${esc(a.label)}</span>${a.kbd ? `<span class="kbd">${esc(a.kbd)}</span>` : ''}</button>`).join('')}`;
  }

  function showQuickActions(targetEl) {
    const zoneId = targetEl.dataset.zoneId; if (!zoneId) return;
    const zoneInfo = { grade: targetEl.dataset.zoneGrade || '', trust: targetEl.dataset.zoneTrust ? Number(targetEl.dataset.zoneTrust) : undefined };
    const menu = ensureQuickActions(); menu.innerHTML = buildQuickActionsHTML(zoneId, zoneInfo);
    const rect = targetEl.getBoundingClientRect(); const menuW = 200; let left = rect.left - menuW - 8; if (left < 8) left = rect.right + 8; let top = rect.top; if (top + 200 > window.innerHeight) top = window.innerHeight - 210;
    menu.style.left = left + 'px'; menu.style.top = top + 'px'; menu.classList.add('is-open'); S.quickActionsTarget = targetEl;
    menu.querySelectorAll('.sh-qactions-item').forEach(btn => { btn.addEventListener('click', (e) => { e.stopPropagation(); const action = btn.dataset.action; hideQuickActions(); applyZoneAction(targetEl, zoneId, action); }); });
  }

  function hideQuickActions() { if (S.quickActionsEl) S.quickActionsEl.classList.remove('is-open'); S.quickActionsTarget = null; }

  async function applyZoneAction(targetEl, zoneId, action) {
    if (action === 'details') { window.location.href = `/smart-reports?zone=${encodeURIComponent(zoneId)}`; return; }
    const prev = targetEl.style.opacity; targetEl.style.opacity = '0.5';
    try {
      const res = await api(`/api/zones/${encodeURIComponent(zoneId)}/action`, { method: 'POST', body: JSON.stringify({ action, reason: 'Quick Action', metadata: action === 'scale' ? { percent: 30 } : action === 'pause' ? { hours: 24 } : {} }) });
      const actionLabels = { blacklist: 'حظر', pause: 'Pause', scale: 'Scale +30%' };
      targetEl.classList.add('sh-action-applied');
      toast(`${actionLabels[action] || action} — ${zoneId}`, 'success', 5000, { undoLabel: 'تراجع', onUndo: async () => { try { await api(`/api/zones/${encodeURIComponent(zoneId)}/action/${res.id}`, { method: 'DELETE' }); targetEl.classList.remove('sh-action-applied'); targetEl.style.opacity = prev; toast('تم التراجع', 'info'); } catch (e) { toast('فشل التراجع: ' + e.message, 'error'); } } });
    } catch (err) { targetEl.style.opacity = prev; toast('فشل: ' + err.message, 'error'); }
  }

  function initQuickActions() {
    let hoverTimer = null; let currentEl = null;
    document.addEventListener('mouseover', (e) => { const target = e.target.closest('[data-zone-id]'); if (!target || target === currentEl) return; if (e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('#shQactions')) return; clearTimeout(hoverTimer); currentEl = target; hoverTimer = setTimeout(() => showQuickActions(target), 200); }, true);
    document.addEventListener('mouseout', (e) => { const target = e.target.closest('[data-zone-id]'); if (!target) return; if (e.relatedTarget && ((e.relatedTarget.closest && e.relatedTarget.closest('#shQactions')) || e.relatedTarget.closest?.('[data-zone-id]') === target)) return; clearTimeout(hoverTimer); hoverTimer = setTimeout(hideQuickActions, 250); }, true);
    document.addEventListener('mouseover', (e) => { if (e.target.closest && e.target.closest('#shQactions')) clearTimeout(hoverTimer); }, true);
    document.addEventListener('mouseout', (e) => { if (e.target.closest && e.target.closest('#shQactions') && !e.relatedTarget?.closest?.('#shQactions')) { clearTimeout(hoverTimer); hoverTimer = setTimeout(hideQuickActions, 250); } }, true);
    window.addEventListener('scroll', hideQuickActions, { passive: true });
  }

  async function mount(opts = {}) {
    if (S.mounted) return; S.active = opts.active || 'dashboard'; S.lang = opts.lang || 'ar'; S.baseTitle = opts.title || document.title;
    document.body.classList.add('sh-body');
    if (S.lang === 'ar') { document.body.classList.add('ar'); document.documentElement.setAttribute('dir', 'rtl'); document.documentElement.setAttribute('lang', 'ar'); }
    try { S.user = await api('/api/auth/me'); } catch (e) { throw new Error('فشل تحميل بيانات المستخدم: ' + e.message); }
    try { S.campaigns = await api('/api/campaigns'); } catch (e) { S.campaigns = []; }
    const appRoot = document.getElementById('shAppRoot'); const contentEl = document.getElementById('shContent');
    if (!appRoot) throw new Error('Missing #shAppRoot in HTML'); if (!contentEl) throw new Error('Missing #shContent in HTML');
    const innerContent = contentEl.innerHTML;
    appRoot.innerHTML = `<div class="sh-shell">${buildSidebar()}<div class="sh-main">${buildTopbar()}<main class="sh-content" id="shContentInner">${innerContent}</main>${buildStatusbar()}</div>${buildMobileNav()}</div>`;
    if (!document.getElementById('shLiveKeyframes')) { const styleEl = document.createElement('style'); styleEl.id = 'shLiveKeyframes'; styleEl.textContent = `@keyframes sh-live-pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.75); } }`; document.head.appendChild(styleEl); }
    const cmdWrapper = document.createElement('div'); cmdWrapper.innerHTML = buildCmdPalette(); document.body.appendChild(cmdWrapper.firstElementChild);
    ensureToastContainer(); initTheme(); initCollapse(); bindCmd(); initQuickActions();
    const searchBtn = document.getElementById('shSearchBtn'); if (searchBtn) searchBtn.addEventListener('click', openCmd);
    const moneyPulse = document.getElementById('shMoneyPulse'); if (moneyPulse) { moneyPulse.addEventListener('click', () => { window.location.href = '/smart-reports'; }); }
    document.addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openCmd(); } });
    setBreadcrumb(opts.breadcrumb || [{ label: T[S.lang].nav }]);
    refreshMoneyPulse(); refreshAttentionCount(); setInterval(refreshMoneyPulse, 30000); setInterval(refreshAttentionCount, 60000);
    S.mounted = true; return appRoot;
  }

  window.Shell = {
    mount, toast, openCmd, closeCmd, api, setBreadcrumb,
    refreshMoneyPulse, refreshAttentionCount, applyTheme,
    esc, fmtNum, fmtMoney, fmtPct,
    localDateStr,
    ICON,
    state: S,
  };
})();