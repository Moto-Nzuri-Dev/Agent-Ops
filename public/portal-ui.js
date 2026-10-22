(() => {
  'use strict';
  const THEMES = [
    ['monokai','Monokai'], ['daylight','Daylight'], ['san-francisco','San Francisco'],
    ['africa','Africa'], ['tokyo-night','Tokyo Night'], ['tokyo-day','Tokyo Day']
  ];
  const theme = localStorage.getItem('mn_portal_theme') || 'san-francisco';
  document.documentElement.dataset.theme = THEMES.some(t => t[0] === theme) ? theme : 'san-francisco';
  function themeSelect(extraClass='') {
    const label = document.createElement('label'); label.className = `theme-picker ${extraClass}`.trim();
    label.innerHTML = '<span aria-hidden="true">◐</span><span class="theme-label">Theme</span><select aria-label="Choose colour theme">' + THEMES.map(([id,name]) => `<option value="${id}">${name}</option>`).join('') + '</select>';
    const select = label.querySelector('select'); select.value = document.documentElement.dataset.theme;
    select.addEventListener('change', () => { document.documentElement.dataset.theme = select.value; localStorage.setItem('mn_portal_theme', select.value); document.querySelectorAll('.theme-picker select').forEach(s => s.value = select.value); });
    return label;
  }
  const login = document.querySelector('.auth-card');
  if (login) login.append(themeSelect('login-theme-picker'));
  const app = document.querySelector('#app');
  const shell = app?.querySelector('.shell');
  if (!app || !shell) return;
  const isRep = !!document.querySelector('#submissionForm');
  const topActions = app.querySelector('.top-actions');
  if (topActions) topActions.insertBefore(themeSelect(), topActions.querySelector('#signOut'));

  const oldChildren = [...shell.children];
  const welcome = oldChildren.find(el => el.classList.contains('welcome'));
  const metrics = oldChildren.find(el => el.classList.contains('rep-metrics'));
  const directory = oldChildren.find(el => el.querySelector('#masterDirectory'));
  const tickets = oldChildren.find(el => el.querySelector('#repTickets') || el.querySelector('#ticketList'));
  const grid = oldChildren.find(el => el.classList.contains('content-grid'));
  const formPanel = grid?.querySelector('#submissionForm')?.closest('.panel');
  const historyPanel = grid?.querySelector('#history')?.closest('.panel');

  const layout = document.createElement('div'); layout.className = 'portal-layout';
  const sidebar = document.createElement('aside'); sidebar.className = 'portal-sidebar';
  const brand = app.querySelector('.brand')?.cloneNode(true);
  sidebar.innerHTML = '<div class="sidebar-brand"></div><div class="sidebar-caption">WORKSPACE</div><nav class="portal-nav" aria-label="Portal sections"></nav><div class="sidebar-footer"><span class="online-dot"></span><span>Field operations</span></div>';
  if (brand) sidebar.querySelector('.sidebar-brand').append(brand);
  const nav = sidebar.querySelector('.portal-nav');
  const stage = document.createElement('div'); stage.className = 'portal-stage';
  const pageHead = document.createElement('div'); pageHead.className = 'tab-heading'; pageHead.innerHTML = '<div><span class="eyebrow">MOTO NZURI FIELD OPS</span><h1></h1><p></p></div><span class="secure-pill">● Secure workspace</span>';
  stage.append(pageHead);
  const tabs = [];
  function addTab(id,label,icon,title,description,items,active=false) {
    const button = document.createElement('button'); button.type='button'; button.className='nav-item'; button.dataset.tab=id;
    button.innerHTML=`<span class="nav-icon" aria-hidden="true">${icon}</span><span>${label}</span><span class="nav-chevron">›</span>`; nav.append(button);
    const panel = document.createElement('section'); panel.className='portal-tab'; panel.dataset.panel=id; panel.hidden=true;
    items.filter(Boolean).forEach(item=>panel.append(item)); stage.append(panel);
    tabs.push({id,label,title,description,button,panel});
    button.addEventListener('click',()=>activate(id));
  }
  function activate(id) {
    tabs.forEach(t=>{const on=t.id===id;t.button.classList.toggle('active',on);t.button.setAttribute('aria-current',on?'page':'false');t.panel.hidden=!on;});
    const t=tabs.find(x=>x.id===id); if(t){pageHead.querySelector('h1').textContent=t.title;pageHead.querySelector('p').textContent=t.description;}
    sidebar.classList.remove('sidebar-open');
    localStorage.setItem(`mn_${isRep?'rep':'tech'}_active_tab`,id);
  }
  if (isRep) {
    addTab('form','New shop form','＋','Register a shop','Complete the shop details and capture GPS at the location.',[formPanel],true);
    addTab('history','My submissions','▤','My submissions','Review and search shop records submitted from your account.',[historyPanel]);
    addTab('directory','Master directory','⌕','Master shop directory','Search shared shop records and share details with your team.',[directory]);
    addTab('tickets','My tickets','✓','Assigned tickets','Track work assigned to your representative account.',[tickets]);
    addTab('overview','Overview','▦','Your activity','A quick summary of your submissions.',[welcome,metrics]);
  } else {
    addTab('tickets','My tickets','✓','Assigned tickets','Review assigned work, update progress and record resolution notes.',[tickets],true);
    addTab('directory','Master directory','⌕','Master shop directory','Search shop details and open the shop location on a map.',[directory]);
    addTab('overview','Overview','▦','Field service overview','Your assigned work and shop directory in one place.',[welcome]);
  }
  const menu = document.createElement('button'); menu.className='mobile-menu'; menu.type='button'; menu.setAttribute('aria-label','Toggle navigation'); menu.innerHTML='☰';
  const topbar = app.querySelector('.topbar'); if(topbar) topbar.insertBefore(menu,topbar.firstChild);
  menu.addEventListener('click',()=>sidebar.classList.toggle('sidebar-open'));
  shell.replaceChildren(layout); layout.append(sidebar,stage);
  // Always open on the primary task: shop form for representatives, ticket queue for technicians.
  activate(isRep ? 'form' : 'tickets');
  // Make long email and action groups behave on narrow screens.
  app.querySelectorAll('.actions').forEach(el=>el.classList.add('responsive-actions'));
})();
