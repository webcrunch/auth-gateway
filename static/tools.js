// Fills in the state of each tool card: asks /tools/status once on load, and again every minute.
(function () {
  const labels = { up: 'Svarar', down: 'Svarar inte', unknown: 'Okänt' };
  const show = (name, state) => {
    for (const el of document.querySelectorAll('.state')) {
      if (el.dataset.tool !== name) continue;
      el.className = 'state ' + state;
      el.querySelector('span').textContent = labels[state] || 'Okänt';
    }
  };
  const check = async () => {
    try {
      const r = await fetch('/tools/status', { credentials: 'same-origin', cache: 'no-store' });
      if (r.status === 401) { window.location.reload(); return; } // the session ended: show the login
      const data = await r.json();
      for (const t of data.tools || []) show(t.name, t.status);
    } catch (e) {
      for (const el of document.querySelectorAll('.state')) show(el.dataset.tool, 'unknown');
    }
  };
  check();
  setInterval(check, 60 * 1000);
})();
