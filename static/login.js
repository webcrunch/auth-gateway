// Sends the approval request to Telegram, then asks every 2 seconds whether it was approved.
(function () {
  const button = document.getElementById('send');
  const status = document.getElementById('status');
  if (!button) return;
  const rd = button.dataset.rd || '';
  const say = (text) => { status.textContent = text; };

  button.addEventListener('click', async () => {
    button.disabled = true;
    say('Skickar…');
    let response;
    try {
      response = await fetch('/auth/login', { method: 'POST', credentials: 'same-origin' });
    } catch (e) {
      response = null;
    }
    if (!response || !response.ok) {
      say(response && response.status === 429
        ? 'En förfrågan skickades nyss. Vänta en minut och försök igen.'
        : 'Det gick inte att skicka förfrågan. Försök igen.');
      button.disabled = false;
      return;
    }
    say('Godkänn inloggningen i Telegram…');
    const started = Date.now();
    const poll = async () => {
      if (Date.now() - started > 5 * 60 * 1000) {
        say('Förfrågan gick ut. Skicka en ny.');
        button.disabled = false;
        return;
      }
      try {
        const r = await fetch('/auth/login/status?rd=' + encodeURIComponent(rd), { credentials: 'same-origin' });
        const data = await r.json();
        if (data.authenticated) {
          say('Godkänd.');
          window.location.assign(data.next);
          return;
        }
      } catch (e) { /* try again */ }
      setTimeout(poll, 2000);
    };
    setTimeout(poll, 2000);
  });
})();
