"use strict";
/* Lock screen: derive the key from the passphrase, decrypt the app and its data in
   the browser, then start the app. Nothing decrypted is ever sent anywhere. */
(function () {
  const view = document.getElementById('view');
  const nav = document.getElementById('nav');
  const KEY = 'p3-pass';
  let meta, key;

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'text') n.textContent = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
    }
    for (const c of kids) if (c != null) n.append(c);
    return n;
  }
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function derive(pass) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(meta.salt), iterations: meta.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function open(name) {
    const r = await fetch('enc/' + name); if (!r.ok) throw new Error(name + ' ' + r.status);
    const buf = new Uint8Array(await r.arrayBuffer());
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12)));
  }
  const text = u8 => new TextDecoder().decode(u8);

  async function unlock(pass, remember) {
    key = await derive(pass);
    if (text(await open('check.bin')) !== 'p3-ok') throw new Error('bad');
    if (remember) { try { sessionStorage.setItem(KEY, pass); } catch (e) { /* ignore */ } }
    const [app, content, traces] = await Promise.all([open('app.bin'), open('content.bin'), open('traces.bin')]);
    window.__DECRYPTED_CONTENT = JSON.parse(text(content));
    window.__DECRYPTED_TRACES = JSON.parse(text(traces));
    const cache = {};
    window.__VIDEO_URL = async ep => {
      if (!meta.videos.includes(ep)) return null;
      if (!cache[ep]) cache[ep] = open(ep + '.bin').then(u8 => URL.createObjectURL(new Blob([u8], { type: 'video/mp4' })));
      return cache[ep];
    };
    nav.hidden = false;
    const s = document.createElement('script');
    s.src = URL.createObjectURL(new Blob([app], { type: 'text/javascript' }));
    document.body.append(s);
  }

  async function whyBlock() {
    try {
      const w = await (await fetch('data/why.json')).json();
      return el('section', { class: 'card' }, el('h2', { text: w.title }), el('p', { text: w.lede }),
        ...w.sections.map(s => el('div', null, el('h3', { text: s.title }), el('p', { text: s.body }),
          s.bullets.length ? el('ul', null, ...s.bullets.map(b => el('li', { text: b }))) : null)));
    } catch (e) { return null; }
  }

  async function lockScreen(msg) {
    nav.hidden = true;
    const input = el('input', { type: 'password', id: 'pass', autocomplete: 'current-password', 'aria-label': 'Passphrase' });
    const keep = el('input', { type: 'checkbox', id: 'keep', checked: '' });
    const status = el('p', { class: 'muted', role: 'status', text: msg || '' });
    const form = el('form', { class: 'card lock', onsubmit: async ev => {
      ev.preventDefault(); status.textContent = 'Unlocking…';
      try { await unlock(input.value, keep.checked); } catch (e) { status.textContent = 'Wrong passphrase.'; input.select(); }
    } },
      el('h1', { text: 'Locked' }),
      el('p', { text: 'The code walkthrough, drills, videos and lab traces are encrypted. Enter the passphrase to open them in this browser.' }),
      el('label', { for: 'pass', text: 'Passphrase' }), input,
      el('label', { class: 'muted' }, keep, ' Remember for this tab'),
      el('button', { type: 'submit', text: 'Unlock' }), status);
    view.replaceChildren(form);
    const w = await whyBlock(); if (w) view.append(w);
    input.focus();
  }

  (async function start() {
    try { meta = await (await fetch('enc/meta.json')).json(); } catch (e) { view.textContent = 'Could not load site data.'; return; }
    let saved = null; try { saved = sessionStorage.getItem(KEY); } catch (e) { /* ignore */ }
    if (saved) { try { await unlock(saved, false); return; } catch (e) { /* fall through */ } }
    lockScreen();
  })();
})();
