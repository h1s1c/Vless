'use strict';

const SAMPLE_INPUT = 'vless://c5209cfd-0e18-4e0d-8f0a-ef8a5fd0ce80@gvp.mobilerom.vu:2087?encryption=none&host=login.vip2vip.info&path=%2F&security=none&type=httpupgrade#Tunnel%20zero';

const inputEl = document.getElementById('inputConfig');
const outputEl = document.getElementById('outputConfig');
const statusEl = document.getElementById('status');
const copyBtn = document.getElementById('copyBtn');
const testLink = document.getElementById('testLink');

function setStatus(message, kind) {
  statusEl.textContent = message;
  statusEl.className = 'status' + (kind ? ` ${kind}` : '');
}

function encodeQueryValue(value) {
  // encodeURIComponent uses %20 for spaces and safely encodes JSON punctuation.
  return encodeURIComponent(value);
}

function getFragmentTemplate() {
  // Keep this JSON template explicit so its output matches the requested format.
  return '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "107", "1"], "delays": ["0"], "maxSplit": "0"}}, {"type": "fragment", "settings": {"packets": "1-2", "lengths": ["120-200", "1-3"], "delays": ["1", "0"], "maxSplit": "15"}}]}\n';
}

function parseVless(input) {
  const raw = input.trim();
  if (!raw) throw new Error('ابتدا یک کانفیگ VLESS وارد کنید.');
  if (!/^vless:\/\//i.test(raw)) throw new Error('آدرس باید با vless:// شروع شود.');
  if (/[\r\n]/.test(raw)) throw new Error('فقط یک کانفیگ در هر بار وارد کنید.');

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('ساختار URL معتبر نیست. آدرس و پارامترها را بررسی کنید.');
  }

  if (url.protocol.toLowerCase() !== 'vless:') throw new Error('پروتکل ورودی VLESS نیست.');
  const uuid = decodeURIComponent(url.username || '');
  if (!uuid) throw new Error('UUID در کانفیگ پیدا نشد.');
  // Standard UUID check; reject malformed userinfo rather than producing a broken link.
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidPattern.test(uuid)) throw new Error('UUID معتبر نیست یا با قالب استاندارد UUID مطابقت ندارد.');
  if (!url.hostname) throw new Error('آدرس سرور در کانفیگ وجود ندارد.');
  if (url.port && (!Number.isInteger(Number(url.port)) || Number(url.port) < 1 || Number(url.port) > 65535)) {
    throw new Error('پورت ورودی معتبر نیست.');
  }

  let name = '';
  try {
    name = decodeURIComponent(url.hash.slice(1));
  } catch {
    name = url.hash.slice(1);
  }
  return { uuid, name };
}

function buildOutput(parsed) {
  const uuid = parsed.uuid;
  const name = parsed.name;
  const fragment = encodeQueryValue(getFragmentTemplate());

  // Parameter order and values follow the output template provided by the user.
  const query = [
    'path=%2F',
    'security=tls',
    'alpn=h3%2Ch2%2Chttp%2F1.1',
    'encryption=none',
    `fm=${fragment}`,
    'insecure=0',
    'host=login.vip2vip.info',
    'type=httpupgrade',
    'allowInsecure=0',
    'sni=login.vip2vip.info'
  ].join('&');

  const output = `vless://${uuid}@8.47.69.0:443?${query}#${encodeURIComponent(name)}`;

  // Reparse the generated URL to catch encoding/structure mistakes.
  let check;
  try { check = new URL(output); } catch { throw new Error('خطا در ساخت URL خروجی رخ داد.'); }
  if (check.protocol !== 'vless:' || check.hostname !== '8.47.69.0' || check.port !== '443') {
    throw new Error('اعتبارسنجی آدرس خروجی ناموفق بود.');
  }
  if (check.searchParams.get('security') !== 'tls' ||
      check.searchParams.get('type') !== 'httpupgrade' ||
      check.searchParams.get('host') !== 'login.vip2vip.info' ||
      check.searchParams.get('sni') !== 'login.vip2vip.info') {
    throw new Error('برخی پارامترهای ضروری خروجی درست ساخته نشده‌اند.');
  }
  try {
    const fm = JSON.parse(check.searchParams.get('fm'));
    if (!Array.isArray(fm.tcp) || fm.tcp.length !== 2) throw new Error();
  } catch {
    throw new Error('پارامتر Fragment در خروجی معتبر نیست.');
  }
  return output;
}

document.getElementById('loadExample').addEventListener('click', () => {
  inputEl.value = SAMPLE_INPUT;
  outputEl.value = '';
  copyBtn.disabled = true;
  testLink.href = '#';
  testLink.classList.add('disabled');
  testLink.setAttribute('aria-disabled', 'true');
  setStatus('نمونه وارد شد. برای ساخت خروجی روی «تبدیل و اعتبارسنجی» بزنید.');
});

document.getElementById('convertBtn').addEventListener('click', () => {
  try {
    const parsed = parseVless(inputEl.value);
    const output = buildOutput(parsed);
    outputEl.value = output;
    copyBtn.disabled = false;
    testLink.href = output;
    testLink.classList.remove('disabled');
    testLink.setAttribute('aria-disabled', 'false');
    setStatus('کانفیگ از نظر ساختار و پارامترهای قالب بررسی شد. اتصال واقعی آزمایش نشده است.', 'success');
  } catch (error) {
    outputEl.value = '';
    copyBtn.disabled = true;
    testLink.href = '#';
    testLink.classList.add('disabled');
    testLink.setAttribute('aria-disabled', 'true');
    setStatus(error.message || 'تبدیل انجام نشد.', 'error');
  }
});

document.getElementById('clearBtn').addEventListener('click', () => {
  inputEl.value = '';
  outputEl.value = '';
  copyBtn.disabled = true;
  testLink.href = '#';
  testLink.classList.add('disabled');
  testLink.setAttribute('aria-disabled', 'true');
  setStatus('');
  inputEl.focus();
});

copyBtn.addEventListener('click', async () => {
  if (!outputEl.value) return;
  try {
    await navigator.clipboard.writeText(outputEl.value);
    setStatus('خروجی کپی شد.', 'success');
  } catch {
    outputEl.focus();
    outputEl.select();
    const copied = document.execCommand('copy');
    setStatus(copied ? 'خروجی کپی شد.' : 'کپی خودکار ممکن نشد؛ متن خروجی را دستی انتخاب و کپی کنید.', copied ? 'success' : 'error');
  }
});
