'use strict';


const inputEl = document.getElementById('inputConfig');
const outputEl = document.getElementById('outputConfig');
const statusEl = document.getElementById('status');
const copyBtn = document.getElementById('copyBtn');
const testLink = document.getElementById('testLink');
const outputTag = document.getElementById('outputTag');

const PROFILES = {
  irancell: {
    label: 'ایرانسل',
    server: 'mtn.vip2vip.info',
    port: '443'
  },
  mci: {
    label: 'همراه اول',
    server: '8.47.69.0',
    port: '443'
  }
};

function setStatus(message, kind = '') {
  statusEl.textContent = message;
  statusEl.className = 'status' + (kind ? ` ${kind}` : '');
}

function resetOutput() {
  outputEl.value = '';
  copyBtn.disabled = true;

  testLink.href = '#';
  testLink.classList.add('disabled');
  testLink.setAttribute('aria-disabled', 'true');

  outputTag.textContent = 'اپراتور انتخاب نشده است';
}

function encodeQueryValue(value) {
  return encodeURIComponent(value);
}

function getFragmentTemplate() {
  // قالب قبلی ایرانسل بدون تغییر حفظ شده است.
  return '{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["0", "107", "1"], "delays": ["0"], "maxSplit": "0"}}, {"type": "fragment", "settings": {"packets": "1-2", "lengths": ["120-200", "1-3"], "delays": ["1", "0"], "maxSplit": "15"}}]}\n';
}

function parseVless(input) {
  const raw = input.trim();

  if (!raw) {
    throw new Error('ابتدا یک کانفیگ VLESS وارد کنید.');
  }

  if (!/^vless:\/\//i.test(raw)) {
    throw new Error('آدرس باید با vless:// شروع شود.');
  }

  if (/[\r\n]/.test(raw)) {
    throw new Error('فقط یک کانفیگ در هر بار وارد کنید.');
  }

  let url;

  try {
    url = new URL(raw);
  } catch {
    throw new Error('ساختار URL معتبر نیست. آدرس و پارامترها را بررسی کنید.');
  }

  if (url.protocol.toLowerCase() !== 'vless:') {
    throw new Error('پروتکل ورودی VLESS نیست.');
  }

  if (url.password) {
    throw new Error('بخش شناسه باید فقط شامل UUID باشد، نه رمز عبور.');
  }

  let uuid;

  try {
    uuid = decodeURIComponent(url.username || '');
  } catch {
    throw new Error('کدگذاری UUID معتبر نیست.');
  }

  if (!uuid) {
    throw new Error('UUID در کانفیگ پیدا نشد.');
  }

  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  if (!uuidPattern.test(uuid)) {
    throw new Error('UUID معتبر نیست یا با قالب استاندارد UUID مطابقت ندارد.');
  }

  if (!url.hostname) {
    throw new Error('آدرس سرور در کانفیگ وجود ندارد.');
  }

  if (
    url.port &&
    (
      !Number.isInteger(Number(url.port)) ||
      Number(url.port) < 1 ||
      Number(url.port) > 65535
    )
  ) {
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

function getQueryEntries(operator) {
  if (operator === 'mci') {
    // ترتیب و مقادیر مطابق نمونهٔ همراه اول هستند.
    return [
      ['path', '/'],
      ['security', 'tls'],
      ['alpn', 'http/1.1'],
      ['encryption', 'none'],
      ['insecure', '0'],
      ['host', 'login.vip2vip.info'],
      ['ech', 'cloudflare-ech.com+udp://1.1.1.1'],
      ['type', 'httpupgrade'],
      ['allowInsecure', '0'],
      ['sni', 'login.vip2vip.info']
    ];
  }

  if (operator === 'irancell') {
    const cipherSuites =
      'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n\n';

    return [
      ['cs', cipherSuites],
      ['path', '/'],
      ['security', 'tls'],
      ['encryption', 'none'],
      ['fm', getFragmentTemplate()],
      ['insecure', '0'],
      ['host', 'login.vip2vip.info'],
      ['fp', 'unsafe'],
      ['type', 'httpupgrade'],
      ['allowInsecure', '0'],
      ['sni', 'login.vip2vip.info']
    ];
  }

  throw new Error('اپراتور انتخاب‌شده معتبر نیست.');
}

function validateOutput(output, parsed, profile, entries, operator) {
  let check;

  try {
    check = new URL(output);
  } catch {
    throw new Error('خطا در ساخت URL خروجی رخ داد.');
  }

  if (
    check.protocol !== 'vless:' ||
    check.hostname !== profile.server ||
    check.port !== profile.port ||
    decodeURIComponent(check.username) !== parsed.uuid ||
    decodeURIComponent(check.hash.slice(1)) !== parsed.name
  ) {
    throw new Error('اعتبارسنجی آدرس یا شناسهٔ خروجی ناموفق بود.');
  }

  // همهٔ پارامترهای خروجی با قالب انتخاب‌شده مقایسه می‌شوند.
  for (const [key, value] of entries) {
    if (check.searchParams.get(key) !== value) {
      throw new Error(`پارامتر ${key} در خروجی درست ساخته نشده است.`);
    }
  }

  if (operator === 'irancell') {
    try {
      const fragment = JSON.parse(check.searchParams.get('fm'));

      if (!Array.isArray(fragment.tcp) || fragment.tcp.length !== 2) {
        throw new Error();
      }
    } catch {
      throw new Error('پارامتر Fragment در خروجی معتبر نیست.');
    }
  }
}

function buildOutput(parsed, operator) {
  const profile = PROFILES[operator];

  if (!profile) {
    throw new Error('اپراتور انتخاب‌شده معتبر نیست.');
  }

  const entries = getQueryEntries(operator);

  // encodeURIComponent فاصله‌ها را با %20 نمایش می‌دهد.
  const query = entries
    .map(([key, value]) => `${key}=${encodeQueryValue(value)}`)
    .join('&');

  const output =
    `vless://${parsed.uuid}@${profile.server}:${profile.port}` +
    `?${query}#${encodeURIComponent(parsed.name)}`;

  validateOutput(output, parsed, profile, entries, operator);

  return output;
}

function convert(operator) {
  try {
    const parsed = parseVless(inputEl.value);
    const output = buildOutput(parsed, operator);
    const profile = PROFILES[operator];

    outputEl.value = output;
    copyBtn.disabled = false;

    testLink.href = output;
    testLink.classList.remove('disabled');
    testLink.setAttribute('aria-disabled', 'false');

    outputTag.textContent =
      `${profile.label} — مقصد: ${profile.server}:${profile.port}`;

    setStatus(
      `کانفیگ ${profile.label} ساخته و از نظر ساختار بررسی شد. اتصال واقعی آزمایش نشده است.`,
      'success'
    );
  } catch (error) {
    resetOutput();
    setStatus(error.message || 'تبدیل انجام نشد.', 'error');
  }
}

document.getElementById('convertBtn').addEventListener('click', () => {
  convert('irancell');
});

document.getElementById('mciBtn').addEventListener('click', () => {
  convert('mci');
});


document.getElementById('clearBtn').addEventListener('click', () => {
  inputEl.value = '';
  resetOutput();
  setStatus('');
  inputEl.focus();
});

// با تغییر ورودی، خروجی قبلی پاک می‌شود تا اشتباهی کپی نشود.
inputEl.addEventListener('input', () => {
  resetOutput();
  setStatus('');
});

// جلوگیری از فعال‌شدن لینک غیرفعال با صفحه‌کلید.
testLink.addEventListener('click', (event) => {
  if (testLink.getAttribute('aria-disabled') === 'true') {
    event.preventDefault();
  }
});

copyBtn.addEventListener('click', async () => {
  const text = outputEl.value;

  if (!text) return;

  try {
    await navigator.clipboard.writeText(text);
    setStatus('خروجی کپی شد.', 'success');
  } catch {
    outputEl.focus();
    outputEl.select();

    let copied = false;

    try {
      copied = document.execCommand('copy');
    } catch {
      copied = false;
    }

    setStatus(
      copied
        ? 'خروجی کپی شد.'
        : 'کپی خودکار ممکن نشد؛ متن خروجی را دستی انتخاب و کپی کنید.',
      copied ? 'success' : 'error'
    );
  }
});
