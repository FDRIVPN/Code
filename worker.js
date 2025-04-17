addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const USER_KV = USER;
const ADMIN_PASSWORD = "_ES_";

const USER_PANELS = {
  'basic': [],
  'silver': ['panel1'],
  'gold': ['panel1', 'panel2'],
  'platinum': ['panel1', 'panel2', 'panel3'],
  'vip': ['panel1', 'panel2', 'panel3', 'panel4']
};

const UPGRADES = {
  energy: {
    basePrice: 1000,
    multiplier: 1.5,
    effect: 50
  },
  multiClick: {
    basePrice: 1000,
    multiplier: 1.5
  },
  recharge: {
    basePrice: 1000,
    multiplier: 1.5
  },
  autoClicker: {
    basePrice: 1000,
    multiplier: 1.5
  }
};

const INVITE_REWARD = 50;

// توابع کمکی عمومی
function formatRemainingTime(seconds) {
  if (seconds < 60) return `${seconds} ثانیه`;
  if (seconds < 3600) return `${Math.floor(seconds/60)} دقیقه`;
  if (seconds < 86400) return `${Math.floor(seconds/3600)} ساعت`;
  return `${Math.floor(seconds/86400)} روز`;
}

async function generateStableInviteCode(username) {
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(username + 'SALT_' + Math.random().toString(36))
  );
  const hashArray = Array.from(new Uint8Array(hash));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hashHex.substring(0, 8)}-${Math.random().toString(36).substring(2, 6)}`.toUpperCase();
}

function isValidUsername(username) {
  return username && 
         username.length >= 3 && 
         username.length <= 20 &&
         /^[a-zA-Z0-9_\-.]{3,20}$/.test(username);
}

// اصلاح شده
function getUsernameFromCookie(cookieHeader) {
  if (!cookieHeader) return null;
  
  try {
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'username' && value) {
        return decodeURIComponent(value);
      }
    }
    return null;
  } catch (error) {
    console.error('Error parsing cookie:', error);
    return null;
  }
}

function setGameDataCookie(data) {
  const cookieData = {
    coins: data.coins || 0,
    energy: data.energy || 100,
    maxEnergy: data.maxEnergy || 100,
    upgrades: data.upgrades || {
      energy: 0,
      multiClick: 0,
      recharge: 0,
      autoClicker: 0
    },
    lastEnergyUpdate: data.lastEnergyUpdate || Math.floor(Date.now()/1000),
    turboEndTime: data.turboEndTime || 0
  };
  
  return `gameData=${encodeURIComponent(JSON.stringify(cookieData))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}

function setGameDataCookie(data) {
  return `gameData=${encodeURIComponent(JSON.stringify(data))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}

function initializeGameData() {
  return {
    coins: 0,
    energy: 100,
    maxEnergy: 100,
    upgrades: {
      energy: 0,
      multiClick: 0,
      recharge: 0,
      autoClicker: 0
    },
    lastEnergyUpdate: Math.floor(Date.now()/1000),
    turboEndTime: 0
  };
}

async function handleRequest(request) {
  try {
    const url = new URL(request.url);
    const { pathname } = url;
    const cookie = request.headers.get('cookie') || '';
    const username = getUsernameFromCookie(cookie);

    if (url.pathname === '/error-1101') {
      return handleError1101(request);
    }

    const adminResponse = await adminMiddleware(request);
    if (adminResponse) return adminResponse;

    if (username && pathname === '/') {
      return Response.redirect(new URL('/profile', url.origin).toString(), 302);
    }
    
    if (!username && pathname !== '/' && pathname !== '/submit') {
      return Response.redirect(new URL('/', url.origin).toString(), 302);
    }

    if (pathname === '/' || pathname === '/submit') {
      if (request.method === 'POST' && pathname === '/submit') {
        return handleFormSubmission(request);
      }
      return serveLoginPage('', request); // Pass request here
    }

    if (!username) {
      return Response.redirect(new URL('/', url.origin).toString(), 302);
    }

    let userData = await USER_KV.get(username, 'json') || {};
    let gameData = getGameDataFromCookie(cookie) || initializeGameData();

    if (userData.banned) {
      const banEnd = userData.banned.until || 0;
      const now = Math.floor(Date.now()/1000);
      
      if (banEnd === 0 || now < banEnd) {
        return new Response(getBannedHTML(userData.banned.reason, 
          banEnd === 0 ? 'دائمی' : formatRemainingTime(banEnd - now)), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } else {
        delete userData.banned;
        await USER_KV.put(username, JSON.stringify(userData));
      }
    }

    switch (pathname) {
      case '/profile':
        return serveProfilePage(username, userData, gameData);
      case '/click-coin':
        return handleClickCoin(request, gameData);
      case '/upgrade':
        return serveUpgradePage(userData);
      case '/use-boost':
        return handleBoost(request);
      case '/purchase-upgrade':
        return handlePurchaseUpgrade(request);
      case '/leaderboard':
        return handleLeaderboard(request);
      case '/invite':
        return handleInvitePage(username);
        case '/admin':
          return handleAdminPanel(request);
        case '/admin/login':
          return handleAdminLogin(request);
        case '/admin/actions':
          return handleAdminActions(request);
        case '/admin/user-data':
          return handleAdminUserData(request);
      case '/sync-game':
        return handleGameSync(request);
      case '/reward':
        return handleRewardPage(request);
      default:
        return Response.redirect(new URL('/error-1101', url.origin).toString(), 302);
    }

  } catch (error) {
    console.error('Server Error:', error);
    return Response.redirect(new URL('/error-1101', request.url).toString(), 302);
  }
}




function setGameDataCookie(data) {
  return `gameData=${encodeURIComponent(JSON.stringify(data))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}



function rechargeEnergy(gameData, now) {
  const rechargeRate = 1 + (gameData.upgrades.recharge || 0);
  const secondsPassed = now - (gameData.lastEnergyUpdate || now);
  
  if (secondsPassed > 0) {
    const energyToAdd = Math.floor(secondsPassed * rechargeRate);
    gameData.energy = Math.min(
      gameData.maxEnergy,
      (gameData.energy || 0) + energyToAdd
    );
    gameData.lastEnergyUpdate = now;
  }
  
  return gameData;
}

async function handleClickCoin(request, gameData) {
  const cookie = request.headers.get('cookie') || '';
  const username = getUsernameFromCookie(cookie);
  
  // Recharge energy first
  const now = Math.floor(Date.now() / 1000);
  gameData = rechargeEnergy(gameData, now);
  
  // Calculate coins
  const base = 1 + (gameData.upgrades.multiClick || 0) * 0.5;
  const turboMultiplier = gameData.turboEndTime > now ? 3 : 1;
  const coinsToAdd = Math.floor(base * turboMultiplier);
  
  // Deduct energy (unless in turbo mode)
  const energyCost = 1 + (gameData.upgrades.multiClick || 0);
  if (!(gameData.turboEndTime > now)) {
    if (gameData.energy < energyCost) {
      return new Response(JSON.stringify({ 
        error: 'انرژی کافی نیست',
        energy: gameData.energy
      }), { status: 400 });
    }
    gameData.energy -= energyCost;
  }

  // Update game state
  gameData.coins += coinsToAdd;
  gameData.lastEnergyUpdate = now;

  // Sync with server if needed
  if (username) {
    await updateServerData(username, gameData);
  }

  return new Response(JSON.stringify({
    coins: gameData.coins,
    energy: gameData.energy,
    turboActive: gameData.turboEndTime > now
  }), {
    headers: {'Set-Cookie': setGameDataCookie(gameData)}
  });
}




// Helper Functions
async function getUsernameFromSession(cookie) {
  const sessionMatch = cookie?.match(/session=([^;]+)/);
  if(!sessionMatch) return null;
  
  const sessionId = sessionMatch[1];
  return await SESSIONS_KV.get(sessionId);
}



function setGameDataCookie(data) {
  const cookieData = {
    coins: data.coins,
    energy: data.energy,
    lastEnergyUpdate: data.lastEnergyUpdate,
    turboEndTime: data.turboEndTime
  };
  
  return `gameData=${encodeURIComponent(JSON.stringify(cookieData))}; ` +
         `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}





async function handleFormSubmission(request) {
  try {
    const url = new URL(request.url);
    const formData = await request.formData();
    
    // اعتبارسنجی CSRF Token
    const csrfToken = formData.get('csrfToken');
    const cookieHeader = request.headers.get('cookie') || '';
    const cookieToken = getCookieValue(cookieHeader, 'csrfToken');
    
    if (!csrfToken || csrfToken !== cookieToken) {
      return serveLoginPage('درخواست نامعتبر. لطفاً صفحه را refresh کنید.');
    }
    
    // دریافت و اعتبارسنجی داده‌های فرم
    const username = (formData.get('username') || '').trim();
    const inviteCode = (formData.get('inviteCode') || '').trim().toUpperCase();
    
    // اعتبارسنجی نام کاربری
    if (!isValidUsername(username)) {
      return serveLoginPage('نام کاربری باید بین ۳ تا ۲۰ کاراکتر و فقط شامل حروف انگلیسی، اعداد و _ - . باشد');
    }
    
    // بررسی وجود کاربر
    const existingUser = await USER_KV.get(username, 'json');
    
    // اگر کاربر وجود دارد - ورود
    if (existingUser) {
      return handleExistingUser(request, existingUser, username, url);
    }
    
    // اگر کاربر جدید است - ثبت نام
    return handleNewUserRegistration(request, username, inviteCode, url);
    
  } catch (error) {
    console.error('Error in form submission:', error);
    return serveLoginPage('خطای سرور. لطفاً بعداً تلاش کنید.');
  }
}

async function handleExistingUser(request, userData, username, url) {
  // بررسی مسدود بودن کاربر
  if (userData.banned) {
    const banEnd = userData.banned.until || 0;
    const now = Math.floor(Date.now()/1000);
    const remainingTime = banEnd === 0 ? 'دائمی' : formatRemainingTime(banEnd - now);
    
    if (banEnd === 0 || now < banEnd) {
      return serveLoginPage(`حساب شما مسدود شده است. دلیل: ${userData.banned.reason || 'نامشخص'}. زمان باقی‌مانده: ${remainingTime}`);
    }
    
    // رفع مسدودیت اگر زمان آن گذشته است
    delete userData.banned;
  }

  // به‌روزرسانی آخرین ورود
  userData.lastLogin = Date.now();
  userData.lastIp = request.headers.get('CF-Connecting-IP') || 'unknown';
  
  // ذخیره تغییرات
  await USER_KV.put(username, JSON.stringify(userData));

  // پاسخ با کوکی‌های امن
  return new Response(null, {
    status: 302,
    headers: {
      'Location': `${url.origin}/profile`,
      'Set-Cookie': [
        `username=${encodeURIComponent(username)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
        setGameDataCookie(initializeGameData())
      ]
    }
  });
}

async function handleNewUserRegistration(request, username, inviteCode, url) {
  try {
    // بررسی کد دعوت
    let inviter = null;
    if (inviteCode) {
      const { valid, inviter: codeInviter } = await checkInviteCode(inviteCode);
      if (!valid) {
        return serveLoginPage('کد دعوت نامعتبر است');
      }
      inviter = codeInviter;
    }

    // تولید کد دعوت منحصر به فرد
    let inviteCode;
    let attempts = 0;
    const maxAttempts = 5;
    
    while (attempts < maxAttempts) {
      try {
        const newCode = await generateStableInviteCode(username);
        const existing = await USER_KV.get(`invite:${newCode}`);
        if (!existing) {
          inviteCode = newCode;
          break;
        }
      } catch (error) {
        console.error('Error generating invite code:', error);
      }
      attempts++;
    }
    
    if (!inviteCode) {
      inviteCode = `${username}-${Math.random().toString(36).substring(2, 8)}`.toUpperCase();
    }

    // ایجاد کاربر جدید
    const userIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userData = {
      username,
      coins: 0,
      secondaryCoins: 0,
      energy: 100,
      maxEnergy: 100,
      upgrades: {
        energy: 0,
        multiClick: 0,
        recharge: 0,
        autoClicker: 0
      },
      level: 'basic',
      lastDailyReset: Math.floor(Date.now()/1000),
      dailyTurbo: 3,
      dailyRefill: 3,
      inviteCode,
      invitedBy: inviter,
      inviteCount: 0,
      invitedUsers: [],
      registeredAt: Date.now(),
      lastLogin: Date.now(),
      darkMode: true,
      lastIp: userIp
    };

    // ذخیره کاربر جدید
    await USER_KV.put(username, JSON.stringify(userData));
    
    // ذخیره کد دعوت برای جستجوی سریع
    await USER_KV.put(`invite:${inviteCode}`, username);

    // پاداش به دعوت‌کننده
    if (inviter) {
      await rewardInviter(inviter, username);
    }

    // پاسخ با کوکی‌های امن
    const headers = new Headers();
    headers.append('Location', `${url.origin}/profile`);
    headers.append('Set-Cookie', `username=${encodeURIComponent(username)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`);
    headers.append('Set-Cookie', setGameDataCookie(initializeGameData()));
    headers.append('Set-Cookie', `csrfToken=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
    
    return new Response(null, { status: 302, headers });

  } catch (error) {
    console.error('Error in new user registration:', error);
    return serveLoginPage('خطا در ثبت نام. لطفاً مجدداً تلاش کنید.');
  }
}

async function rewardInviter(inviterUsername, newUsername) {
  const inviterData = await USER_KV.get(inviterUsername, 'json');
  if (!inviterData) return;

  inviterData.inviteCount = (inviterData.inviteCount || 0) + 1;
  inviterData.invitedUsers.push({
    username: newUsername,
    date: new Date().toISOString()
  });
  inviterData.secondaryCoins = (inviterData.secondaryCoins || 0) + INVITE_REWARD;
  
  await USER_KV.put(inviterUsername, JSON.stringify(inviterData));
}

// توابع کمکی
function getCookieValue(cookieHeader, name) {
  const match = cookieHeader.match(new RegExp(`(^| )${name}=([^;]+)`));
  return match ? decodeURIComponent(match[2]) : null;
}

function isValidUsername(username) {
  return username && 
         username.length >= 3 && 
         username.length <= 20 &&
         /^[a-zA-Z0-9_\-.]{3,20}$/.test(username);
}

async function checkInviteCode(code) {
  const inviter = await USER_KV.get(`invite:${code}`, 'text');
  if (!inviter) return { valid: false, inviter: null };
  
  // بررسی اضافی برای اطمینان از وجود کاربر دعوت کننده
  const inviterData = await USER_KV.get(inviter, 'json');
  if (!inviterData) {
    await USER_KV.delete(`invite:${code}`);
    return { valid: false, inviter: null };
  }
  
  // بررسی مسدود نبودن دعوت کننده
  if (inviterData.banned) {
    return { valid: false, inviter: null };
  }
  
  return { valid: true, inviter };
}

async function generateStableInviteCode(username) {
  let attempts = 0;
  const maxAttempts = 5;
  
  while (attempts < maxAttempts) {
    const encoder = new TextEncoder();
    const data = encoder.encode(username + 'SALT_' + Date.now() + Math.random());
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    const code = `${hashHex.substring(0, 8)}-${Math.random().toString(36).substring(2, 6)}`.toUpperCase();
    
    // بررسی تکراری نبودن کد
    const existing = await USER_KV.get(`invite:${code}`, 'text');
    if (!existing) return code;
    
    attempts++;
  }
  
  // Fallback اگر تولید کد منحصر به فرد ناموفق بود
  return `${username}-${Math.random().toString(36).substring(2, 8)}`.toUpperCase();
}

function formatRemainingTime(seconds) {
  if (seconds < 60) return `${seconds} ثانیه`;
  if (seconds < 3600) return `${Math.floor(seconds/60)} دقیقه`;
  if (seconds < 86400) return `${Math.floor(seconds/3600)} ساعت`;
  return `${Math.floor(seconds/86400)} روز`;
}

// تابع برای جلوگیری از XSS
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// تابع برای خواندن مقدار کوکی
function getCookieValue(cookieHeader, name) {
  const match = cookieHeader.match(new RegExp(`(^| )${name}=([^;]+)`));
  return match ? match[2] : null;
}

// تابع اعتبارسنجی نام کاربری
function isValidUsername(username) {
  return username && 
         username.length >= 3 && 
         username.length <= 20 &&
         /^[a-zA-Z0-9_\-.]{3,20}$/.test(username);
}

// تابع تولید کد دعوت ایمن
async function generateStableInviteCode(username) {
  const encoder = new TextEncoder();
  const data = encoder.encode(username + 'SALT_' + Date.now());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hashHex.substring(0, 8)}-${Math.random().toString(36).substring(2, 6)}`.toUpperCase();
}

async function adminMiddleware(request) {
  const url = new URL(request.url);
  
  // اگر مسیر مربوط به ادمین نیست، ادامه دهید
  if (!url.pathname.startsWith('/admin')) return null;

  const cookie = request.headers.get('cookie') || '';
  const isAuthenticated = cookie.includes('admin_authenticated=true');

  // اگر احراز هویت شده و در مسیر ادمین است، null برگردان
  if (isAuthenticated) return null;

  // اگر POST برای لاگین باشد
  if (request.method === 'POST' && url.pathname === '/admin/login') {
    try {
      const formData = await request.formData();
      const password = formData.get('password');
      
      if (password === ADMIN_PASSWORD) {
        const headers = new Headers();
        headers.append('Set-Cookie', 'admin_authenticated=true; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=3600');
        headers.append('Location', '/admin');
        
        return new Response(null, {
          status: 302,
          headers: headers
        });
      }
      
      return new Response(getAdminLoginHTML('رمز عبور اشتباه است'), {
        headers: { 'Content-Type': 'text/html' },
        status: 401
      });
    } catch (error) {
      return new Response(getAdminLoginHTML('خطا در پردازش فرم'), {
        headers: { 'Content-Type': 'text/html' },
        status: 500
      });
    }
  }

  // اگر GET برای لاگین باشد
  return new Response(getAdminLoginHTML(), {
    headers: { 'Content-Type': 'text/html' },
    status: 200
  });
}

// بررسی معتبر بودن کد دعوت
async function checkInviteCode(code) {
  try {
    // بررسی در KV
    const inviter = await USER_KV.get(`invite:${code}`, 'text');
    
    // بررسی اضافی برای اطمینان از وجود کاربر دعوت کننده
    if (inviter) {
      const inviterData = await USER_KV.get(inviter, 'json');
      if (!inviterData) {
        // اگر کاربر دعوت کننده وجود ندارد، کد نامعتبر است
        await USER_KV.delete(`invite:${code}`);
        return { valid: false, inviter: null };
      }
      
      // بررسی مسدود نبودن دعوت کننده
      if (inviterData.banned) {
        return { valid: false, inviter: null };
      }
      
      return { valid: true, inviter };
    }
    
    return { valid: false, inviter: null };
  } catch (error) {
    console.error('Error checking invite code:', error);
    return { valid: false, inviter: null };
  }
}

// تولید کد دعوت پایدار و منحصر به فرد
async function generateStableInviteCode(username) {
  let attempts = 0;
  const maxAttempts = 5;
  
  while (attempts < maxAttempts) {
    try {
      // تولید کد با ترکیب هش و کاراکترهای تصادفی
      const encoder = new TextEncoder();
      const data = encoder.encode(username + 'SALT_' + Date.now() + Math.random());
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      // فرمت کد: 8 کاراکتر هش + 4 کاراکتر تصادفی
      const code = `${hashHex.substring(0, 8)}-${Math.random().toString(36).substring(2, 6)}`.toUpperCase();
      
      // بررسی تکراری نبودن کد
      const existing = await USER_KV.get(`invite:${code}`, 'text');
      if (!existing) {
        return code;
      }
      
      attempts++;
    } catch (error) {
      console.error('Error generating invite code:', error);
      attempts++;
    }
  }
  
  // اگر پس از چند تلاش موفق نشد، از روش ساده‌تر استفاده می‌کنیم
  return `${username}-${Math.random().toString(36).substring(2, 10)}`.toUpperCase();
}

// توابع کمکی مورد نیاز








// در سمت کلاینت (جاوااسکریپت صفحه):
async function syncGameState() {
  try {
    // ارسال وضعیت فعلی به سرور
    const response = await fetch('/sync-game', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(gameState)
    });
    
    if (response.ok) {
      const serverState = await response.json();
      // ادغام وضعیت سرور و کلاینت
      gameState = {...gameState, ...serverState};
      updateDisplay();
    }
  } catch (error) {
    console.error('Sync error:', error);
  }
}

// در سمت سرور (Worker):
async function syncGameState(username, gameData) {
  try {
    const userData = await USER_KV.get(username, 'json') || {};
    
    // ادغام هوشمندانه حالت‌ها
    const mergedState = {
      coins: Math.max(gameData.coins || 0, userData.coins || 0),
      energy: Math.min(
        Math.max(gameData.energy || 0, userData.energy || 0),
        userData.maxEnergy || 100
      ),
      maxEnergy: userData.maxEnergy || 100,
      upgrades: userData.upgrades || gameData.upgrades || {
        energy: 0,
        multiClick: 0,
        recharge: 0,
        autoClicker: 0
      },
      lastEnergyUpdate: Math.floor(Date.now()/1000),
      turboEndTime: Math.max(gameData.turboEndTime || 0, userData.turboEndTime || 0)
    };
    
    await USER_KV.put(username, JSON.stringify(mergedState));
    
    return mergedState;
  } catch (error) {
    console.error('Sync error:', error);
    return gameData;
  }
}

// در تابع handleRechargeEnergy:
async function handleRechargeEnergy(request) {
  const cookie = request.headers.get('cookie');
  const cookieData = getGameDataFromCookie(cookie);
  
  const { energy, maxEnergy, upgrades } = cookieData;
  const rechargeRate = 1 + (upgrades?.recharge || 0); // هر سطح شارژ ۱ واحد به سرعت اضافه می‌کند
  
  // محاسبه انرژی قابل اضافه شدن
  const now = Math.floor(Date.now() / 1000);
  const lastUpdate = cookieData.lastEnergyUpdate || now;
  const secondsPassed = now - lastUpdate;
  
  // محاسبه انرژی قابل اضافه شدن (هر ثانیه 1 واحد با در نظر گرفتن سطح شارژ)
  const energyToAdd = Math.min(
    Math.floor(secondsPassed * rechargeRate),
    maxEnergy - energy
  );
  
  if (energyToAdd > 0) {
    const newEnergy = energy + energyToAdd;
    const newCookie = setGameDataToCookie({
      ...cookieData,
      energy: newEnergy,
      lastEnergyUpdate: now
    });
    
    return new Response(JSON.stringify({
      energy: newEnergy,
      maxEnergy,
      rechargeRate
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': newCookie
      }
    });
  }
  
  return new Response(JSON.stringify({
    energy,
    maxEnergy,
    rechargeRate
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleRewardPage(request) {
  const cookie = request.headers.get('cookie') || '';
  const username = getUsernameFromCookie(cookie);
  
  if (!username) return Response.redirect('/', 302);

  const url = new URL(request.url);
  const rewardId = url.searchParams.get('id');
  
  if (request.method === 'POST' && rewardId) {
    return handleClaimReward(request, rewardId);
  }

  const userData = await USER_KV.get(username, 'json') || {};
  return new Response(getRewardPageHTML(rewardId, userData)), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  };
}

async function handleClaimReward(request, rewardId) {
  const cookie = request.headers.get('cookie') || '';
  const username = getUsernameFromCookie(cookie);
  
  if (!username) {
    return new Response(JSON.stringify({ error: 'ابتدا وارد شوید' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userData = await USER_KV.get(username, 'json') || {};
  const gameData = getGameDataFromCookie(cookie) || initializeGameData();
  
  // اعطای جایزه
  const rewardAmount = 300; // مقدار جایزه
  gameData.coins += rewardAmount;
  
  // ذخیره تغییرات
  await USER_KV.put(username, JSON.stringify(userData));
  
  return new Response(JSON.stringify({ 
    success: true,
    newCoins: gameData.coins 
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Set-Cookie': setGameDataCookie(gameData)
    }
  });
}

async function serveUpgradePage(userData) {
  if (!userData.username) return Response.redirect('/', 302);
  
  // Reset daily boosts if needed
  const now = Math.floor(Date.now() / 1000);
  const lastReset = userData.lastDailyReset || 0;
  const resetTime = 24 * 3600;
  
  if (now - lastReset > resetTime) {
    userData.dailyTurbo = 3;
    userData.dailyRefill = 3;
    userData.lastDailyReset = now;
    await USER_KV.put(userData.username, JSON.stringify(userData));
  }

  return new Response(getUpgradeHTML(userData), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

async function handleBoost(request) {
  try {
    const { type } = await request.json();
    const username = getUsernameFromCookie(request.headers.get('cookie'));
    
    if (!username) {
      return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const userData = await USER_KV.get(username, 'json') || {};
    
    if (type === 'turbo') {
      if ((userData.dailyTurbo || 0) <= 0) {
        return new Response(JSON.stringify({ error: 'تعداد تقویت‌کننده‌های شما تمام شده است' }), { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      userData.dailyTurbo--;
      userData.turboEndTime = Math.floor(Date.now()/1000) + 30;
    }
    
    if (type === 'refill') {
      if ((userData.dailyRefill || 0) <= 0) {
        return new Response(JSON.stringify({ error: 'تعداد تقویت‌کننده‌های شما تمام شده است' }), { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      userData.dailyRefill--;
      userData.energy = userData.maxEnergy || 250;
    }
    
    await USER_KV.put(username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: 'خطای سرور' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handlePurchaseUpgrade(request) {
  try {
    const { type } = await request.json();
    const cookie = request.headers.get('cookie') || '';
    const username = getUsernameFromCookie(cookie);
    
    if (!username) {
      return new Response(JSON.stringify({ error: 'لطفاً ابتدا وارد شوید' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const userData = await USER_KV.get(username, 'json') || {};
    const upgrade = UPGRADES[type];
    
    if (!upgrade) {
      return new Response(JSON.stringify({ error: 'نوع ارتقاء نامعتبر است' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const currentLevel = userData.upgrades?.[type] || 0;
    const price = calculatePrice(upgrade, currentLevel);
    
    if ((userData.secondaryCoins || 0) < price) {
      return new Response(JSON.stringify({ 
        error: 'سکه کافی نیست',
        required: price,
        current: userData.secondaryCoins || 0
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Process purchase
    userData.secondaryCoins -= price;
    userData.upgrades = userData.upgrades || {};
    userData.upgrades[type] = currentLevel + 1;
    
    // Apply special effects
    if (type === 'energy') {
      userData.maxEnergy = 250 + (UPGRADES.energy.effect * userData.upgrades.energy);
    }
    
    // Save changes
    await USER_KV.put(username, JSON.stringify(userData));
    
    // Sync with game cookie
    const gameData = {
      coins: userData.coins,
      energy: userData.energy,
      maxEnergy: userData.maxEnergy,
      upgrades: userData.upgrades,
      turboEndTime: userData.turboEndTime,
      lastEnergyUpdate: Math.floor(Date.now()/1000)
    };
    
    return new Response(JSON.stringify({
      success: true,
      newLevel: userData.upgrades[type],
      remainingCoins: userData.secondaryCoins,
      maxEnergy: userData.maxEnergy
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Set-Cookie': setGameDataCookie(gameData)
      }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'خطای سرور',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

function calculatePrice(upgrade, currentLevel) {
  return Math.floor(upgrade.basePrice * Math.pow(upgrade.multiplier, currentLevel));
}

async function handleBoost(request) {
  try {
    const { type } = await request.json();
    const username = getUsernameFromCookie(request.headers.get('cookie'));
    
    if (!username) {
      return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const userData = await USER_KV.get(username, 'json') || {};
    
    if (type === 'turbo') {
      if ((userData.dailyTurbo || 0) <= 0) {
        return new Response(JSON.stringify({ error: 'تعداد تقویت‌کننده‌های شما تمام شده است' }), { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      userData.dailyTurbo--;
      userData.turboEndTime = Math.floor(Date.now()/1000) + 30;
    }
    
    if (type === 'refill') {
      if ((userData.dailyRefill || 0) <= 0) {
        return new Response(JSON.stringify({ error: 'تعداد تقویت‌کننده‌های شما تمام شده است' }), { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      userData.dailyRefill--;
      userData.energy = userData.maxEnergy || 250;
    }
    
    await USER_KV.put(username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: 'خطای سرور' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}


async function handleThemeUpdate(request) {
  try {
    const data = await request.json();
    const username = data.username;
    const darkMode = data.darkMode;
    
    const userData = await USER_KV.get(username, 'json') || {};
    userData.darkMode = darkMode;
    
    await USER_KV.put(username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'خطا در به‌روزرسانی تم' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}


async function handleBoost(request) {
  try {
    const { type } = await request.json();
    const username = getUsernameFromCookie(request.headers.get('cookie'));
    
    if (!username) {
      return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const userData = await USER_KV.get(username, 'json') || {};
    
    if (type === 'turbo') {
      if ((userData.dailyTurbo || 0) <= 0) {
        return new Response(JSON.stringify({ error: 'تعداد تقویت‌کننده‌های شما تمام شده است' }), { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      userData.dailyTurbo--;
      userData.turboEndTime = Math.floor(Date.now()/1000) + 30;
    }
    
    if (type === 'refill') {
      if ((userData.dailyRefill || 0) <= 0) {
        return new Response(JSON.stringify({ error: 'تعداد تقویت‌کننده‌های شما تمام شده است' }), { 
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      userData.dailyRefill--;
      userData.energy = userData.maxEnergy || 250;
    }
    
    await USER_KV.put(username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ error: 'خطای سرور' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleUserUpdate(request) {
  const data = await request.json();
  const userData = await USER_KV.get(data.username, 'json') || {};
  
  // به‌روزرسانی داده‌ها
  userData.coins = data.coins;
  userData.energy = data.energy;
  userData.upgrades = data.upgrades;
  
  await USER_KV.put(data.username, JSON.stringify(userData));
  
  return new Response(JSON.stringify({ success: true }));
}

async function handlePurchaseUpgrade(request) {
  try {
    const { type } = await request.json();
    const cookie = request.headers.get('cookie') || '';
    const username = getUsernameFromCookie(cookie);
    
    if (!username) {
      return new Response(JSON.stringify({ error: 'لطفاً ابتدا وارد شوید' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const userData = await USER_KV.get(username, 'json') || {};
    const upgrade = UPGRADES[type];
    
    if (!upgrade) {
      return new Response(JSON.stringify({ error: 'نوع ارتقاء نامعتبر است' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const currentLevel = userData.upgrades?.[type] || 0;
    const price = calculatePrice(upgrade, currentLevel);
    
    if ((userData.secondaryCoins || 0) < price) {
      return new Response(JSON.stringify({ 
        error: 'سکه کافی نیست',
        required: price,
        current: userData.secondaryCoins || 0
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // پردازش خرید
    userData.secondaryCoins -= price;
    userData.upgrades = userData.upgrades || {};
    userData.upgrades[type] = currentLevel + 1;
    
    // اعمال اثرات خاص
    if (type === 'energy') {
      userData.maxEnergy = 250 + (UPGRADES.energy.effect * userData.upgrades.energy);
    }
    
    // ذخیره تغییرات
    await USER_KV.put(username, JSON.stringify(userData));
    
    // همگام‌سازی با کوکی بازی
    const gameData = {
      coins: userData.coins,
      energy: userData.energy,
      maxEnergy: userData.maxEnergy,
      upgrades: userData.upgrades,
      turboEndTime: userData.turboEndTime,
      lastEnergyUpdate: Math.floor(Date.now()/1000)
    };
    
    return new Response(JSON.stringify({
      success: true,
      newLevel: userData.upgrades[type],
      remainingCoins: userData.secondaryCoins,
      maxEnergy: userData.maxEnergy
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Set-Cookie': setGameDataCookie(gameData)
      }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'خطای سرور',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
async function handlePurchase(request) {
  try {
    const { type } = await request.json();
    const username = getUsernameFromCookie(request.headers.get('cookie'));
    
    if (!username) {
      return new Response(JSON.stringify({ error: 'کاربر یافت نشد' }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const userData = await USER_KV.get(username, 'json') || {};
    const upgrade = UPGRADES[type];
    
    if (!upgrade) {
      return new Response(JSON.stringify({ error: 'نوع ارتقاء نامعتبر است' }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const currentLevel = userData.upgrades?.[type] || 0;
    const price = calculatePrice(upgrade, currentLevel);
    
    if ((userData.secondaryCoins || 0) < price) {
      return new Response(JSON.stringify({ 
        error: 'سکه کافی نیست',
        required: price,
        current: userData.secondaryCoins || 0
      }), { 
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // پردازش خرید
    userData.secondaryCoins -= price;
    userData.upgrades = userData.upgrades || {};
    userData.upgrades[type] = currentLevel + 1;
    
    // اعمال اثرات خاص
    if (type === 'energy') {
      userData.maxEnergy = 250 + (UPGRADES.energy.effect * userData.upgrades.energy);
    }
    
    await USER_KV.put(username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({
      success: true,
      newLevel: userData.upgrades[type],
      remainingCoins: userData.secondaryCoins
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      error: 'خطای سرور',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}


// مدیریت کلیک روی سکه

async function handleClickCoin(request, gameData) {
  const cookie = request.headers.get('cookie') || '';
  const username = getUsernameFromCookie(cookie);
  
  // Recharge energy
  const now = Math.floor(Date.now() / 1000);
  gameData = rechargeEnergy(gameData, now);
  
  // Calculate coins
  const base = 1 + (gameData.upgrades.multiClick || 0) * 0.5;
  const turboMultiplier = gameData.turboEndTime > now ? 3 : 1;
  const coinsToAdd = Math.floor(base * turboMultiplier);
  
  // Deduct energy (unless in turbo mode)
  const energyCost = 1 + (gameData.upgrades.multiClick || 0);
  if (!(gameData.turboEndTime > now)) {
    if (gameData.energy < energyCost) {
      return new Response(JSON.stringify({ 
        error: 'انرژی کافی نیست',
        energy: gameData.energy
      }), { status: 400 });
    }
    gameData.energy -= energyCost;
  }

  // Update game state
  gameData.coins += coinsToAdd;
  gameData.lastEnergyUpdate = now;

  // Sync with server
  if (username) {
    await updateServerData(username, gameData);
  }

  return new Response(JSON.stringify({
    coins: gameData.coins,
    energy: gameData.energy,
    turboActive: gameData.turboEndTime > now
  }), {
    headers: {'Set-Cookie': setGameDataCookie(gameData)}
  });
}

async function handleAdminLogin(request) {
  if (request.method === 'POST') {
    const formData = await request.formData();
    const password = formData.get('password');
    
    if (password === ADMIN_PASSWORD) {
      const headers = new Headers();
      headers.append('Set-Cookie', 'admin_authenticated=true; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600');
      headers.append('Location', '/admin');
      
      return new Response(null, {
        status: 302,
        headers: headers
      });
    }
    
    return new Response(getAdminLoginHTML('رمز عبور اشتباه است'), {
      headers: { 'Content-Type': 'text/html' },
      status: 401
    });
  }
  
  return new Response(getAdminLoginHTML(), {
    headers: { 'Content-Type': 'text/html' },
    status: 200
  });
}

async function handleAdminActions(request) {
  try {
    const formData = await request.formData();
    const action = formData.get('action');
    const username = formData.get('username');
    
    if (!action) {
      return new Response(
        JSON.stringify({ error: 'عملیات مشخص نشده است' }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    switch (action) {
      case 'ban_user':
        return await banUser(username, formData);
      case 'unban_user':
        return await unbanUser(username);
      case 'update_user':
        return await updateUser(username, formData);
      case 'delete_user':
        return await deleteUser(username);
      case 'refresh_all_users':
        return await refreshAllUsers();
      case 'refresh_single_user':
        return await refreshSingleUser(username);
      case 'give_reward':
        return await giveReward(username);
      default:
        return new Response(
          JSON.stringify({ error: 'عملیات نامعتبر' }),
          {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          }
        );
    }
  } catch (error) {
    console.error('Error in admin actions:', error);
    return new Response(
      JSON.stringify({ 
        error: 'خطای سرور',
        details: error.message
      }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

async function banUser(username, formData) {
  if (!username) {
    return new Response(JSON.stringify({ error: 'نام کاربری مشخص نشده است' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userData = await USER_KV.get(username, 'json') || {};
  const duration = formData.get('ban_duration') || '1h';
  const reason = formData.get('ban_reason') || 'بدون دلیل مشخص';
  
  userData.banned = {
    until: getBanEndTime(duration),
    reason: reason
  };
  
  await USER_KV.put(username, JSON.stringify(userData));
  
  return new Response(JSON.stringify({ 
    success: true,
    message: `کاربر ${username} با موفقیت مسدود شد`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function unbanUser(username) {
  if (!username) {
    return new Response(JSON.stringify({ error: 'نام کاربری مشخص نشده است' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userData = await USER_KV.get(username, 'json') || {};
  
  if (userData.banned) {
    delete userData.banned;
    await USER_KV.put(username, JSON.stringify(userData));
  }
  
  return new Response(JSON.stringify({ 
    success: true,
    message: `مسدودیت کاربر ${username} با موفقیت برداشته شد`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function updateUser(username, formData) {
  try {
    const userData = await USER_KV.get(username, 'json');
    if (!userData) throw new Error('کاربر یافت نشد');
    
    const updatedData = {
      ...userData,
      handle: formData.get('handle') || userData.handle,
      level: formData.get('level') || userData.level,
      darkMode: formData.get('darkMode') === 'true'
    };
    
    await USER_KV.put(username, JSON.stringify(updatedData));
    return { success: true, message: 'اطلاعات کاربر با موفقیت به‌روزرسانی شد' };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function deleteUser(username) {
  if (!username) {
    return new Response(JSON.stringify({ error: 'نام کاربری مشخص نشده است' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  await USER_KV.delete(username);
  
  return new Response(JSON.stringify({ 
    success: true,
    message: `کاربر ${username} با موفقیت حذف شد`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function refreshSingleUser(username) {
  if (!username) {
    return new Response(JSON.stringify({ error: 'نام کاربری مشخص نشده است' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const userData = await USER_KV.get(username, 'json') || {};
  // منطق بروزرسانی کاربر از API خارجی
  // ...
  
  return new Response(JSON.stringify({ 
    success: true,
    message: `اطلاعات کاربر ${username} با موفقیت بروزرسانی شد`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function giveReward(username) {
  try {
    const userData = await USER_KV.get(username, 'json');
    if (!userData) throw new Error('کاربر یافت نشد');
    
    const rewardAmount = 3000;
    const updatedData = {
      ...userData,
      coins: (userData.coins || 0) + rewardAmount
    };
    
    await USER_KV.put(username, JSON.stringify(updatedData));
    return { 
      success: true, 
      message: `جایزه با موفقیت اعطا شد`,
      newCoins: updatedData.coins
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function banUser(username, formData) {
  const userData = await USER_KV.get(username, 'json') || {};
  const duration = formData.get('ban_duration') || '1h';
  const reason = formData.get('ban_reason') || 'بدون دلیل مشخص';
  
  userData.banned = {
    until: getBanEndTime(duration),
    reason: reason
  };
  
  await USER_KV.put(username, JSON.stringify(userData));
  
  return new Response(JSON.stringify({ 
    success: true,
    message: `کاربر ${username} با موفقیت مسدود شد`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function unbanUser(username) {
  const userData = await USER_KV.get(username, 'json') || {};
  
  if (userData.banned) {
    delete userData.banned;
    await USER_KV.put(username, JSON.stringify(userData));
  }
  
  return new Response(JSON.stringify({ 
    success: true,
    message: `مسدودیت کاربر ${username} با موفقیت برداشته شد`
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
// اصلاح شده با جلوگیری از race condition
async function updateServerData(username, data) {
  const userData = await USER_KV.get(username, 'json') || {};
  const now = Math.floor(Date.now()/1000);
  
  // Merge strategy
  const mergedData = {
    ...userData,
    coins: Math.max(data.coins, userData.coins || 0),
    energy: Math.min(data.energy, userData.maxEnergy || 100),
    lastEnergyUpdate: Math.max(data.lastEnergyUpdate, userData.lastEnergyUpdate || now)
  };

  await USER_KV.put(username, JSON.stringify(mergedData));
  return mergedData;
}





// در تابع handleGetUserData
async function handleGetUserData(request) {
  const cookie = request.headers.get('cookie') || '';
  const username = getUsernameFromCookie(cookie);
  let gameData = getGameDataFromCookie(cookie) || initializeGameData();
  
  // شارژ انرژی قبل از هر چیزی
  const now = Math.floor(Date.now() / 1000);
  gameData = rechargeEnergy(gameData, now);
  
  // دریافت داده‌های دائمی از KV
  if (username) {
    const userData = await USER_KV.get(username, 'json') || {};
    gameData = {
      ...gameData,
      upgrades: userData.upgrades || gameData.upgrades,
      maxEnergy: userData.maxEnergy || gameData.maxEnergy,
      turboEndTime: userData.turboEndTime || gameData.turboEndTime
    };
  }

  // بروزرسانی کوکی
  const newCookie = setGameDataCookie(gameData);
  
  return new Response(JSON.stringify(gameData), {
    headers: {'Set-Cookie': newCookie}
  });
}

function initializeNewGameData() {
  return {
    coins: 0,
    energy: 100,
    maxEnergy: 100,
    upgrades: {
      energy: 0,
      multiClick: 0,
      recharge: 0,
      autoClicker: 0
    },
    lastEnergyUpdate: Math.floor(Date.now()/1000),
    turboEndTime: 0
  };
}






// در

async function handleAutoClicker(userData) {
  const now = Math.floor(Date.now()/1000);
  const lastAuto = userData.lastAutoClick || now;
  const hoursPassed = Math.floor((now - lastAuto)/3600);
  
  if (hoursPassed > 0 && userData.upgrades?.autoClicker > 0) {
    userData.secondaryCoins += 30 * userData.upgrades.autoClicker * hoursPassed;
    userData.lastAutoClick = now;
    await USER_KV.put(userData.username, JSON.stringify(userData));
  }
}

// ثبت event listener
addEventListener('fetch', event => {
  event.respondWith(handleClickCoin(event.request));
});



// در handleLeaderboard (جدول رده‌بندی):
async function handleLeaderboard(request) {
  try {
    const url = new URL(request.url);
    const league = url.searchParams.get('league') || 'bronze';
    
    const usersList = await USER_KV.list();
    const allUsers = [];
    
    for (const key of usersList.keys) {
      const userData = await USER_KV.get(key.name, 'json');
      if (userData && !userData.banned) {
        allUsers.push(userData);
      }
    }
    
    // Filter based on league (only secondaryCoins)
    const filteredUsers = allUsers.filter(user => {
      const userCoins = user.secondaryCoins || 0;
      switch (league.toLowerCase()) {
        case 'bronze': return userCoins < 100;
        case 'silver': return userCoins >= 100 && userCoins < 500;
        case 'gold': return userCoins >= 500 && userCoins < 2000;
        case 'platinum': return userCoins >= 2000 && userCoins < 5000;
        case 'diamond': return userCoins >= 5000;
        default: return userCoins < 100;
      }
    });
    
    // Sort by secondaryCoins
    filteredUsers.sort((a, b) => {
      return (b.secondaryCoins || 0) - (a.secondaryCoins || 0);
    });
    
    // Generate HTML (display secondaryCoins)
    const leaderboardHTML = `
      <table style="width: 100%; border-collapse: collapse;">
        <thead>
          <tr style="background: #f5f5f5;">
            <th style="padding: 8px; text-align: right;">رتبه</th>
            <th style="padding: 8px; text-align: right;">نام کاربری</th>
            <th style="padding: 8px; text-align: right;">سکه‌ها</th>
          </tr>
        </thead>
        <tbody>
          ${filteredUsers.slice(0, 50).map((user, index) => `
            <tr style="border-bottom: 1px solid #eee;">
              <td style="padding: 8px;">${index + 1}</td>
              <td style="padding: 8px;">${user.username}</td>
              <td style="padding: 8px;">${user.secondaryCoins || 0}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
    
    return new Response(leaderboardHTML, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
    
  } catch (error) {
    console.error('Error in handleLeaderboard:', error);
    return new Response('خطا در بارگذاری جدول رده‌بندی', { status: 500 });
  }
}
// و این تابع را اضافه کنید:
async function handleAdminUserData(request) {
  const cookie = request.headers.get('cookie');
  if (!cookie || !cookie.includes('admin_authenticated=true')) {
    return new Response('دسترسی غیرمجاز', { status: 403 });
  }
  
  const url = new URL(request.url);
  const username = url.searchParams.get('username');
  
  if (!username) {
    return new Response('نام کاربری الزامی است', { status: 400 });
  }
  
  const userData = await USER_KV.get(username, 'json');
  if (!userData) {
    return new Response('کاربر یافت نشد', { status: 404 });
  }
  
  return Response.json(userData);
}

// تنظیمات سیستم دعوت
// تعداد سکه پاداش برای هر دعوت موفق

/**
 * بررسی معتبر بودن کد دعوت
 * @param {string} code - کد دعوت
 * @returns {Promise<{valid: boolean, inviter: string|null}>}
 */


/**
 * ثبت دعوت جدید در سیستم
 * @param {string} inviter - کاربر دعوت کننده
 * @param {string} invitee - کاربر دعوت شده
 * @returns {Promise<boolean>}
 */
async function registerInvite(inviter, invitee) {
  try {
    const response = await fetch('https://api.xiresow709.workers.dev/invites/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ inviter, invitee })
    });
    return response.ok;
  } catch (error) {
    console.error('Error registering invite:', error);
    return false;
  }
}

// تابع تولید کد دعوت پایدار


/**
 * تولید کد دعوت جدید برای کاربر
 * @param {string} username - نام کاربری
 * @returns {Promise<string|null>}
 */
async function generateInviteCode(username) {
  try {
    // اگر از API خارجی استفاده می‌کنید
    const response = await fetch('https://api.xiresow709.workers.dev/invites/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    
    if (!response.ok) throw new Error('خطا در تولید کد دعوت');
    const data = await response.json();
    return data.code;
  } catch (error) {
    console.error('Error generating invite code:', error);
    // اگر API کار نکرد، یک کد ساده تولید می‌کنیم
    return `${username}-${Math.random().toString(36).substring(2, 8)}`;
  }
}


async function serveLoginPage(errorMessage = '', request) {
  try {
    if (!request) {
      throw new Error('Request object is required');
    }
    
    const url = new URL(request.url);
    const isSecure = url.protocol === 'https:';
    
    // Generate CSRF token with fallback
    let csrfToken;
    try {
      csrfToken = crypto.randomUUID();
    } catch (e) {
      csrfToken = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    const safeErrorMessage = escapeHtml(errorMessage);
  
  const html = `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ورود به بازی سکه‌ها</title>
        <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/font.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: Vazirmatn, sans-serif;
            }
            
            body {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 1rem;
            }

            .login-container {
                width: 100%;
                max-width: 400px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 15px;
                padding: 2rem;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.1);
                animation: fadeIn 0.5s ease;
            }

            .login-header {
                text-align: center;
                margin-bottom: 1.5rem;
                color: white;
            }

            .login-header i {
                font-size: 2.5rem;
                color: #6a11cb;
                margin-bottom: 0.5rem;
            }

            .login-header h1 {
                font-size: 1.5rem;
                font-weight: 500;
            }

            .error-message {
                background: rgba(255, 0, 0, 0.1);
                color: #ff6b6b;
                padding: 0.75rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
                text-align: center;
                border: 1px solid rgba(255, 0, 0, 0.2);
                animation: fadeIn 0.3s ease;
            }

            .login-form {
                display: flex;
                flex-direction: column;
                gap: 1.2rem;
            }

            .input-group {
                position: relative;
            }

            .input-group i {
                position: absolute;
                left: 15px;
                top: 50%;
                transform: translateY(-50%);
                color: rgba(255, 255, 255, 0.5);
            }

            .input-field {
                width: 100%;
                padding: 0.75rem 0.75rem 0.75rem 40px;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                color: white;
                font-size: 1rem;
                transition: all 0.3s ease;
            }

            .input-field:focus {
                border-color: #6a11cb;
                box-shadow: 0 0 0 3px rgba(106, 17, 203, 0.3);
                outline: none;
            }

            .submit-btn {
                width: 100%;
                padding: 0.75rem;
                background: linear-gradient(to right, #6a11cb, #2575fc);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                margin-top: 0.5rem;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }

            .submit-btn:hover {
                background: linear-gradient(to right, #5a0db5, #1a65e0);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            }

            .submit-btn:disabled {
                background: #4b5563;
                cursor: not-allowed;
                transform: none;
                box-shadow: none;
                opacity: 0.7;
            }

            .login-footer {
                text-align: center;
                margin-top: 1.5rem;
                color: rgba(255, 255, 255, 0.6);
                font-size: 0.9rem;
            }

            .login-footer a {
                color: #6a11cb;
                text-decoration: none;
                font-weight: 500;
            }

            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-10px); }
                to { opacity: 1; transform: translateY(0); }
            }

            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                20%, 60% { transform: translateX(-5px); }
                40%, 80% { transform: translateX(5px); }
            }

            @media (max-width: 480px) {
                .login-container {
                    padding: 1.5rem;
                }
                
                .login-header h1 {
                    font-size: 1.3rem;
                }
            }
        </style>
    </head>
    <body>
    <div class="login-container">
        <div class="login-header">
            <i class="fas fa-coins"></i>
            <h1>ورود به بازی سکه‌ها</h1>
        </div>
        
        ${safeErrorMessage ? `<div class="error-message">${safeErrorMessage}</div>` : ''}
        
        <form class="login-form" id="loginForm" method="POST" action="/submit">
            <input type="hidden" name="csrfToken" value="${csrfToken}">
            
            <div class="input-group">
                <i class="fas fa-user"></i>
                <input type="text" 
                       name="username" 
                       class="input-field" 
                       placeholder="نام کاربری (3 تا 20 حرف)" 
                       required 
                       minlength="3" 
                       maxlength="20"
                       pattern="[a-zA-Z0-9_\\-\\.]{3,20}"
                       title="فقط حروف انگلیسی، اعداد و _ - . مجاز هستند">
            </div>
            
            <div class="input-group">
                <i class="fas fa-ticket-alt"></i>
                <input type="text" 
                       name="inviteCode" 
                       class="input-field" 
                       placeholder="کد دعوت (اختیاری)" 
                       maxlength="20">
            </div>
            
            <button type="submit" class="submit-btn" id="submitBtn">
                <span id="btnText">ورود / ثبت نام</span>
            </button>
        </form>
        
        <div class="login-footer">
            با ورود یا ثبت نام، <a href="/terms">قوانین و شرایط</a> را می‌پذیرید
        </div>
    </div>

    <script>
    // Set CSRF token cookie
    document.cookie = "csrfToken=${csrfToken}; Path=/; ${isSecure ? 'Secure; ' : ''}SameSite=Lax; HttpOnly; Max-Age=3600";
    
    const loginForm = document.getElementById('loginForm');
    const submitBtn = document.getElementById('submitBtn');
    const btnText = document.getElementById('btnText');

    // Form validation
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = loginForm.username.value.trim();
        const inviteCode = loginForm.inviteCode.value.trim();
        
        // Client-side validation
        if (!isValidUsername(username)) {
            showError('نام کاربری باید بین ۳ تا ۲۰ حرف و فقط شامل حروف، اعداد و _ - . باشد');
            return;
        }
        
        // Disable button during submission
        btnText.innerHTML = '<i class="fas fa-spinner fa-spin"></i> در حال پردازش...';
        submitBtn.disabled = true;
        
        try {
            const formData = new FormData(loginForm);
            const response = await fetch('/submit', {
                method: 'POST',
                body: formData,
                credentials: 'include'
            });
            
            if (response.redirected) {
                window.location.href = response.url;
            } else if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    window.location.href = '/profile';
                } else {
                    showError(result.error || 'خطا در ورود به سیستم');
                }
            } else {
                const error = await response.text();
                showError(error || 'خطا در ارتباط با سرور');
            }
        } catch (error) {
            console.error('Error:', error);
            showError('خطا در ارتباط با سرور: ' + error.message);
        } finally {
            btnText.innerHTML = 'ورود / ثبت نام';
            submitBtn.disabled = false;
        }
    });

    function isValidUsername(username) {
        const regex = /^[a-zA-Z0-9_\\-\\.]{3,20}$/;
        return regex.test(username);
    }

    function showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        errorDiv.style.animation = 'shake 0.5s';
        
        const existingError = document.querySelector('.error-message');
        if (existingError) {
            existingError.replaceWith(errorDiv);
        } else {
            const loginHeader = document.querySelector('.login-header');
            loginHeader.insertAdjacentElement('afterend', errorDiv);
        }
        
        setTimeout(() => {
            errorDiv.style.opacity = '0';
            setTimeout(() => errorDiv.remove(), 300);
        }, 5000);
    }
    
    window.addEventListener('DOMContentLoaded', () => {
        const urlParams = new URLSearchParams(window.location.search);
        const error = urlParams.get('error');
        
        if (error) {
            showError(decodeURIComponent(error));
        }
    });
    </script>
    </body>
    </html>
  `;

  const headers = new Headers();
  headers.append('Content-Type', 'text/html; charset=utf-8');
  headers.append('Set-Cookie', `csrfToken=${csrfToken}; Path=/; ${isSecure ? 'Secure; ' : ''}SameSite=Lax; HttpOnly; Max-Age=3600`);
  headers.append('Cache-Control', 'no-cache, no-store, must-revalidate');
  
  return new Response(html, { headers });
} catch (error) {
  console.error('Error serving login page:', error);
  return new Response(getMinimalErrorHTML(), {
    headers: { 'Content-Type': 'text/html' },
    status: 500
  });
}
}
async function generateStableInviteCode(username) {
  let attempts = 0;
  const maxAttempts = 5;
  
  while (attempts < maxAttempts) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(username + 'SALT_' + Date.now() + Math.random());
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      const code = `${hashHex.substring(0, 8)}-${Math.random().toString(36).substring(2, 6)}`.toUpperCase();
      
      // بررسی تکراری نبودن کد
      const existing = await USER_KV.get(`invite:${code}`);
      if (!existing) return code;
      
      attempts++;
    } catch (error) {
      console.error('Error generating invite code:', error);
      attempts++;
    }
  }
  
  // Fallback اگر تولید کد منحصر به فرد ناموفق بود
  return `${username}-${Math.random().toString(36).substring(2, 8)}`.toUpperCase();
}


async function checkInviteCode(code) {
  if (!code || typeof code !== 'string' || code.length < 8) {
    return { valid: false, inviter: null };
  }

  try {
    const inviter = await USER_KV.get(`invite:${code}`);
    if (!inviter) {
      return { valid: false, inviter: null };
    }

    // بررسی اضافی برای اطمینان از وجود کاربر دعوت کننده
    const inviterData = await USER_KV.get(inviter, 'json');
    if (!inviterData) {
      await USER_KV.delete(`invite:${code}`);
      return { valid: false, inviter: null };
    }
    
    // بررسی مسدود نبودن دعوت کننده
    if (inviterData.banned) {
      return { valid: false, inviter: null };
    }
    
    return { valid: true, inviter };
  } catch (error) {
    console.error('Error checking invite code:', error);
    return { valid: false, inviter: null };
  }
}


async function rewardInviter(inviterUsername, newUsername) {
  if (!inviterUsername || !newUsername) return;

  try {
    const inviterData = await USER_KV.get(inviterUsername, 'json');
    if (!inviterData) return;

    // به‌روزرسانی اطلاعات دعوت‌کننده
    inviterData.inviteCount = (inviterData.inviteCount || 0) + 1;
    inviterData.invitedUsers = inviterData.invitedUsers || [];
    inviterData.invitedUsers.push({
      username: newUsername,
      date: new Date().toISOString()
    });
    inviterData.secondaryCoins = (inviterData.secondaryCoins || 0) + INVITE_REWARD;
    
    await USER_KV.put(inviterUsername, JSON.stringify(inviterData));
  } catch (error) {
    console.error('Error rewarding inviter:', error);
  }
}


// توابع کمکی
async function createNewUser(username, inviteCode) {
  const newUser = {
    username,
    coins: 0,
    energy: 100,
    maxEnergy: 100,
    upgrades: {
      energy: 0,
      multiClick: 0,
      recharge: 0,
      autoClicker: 0
    },
    inviteCode: generateInviteCode(username),
    invitedBy: await processInviteCode(inviteCode),
    registeredAt: Date.now(),
    lastLogin: Date.now(),
    darkMode: true
  };

  await USER_KV.put(username, JSON.stringify(newUser));
  return newUser;
}

function generateInviteCode(username) {
  return `${username}-${Math.random().toString(36).substr(2, 8)}`;
}

async function processInviteCode(code) {
  if (!code) return null;
  
  try {
    const response = await fetch(`https://api.example.com/invites/validate?code=${encodeURIComponent(code)}`);
    const result = await response.json();
    return result.valid ? result.inviter : null;
  } catch {
    return null;
  }
}
/**
 * بررسی و تولید کد دعوت در صورت عدم وجود
 * @param {object} userData - اطلاعات کاربر
 * @returns {Promise<object>} اطلاعات کاربر با کد دعوت
 */
async function ensureInviteCode(userData) {
  // اگر کد دعوت وجود دارد و معتبر است، همان را برگردان
  if (userData.inviteCode && typeof userData.inviteCode === 'string' && userData.inviteCode.length >= 8) {
    return userData;
  }
  
  // در غیر این صورت کد جدید تولید کن
  userData.inviteCode = await generateStableInviteCode(userData.username);
  await USER_KV.put(userData.username, JSON.stringify(userData));
  return userData;
}

/**
 * مدیریت صفحه پروفایل کاربر
 * @param {string|null} usernameFromCookie - نام کاربری از کوکی
 * @param {URL} url - آدرس URL درخواست
 * @returns {Promise<Response>}
 */
// اصلاح شده با بررسی دقیق‌تر خطاها
async function serveProfilePage(username, userData, gameData) {
  try {
    // Validate user data
    if(!userData || typeof userData !== 'object') {
      userData = await USER_KV.get(username, 'json') || initializeUserData(username);
    }

    // Merge game data from cookie and KV
    const mergedGameData = {
      ...initializeGameData(),
      ...gameData,
      ...userData,
      upgrades: {
        ...initializeGameData().upgrades,
        ...(userData.upgrades || {})
      }
    };

    // Calculate current energy
    const now = Math.floor(Date.now()/1000);
    const updatedGameData = rechargeEnergy(mergedGameData, now);

    // Update data in KV
    await USER_KV.put(username, JSON.stringify({
      ...userData,
      ...updatedGameData,
      lastLogin: Date.now()
    }));

    return new Response(getProfileHTML(userData, updatedGameData), {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Set-Cookie': setGameDataCookie(updatedGameData)
      }
    });

  } catch (error) {
    console.error('Error serving profile:', error);
    return new Response(getErrorPageHTML('مشکل در بارگذاری پروفایل', error.message)), {
      status: 500,
      headers: {'Content-Type': 'text/html'}
    };
  }
}

function initializeUserData(username) {
  return {
    username,
    coins: 0,
    energy: 100,
    maxEnergy: 100,
    upgrades: {
      energy: 0,
      multiClick: 0,
      recharge: 0,
      autoClicker: 0
    },
    level: 'basic',
    lastDailyReset: Math.floor(Date.now()/1000),
    dailyTurbo: 3,
    dailyRefill: 3,
    registeredAt: Date.now(),
    lastLogin: Date.now()
  };
}

function getErrorHTML(title, message) {
  return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
      <style>
        body {
          font-family: Vazirmatn, sans-serif;
          text-align: center;
          padding: 2rem;
          background: #f8f9fa;
        }
        .error-box {
          max-width: 500px;
          margin: 2rem auto;
          padding: 2rem;
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .error-icon {
          font-size: 3rem;
          color: #dc3545;
          margin-bottom: 1rem;
        }
      </style>
    </head>
    <body>
      <div class="error-box">
        <div class="error-icon">⚠️</div>
        <h1>${title}</h1>
        <p>${message}</p>
        <p>لطفاً بعداً مجدداً تلاش کنید یا با پشتیبانی تماس بگیرید.</p>
        <a href="/" style="display: inline-block; margin-top: 1rem; padding: 0.5rem 1rem; background: #6c757d; color: white; text-decoration: none; border-radius: 4px;">
          بازگشت به صفحه اصلی
        </a>
      </div>
    </body>
    </html>
  `;
}



function setGameDataCookie(data) {
  return `gameData=${encodeURIComponent(JSON.stringify(data))}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}


/**
 * HTML صفحه پروفایل کاربر
 * @param {object} userData - اطلاعات کاربر
 * @param {object} gameData - داده‌های بازی
 * @returns {string} HTML صفحه پروفایل
 */
function getProfileHTML(userData, gameData) {
  // اعتبارسنجی و مقداردهی اولیه داده‌ها
  userData = userData || {};
  gameData = gameData || {};
  
  const isDarkMode = userData.darkMode !== false;
  const username = userData.username || "کاربر";
  const coins = Math.floor(gameData.coins || 0);
  const energy = Math.min(Math.floor(gameData.energy || 100), gameData.maxEnergy || 100);
  const maxEnergy = gameData.maxEnergy || 100;
  
  // اعتبارسنجی upgrades
  const upgrades = {
    energy: gameData.upgrades?.energy || 0,
    multiClick: gameData.upgrades?.multiClick || 0,
    recharge: gameData.upgrades?.recharge || 0,
    autoClicker: gameData.upgrades?.autoClicker || 0
  };

  // محاسبات مربوط به لیگ
  const leagueName = getLeagueName(coins);
  const trophyIcon = getTrophyIcon(leagueName);
  const leagueColor = getLeagueColor(leagueName);
  
  // وضعیت توربو
  const turboEndTime = gameData.turboEndTime || 0;
  const now = Math.floor(Date.now() / 1000);
  const turboActive = turboEndTime > now;
  
  // محاسبه ارزش هر کلیک
  const baseCoinValue = 1;
  const multiClickBonus = upgrades.multiClick ? upgrades.multiClick * 0.5 : 0;
  const turboMultiplier = turboActive ? 3 : 1;
  const coinValue = (baseCoinValue + multiClickBonus) * turboMultiplier;

  return `
  <!DOCTYPE html>
  <html lang="fa" dir="rtl">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>پروفایل ${username}</title>
      <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/font.css" rel="stylesheet">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
          :root {
              --primary: ${isDarkMode ? '#6a11cb' : '#2575fc'};
              --secondary: ${isDarkMode ? '#2575fc' : '#6a11cb'};
              --bg: ${isDarkMode ? '#121212' : '#f8f9fa'};
              --text: ${isDarkMode ? '#ffffff' : '#212529'};
              --card: ${isDarkMode ? '#1e1e1e' : '#ffffff'};
              --border: ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
              --coin: #FFD700;
              --energy: #FF6B35;
              --energy-fill: #FFA630;
              --league: ${leagueColor};
          }
          
          * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
              font-family: Vazirmatn, sans-serif;
              user-select: none;
          }
          
          body {
              background: var(--bg);
              color: var(--text);
              height: 100vh;
              overflow: hidden;
              position: relative;
          }
          
          .background-effect {
              position: fixed;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              background: radial-gradient(circle at center, var(--league) 0%, transparent 70%);
              opacity: 0.1;
              z-index: 0;
          }
          
          .coin-container {
              position: fixed;
              top: 50%;
              left: 50%;
              transform: translate(-50%, -50%);
              width: 70vmin;
              height: 70vmin;
              max-width: 300px;
              max-height: 300px;
              min-width: 200px;
              min-height: 200px;
              display: flex;
              flex-direction: column;
              align-items: center;
              justify-content: center;
              z-index: 10;
          }
          
          .coin-image {
              width: 100%;
              height: 100%;
              object-fit: contain;
              cursor: pointer;
              transition: transform 0.1s ease;
              filter: drop-shadow(0 5px 15px rgba(0,0,0,0.3));
              z-index: 15;
          }
          
          .coin-image:active {
              transform: scale(0.95);
          }
          
          .coin-info {
              position: absolute;
              top: -50px;
              display: flex;
              flex-direction: column;
              align-items: center;
              gap: 5px;
              z-index: 20;
              width: 100%;
          }
          
          .coin-text {
              color: var(--text);
              font-weight: bold;
              font-size: 1.5rem;
              text-shadow: 0 2px 5px rgba(0,0,0,0.3);
              display: flex;
              align-items: center;
              gap: 5px;
          }
          
          .league-text {
              color: var(--league);
              font-size: 1rem;
              text-shadow: 0 2px 5px rgba(0,0,0,0.3);
          }
          
          .energy-container {
              position: fixed;
              bottom: 1rem;
              right: 1rem;
              left: 1rem;
              max-width: 500px;
              margin: 0 auto;
              z-index: 20;
          }
          
          .energy-bar {
              height: 20px;
              width: 100%;
              background: ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
              border-radius: 10px;
              overflow: hidden;
          }
          
          .energy-fill {
              height: 100%;
              background: linear-gradient(90deg, var(--energy), var(--energy-fill));
              width: ${(energy / maxEnergy) * 100}%;
              transition: width 0.3s ease;
              border-radius: 10px;
          }
          
          .energy-info {
              display: flex;
              justify-content: space-between;
              margin-top: 5px;
              font-size: 0.9rem;
          }
          
          .turbo-indicator {
              position: fixed;
              top: 1rem;
              left: 1rem;
              background: var(--card);
              color: var(--text);
              padding: 0.5rem 1rem;
              border-radius: 50px;
              display: flex;
              align-items: center;
              gap: 0.5rem;
              font-size: 0.9rem;
              z-index: 20;
              box-shadow: 0 4px 15px rgba(0,0,0,0.1);
              border: 1px solid var(--border);
              animation: pulse 1.5s infinite;
          }
          
          .menu-container {
              position: fixed;
              bottom: 5rem;
              right: 1rem;
              display: flex;
              gap: 1rem;
              z-index: 20;
              background: var(--card);
              padding: 0.5rem;
              border-radius: 50px;
              box-shadow: 0 4px 15px rgba(0,0,0,0.1);
              border: 1px solid var(--border);
          }
          
          .menu-button {
              width: 50px;
              height: 50px;
              border-radius: 50%;
              background: var(--card);
              color: var(--text);
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 1.2rem;
              cursor: pointer;
              transition: all 0.3s ease;
              box-shadow: 0 4px 15px rgba(0,0,0,0.1);
              border: 1px solid var(--border);
              text-decoration: none;
          }
          
          .menu-button:hover {
              transform: translateY(-3px);
              background: var(--primary);
              color: white;
          }
          
          .coin-effect {
              position: absolute;
              color: white;
              font-weight: bold;
              font-size: 1.5rem;
              animation: floatUp 1s ease-out forwards;
              pointer-events: none;
              z-index: 20;
              text-shadow: 0 0 10px rgba(0,0,0,0.8);
          }
          
          .energy-alert {
              position: fixed;
              bottom: 5rem;
              left: 50%;
              transform: translateX(-50%);
              background: #ff4444;
              color: white;
              padding: 0.75rem 1.5rem;
              border-radius: 50px;
              font-size: 1rem;
              z-index: 1000;
              opacity: 0;
              transition: opacity 0.3s;
              box-shadow: 0 4px 15px rgba(0,0,0,0.2);
          }
          
          .energy-alert.show {
              opacity: 1;
          }
          
          @keyframes floatUp {
              0% { opacity: 1; transform: translateY(0); }
              100% { opacity: 0; transform: translateY(-100px); }
          }
          
          @keyframes pulse {
              0%, 100% { transform: scale(1); }
              50% { transform: scale(1.05); }
          }
          
          @media (max-width: 768px) {
              .coin-container {
                  width: 80vmin;
                  height: 80vmin;
              }
              
              .menu-container {
                  bottom: 6rem;
                  right: 50%;
                  transform: translateX(50%);
              }
          }
      </style>
  </head>
  <body>
      <div class="background-effect"></div>
      
      ${turboActive ? `
      <div class="turbo-indicator">
          <i class="fas fa-rocket"></i> توربو فعال
      </div>
      ` : ''}
      
      <div class="coin-container">
          <div class="coin-info">
              <div class="coin-text">
                  <i class="fas fa-coins"></i>
                  <span id="coinCounter">${coins}</span>
              </div>
              <div class="league-text">
                  ${trophyIcon} ${leagueName}
              </div>
          </div>
          <img src="https://raw.githubusercontent.com/animal-rush/esi/refs/heads/main/coin.png"  
               alt="سکه" 
               class="coin-image"
               id="coinImage"
               draggable="false">
      </div>
      
      <div class="menu-container">
          <a href="/invite" class="menu-button" title="دعوت دوستان">
              <i class="fas fa-user-plus"></i>
          </a>
          <a href="/upgrade" class="menu-button" title="فروشگاه ارتقاء">
              <i class="fas fa-level-up-alt"></i>
          </a>
          <a href="/leaderboard" class="menu-button" title="جدول رده‌بندی">
              <i class="fas fa-trophy"></i>
          </a>
      </div>
      
      <div class="energy-container">
          <div class="energy-bar">
              <div class="energy-fill" id="energyFill"></div>
          </div>
          <div class="energy-info">
              <span id="energyValue">${energy}</span>
              <span>/${maxEnergy}</span>
          </div>
      </div>
      
      <div class="energy-alert" id="energyAlert">انرژی شما تمام شده است!</div>
      
      <script>
          // وضعیت فعلی بازی
          const gameState = {
              coins: ${coins},
              energy: ${energy},
              maxEnergy: ${maxEnergy},
              upgrades: ${JSON.stringify(upgrades)},
              turboActive: ${turboActive},
              turboEndTime: ${turboEndTime},
              coinValue: ${coinValue},
              lastClick: 0,
              lastEnergyUpdate: ${now}
          };
          
          // عناصر DOM
          const coinImage = document.getElementById('coinImage');
          const coinCounter = document.getElementById('coinCounter');
          const energyValue = document.getElementById('energyValue');
          const energyFill = document.getElementById('energyFill');
          const energyAlert = document.getElementById('energyAlert');
          
          // مدیریت کلیک روی سکه
          async function handleCoinClick(e) {
              const now = Date.now();
              if(now - gameState.lastClick < 100) return;
              gameState.lastClick = now;
              
              const energyCost = 1 + Math.floor(gameState.upgrades.multiClick / 2);
              
              if(!gameState.turboActive && gameState.energy < energyCost) {
                  showEnergyAlert();
                  return;
              }
              
              createCoinEffect(e.clientX, e.clientY, "+" + gameState.coinValue);
              
              gameState.coins += gameState.coinValue;
              if(!gameState.turboActive) gameState.energy -= energyCost;
              
              updateDisplay();
              
              try {
                  await fetch('/click-coin', {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      credentials: 'include'
                  });
              } catch (error) {
                  console.error('Error saving click:', error);
              }
          }
          
          function createCoinEffect(x, y, value) {
              const effect = document.createElement('div');
              effect.className = 'coin-effect';
              effect.textContent = value;
              effect.style.left = x + 'px';
              effect.style.top = y + 'px';
              document.body.appendChild(effect);
              
              setTimeout(() => {
                  effect.remove();
              }, 1000);
          }
          
          function showEnergyAlert() {
              energyAlert.classList.add('show');
              
              setTimeout(() => {
                  energyAlert.classList.remove('show');
              }, 2000);
          }
          
          function updateDisplay() {
              coinCounter.textContent = Math.floor(gameState.coins);
              energyValue.textContent = gameState.energy;
              energyFill.style.width = (gameState.energy / gameState.maxEnergy) * 100 + '%';
              
              updateLeagueDisplay();
              
              if(gameState.turboActive) {
                  const remaining = gameState.turboEndTime - Math.floor(Date.now() / 1000);
                  if(remaining <= 0) {
                      gameState.turboActive = false;
                      document.querySelector('.turbo-indicator')?.remove();
                  }
              }
          }
          
          function updateLeagueDisplay() {
              const leagueName = getLeagueName(gameState.coins);
              const trophyIcon = getTrophyIcon(leagueName);
              const leagueColor = getLeagueColor(leagueName);
              
              const leagueText = document.querySelector('.league-text');
              if (leagueText) {
                  leagueText.innerHTML = \`\${trophyIcon} \${leagueName}\`;
                  leagueText.style.color = leagueColor;
              }
              
              document.querySelector('.background-effect').style.background = 
                  \`radial-gradient(circle at center, \${leagueColor} 0%, transparent 70%)\`;
          }
          
          function getLeagueName(coins) {
              if(coins >= 5000) return 'الماس';
              if(coins >= 2000) return 'پلاتین';
              if(coins >= 500) return 'طلا';
              if(coins >= 100) return 'نقره';
              return 'برنز';
          }
          
          function getTrophyIcon(league) {
              const icons = {
                  'الماس': '💎',
                  'پلاتین': '🏆',
                  'طلا': '🥇',
                  'نقره': '🥈',
                  'برنز': '🥉'
              };
              return icons[league] || '🎖️';
          }
          
          function getLeagueColor(league) {
              const colors = {
                  'الماس': '#b9f2ff',
                  'پلاتین': '#e5e4e2',
                  'طلا': '#ffd700',
                  'نقره': '#c0c0c0',
                  'برنز': '#cd7f32'
              };
              return colors[league] || '#6a11cb';
          }
          
          function rechargeEnergy() {
              const now = Math.floor(Date.now() / 1000);
              const secondsPassed = now - gameState.lastEnergyUpdate;
              const rechargeRate = 1 + (gameState.upgrades.recharge || 0);
              
              if(secondsPassed > 0) {
                  const energyToAdd = Math.floor(secondsPassed * rechargeRate);
                  if(energyToAdd > 0) {
                      gameState.energy = Math.min(gameState.maxEnergy, gameState.energy + energyToAdd);
                      gameState.lastEnergyUpdate = now;
                      updateDisplay();
                  }
              }
          }
          
          async function syncWithServer() {
              try {
                  const response = await fetch('/sync-game', {
                      credentials: 'include'
                  });
                  
                  if(response.ok) {
                      const data = await response.json();
                      Object.assign(gameState, data);
                      updateDisplay();
                  }
              } catch (error) {
                  console.error('Sync error:', error);
              }
          }
          
          function init() {
              coinImage.addEventListener('click', handleCoinClick);
              
              coinImage.addEventListener('touchstart', (e) => {
                  e.preventDefault();
                  const touch = e.touches[0];
                  handleCoinClick({
                      clientX: touch.clientX,
                      clientY: touch.clientY
                  });
              }, {passive: false});
              
              setInterval(rechargeEnergy, 1000);
              setInterval(syncWithServer, 30000);
              
              if(gameState.turboActive) {
                  const turboInterval = setInterval(() => {
                      const remaining = gameState.turboEndTime - Math.floor(Date.now() / 1000);
                      if(remaining <= 0) {
                          gameState.turboActive = false;
                          clearInterval(turboInterval);
                          document.querySelector('.turbo-indicator')?.remove();
                      }
                  }, 1000);
              }
              
              window.addEventListener('beforeunload', () => {
                  navigator.sendBeacon('/sync-game', JSON.stringify(gameState));
              });
          }
          
          document.addEventListener('DOMContentLoaded', init);
      </script>
  </body>
  </html>
  `;
}

// توابع کمکی خارجی
function getLeagueName(coins) {
  if(coins >= 5000) return 'الماس';
  if(coins >= 2000) return 'پلاتین';
  if(coins >= 500) return 'طلا';
  if(coins >= 100) return 'نقره';
  return 'برنز';
}

function getTrophyIcon(league) {
  const icons = {
    'الماس': '💎',
    'پلاتین': '🏆',
    'طلا': '🥇',
    'نقره': '🥈',
    'برنز': '🥉'
  };
  return icons[league] || '🎖️';
}

function getLeagueColor(league) {
  const colors = {
    'الماس': '#b9f2ff',
    'پلاتین': '#e5e4e2',
    'طلا': '#ffd700',
    'نقره': '#c0c0c0',
    'برنز': '#cd7f32'
  };
  return colors[league] || '#6a11cb';
}
/**
 * HTML صفحه مسدود بودن کاربر
 * @param {string} reason - دلیل مسدودیت
 * @param {string} remainingTime - زمان باقیمانده
 * @returns {string}
 */
function getBannedHTML(reason, remainingTime) {
  return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>حساب مسدود شده</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background: #f5f5f5;
                background-image: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            }
            .ban-container {
                background: #fff;
                padding: 2.5rem;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
                width: 90%;
                max-width: 500px;
                text-align: center;
                animation: fadeIn 0.5s ease;
                border-top: 5px solid #f44336;
            }
            .ban-icon {
                font-size: 4rem;
                color: #f44336;
                margin-bottom: 1.5rem;
                animation: pulse 1.5s infinite;
            }
            .ban-title {
                font-size: 1.8rem;
                margin-bottom: 1.5rem;
                color: #f44336;
                font-weight: 700;
            }
            .ban-reason {
                background: #ffebee;
                padding: 1.2rem;
                border-radius: 10px;
                margin-bottom: 1.5rem;
                border-right: 3px solid #f44336;
                text-align: right;
                font-size: 1.1rem;
            }
            .ban-time {
                font-weight: bold;
                margin-bottom: 2rem;
                font-size: 1.2rem;
                color: #333;
            }
            .logout-btn {
                background: #f44336;
                color: white;
                padding: 0.9rem 2rem;
                border: none;
                border-radius: 8px;
                font-size: 1.1rem;
                cursor: pointer;
                transition: all 0.3s ease;
                box-shadow: 0 4px 8px rgba(244, 67, 54, 0.3);
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }
            .logout-btn:hover {
                background: #d32f2f;
                transform: translateY(-3px);
                box-shadow: 0 6px 12px rgba(244, 67, 54, 0.4);
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            @keyframes pulse {
                0% { transform: scale(1); }
                50% { transform: scale(1.1); }
                100% { transform: scale(1); }
            }
            @media (max-width: 768px) {
                .ban-container {
                    padding: 1.8rem;
                }
                .ban-icon {
                    font-size: 3rem;
                }
                .ban-title {
                    font-size: 1.5rem;
                }
                .ban-reason {
                    font-size: 1rem;
                    padding: 1rem;
                }
                .logout-btn {
                    padding: 0.8rem 1.5rem;
                    font-size: 1rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="ban-container">
            <div class="ban-icon">
                <i class="fas fa-ban"></i>
            </div>
            <div class="ban-title">دسترسی محدود شده است!</div>
            <div class="ban-reason">
                <strong>دلیل مسدودیت:</strong><br>
                ${reason}
            </div>
            <div class="ban-time">
                <i class="fas fa-clock"></i> زمان باقیمانده: ${remainingTime}
            </div>
            <button class="logout-btn" onclick="window.location.href='/logout'">
                <i class="fas fa-sign-out-alt"></i> خروج از حساب
            </button>
        </div>
    </body>
    </html>
  `;
}

/**
 * مدیریت خروج کاربر
 * @returns {Response}
 */
function handleLogout() {
  return new Response(null, {
    status: 302,
    headers: {
      'Set-Cookie': `username=; Path=/; HttpOnly; Secure; Max-Age=0`,
      'Location': '/'
    }
  });
}

/**
 * مدیریت پنل ادمین
 * @param {Request} request
 * @returns {Promise<Response>}
 */
async function handleAdminPanel(request) {
  const url = new URL(request.url);
  const cookie = request.headers.get('cookie') || '';
  
  // بررسی احراز هویت
  if (!cookie.includes('admin_authenticated=true')) {
    return Response.redirect('/admin/login', 302);
  }

  try {
    // دریافت لیست کاربران
    const usersList = await USER_KV.list();
    const users = [];
    
    for (const key of usersList.keys) {
      const userData = await USER_KV.get(key.name, 'json');
      if (userData && !key.name.startsWith('invite:')) {
        users.push(userData);
      }
    }
    
    // مرتب‌سازی کاربران بر اساس تعداد سکه
    users.sort((a, b) => (b.coins || 0) - (a.coins || 0));
    
    return new Response(getAdminPanelHTML(users), {
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      }
    });
  } catch (error) {
    console.error('Admin panel error:', error);
    return new Response(getErrorHTML('خطا در پنل ادمین', error.message), {
      status: 500,
      headers: { 'Content-Type': 'text/html' }
    });
  }
}


async function handleRefreshAllUsers() {
  try {
    const usersList = await USER_KV.list();
    let updatedCount = 0;
    const failedUsers = [];
    
    for (const key of usersList.keys) {
      try {
        const userData = await USER_KV.get(key.name, 'json');
        if (userData && !userData.banned) {
          // Get updated data from API
          const apiResponse = await fetch('https://api.example.com/users/' + userData.username);
          
          if (apiResponse.ok) {
            const apiData = await apiResponse.json();
            
            // Update user data while preserving important fields
            const updatedUserData = {
              ...userData,
              coins: apiData.coins || userData.coins,
              handle: apiData.handle || userData.handle,
              lastUpdated: Math.floor(Date.now() / 1000),
              // Preserve other important fields
              secondaryCoins: userData.secondaryCoins || 0,
              energy: userData.energy || 100,
              level: userData.level || 'basic',
              inviteCode: userData.inviteCode || await generateInviteCode(userData.username),
              invitedBy: userData.invitedBy || null,
              inviteCount: userData.inviteCount || 0,
              invitedUsers: userData.invitedUsers || [],
              darkMode: userData.darkMode !== undefined ? userData.darkMode : true
            };
            
            await USER_KV.put(userData.username, JSON.stringify(updatedUserData));
            updatedCount++;
          } else {
            failedUsers.push(userData.username);
          }
        }
      } catch (error) {
        console.error(`Error updating user ${key.name}:`, error);
        failedUsers.push(key.name);
      }
    }
    
    const result = {
      success: true,
      message: `اطلاعات ${updatedCount} کاربر با موفقیت بروزرسانی شد`,
      count: updatedCount
    };
    
    if (failedUsers.length > 0) {
      result.warning = `${failedUsers.length} کاربر با خطا مواجه شدند`;
      result.failedUsers = failedUsers;
    }
    
    return new Response(JSON.stringify(result)), {
      headers: { 'Content-Type': 'application/json' }
    };
    
  } catch (error) {
    console.error('Error refreshing all users:', error);
    return new Response(JSON.stringify({ 
      success: false,
      error: 'خطا در بروزرسانی کاربران',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

function getBanEndTime(duration) {
  const now = Math.floor(Date.now() / 1000);
  const durations = {
    '5m': 300,
    '30m': 1800,
    '1h': 3600,
    '4h': 14400,
    '24h': 86400,
    'permanent': 0
  };
  
  return durations[duration] !== undefined ? 
    (durations[duration] === 0 ? 0 : now + durations[duration]) : 
    now + 300; // Default 5 minutes
}




/**
 * مدیریت عملیات ادمین


async function handleRefreshSingleUser(username) {
  try {
    const userData = await USER_KV.get(username, 'json');
    if (!userData) {
      return new Response(JSON.stringify({ 
        success: false,
        error: 'کاربر یافت نشد'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get updated data from API
    const apiResponse = await fetch('https://api.example.com/users/' + username);
    
    if (!apiResponse.ok) {
      throw new Error('خطا در دریافت اطلاعات کاربر از API');
    }

    const apiData = await apiResponse.json();
    
    // Update user data while preserving important fields
    const updatedUserData = {
      ...userData,
      coins: apiData.coins || userData.coins,
      handle: apiData.handle || userData.handle,
      lastUpdated: Math.floor(Date.now() / 1000),
      // Preserve other important fields
      secondaryCoins: userData.secondaryCoins || 0,
      energy: userData.energy || 100,
      level: userData.level || 'basic',
      inviteCode: userData.inviteCode || await generateInviteCode(userData.username),
      invitedBy: userData.invitedBy || null,
      inviteCount: userData.inviteCount || 0,
      invitedUsers: userData.invitedUsers || [],
      darkMode: userData.darkMode !== undefined ? userData.darkMode : true
    };
    
    await USER_KV.put(username, JSON.stringify(updatedUserData));
    
    return new Response(JSON.stringify({
      success: true,
      message: 'اطلاعات کاربر با موفقیت بروزرسانی شد',
      userData: updatedUserData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      success: false,
      error: 'خطا در بروزرسانی کاربر',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function handleGiveReward(username) {
  try {
    const userData = await USER_KV.get(username, 'json');
    if (!userData) {
      return new Response(JSON.stringify({ 
        success: false,
        error: 'کاربر یافت نشد'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Give reward
    const rewardAmount = 300;
    userData.coins = (userData.coins || 0) + rewardAmount;
    
    await USER_KV.put(username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({
      success: true,
      message: 'جایزه با موفقیت به کاربر داده شد',
      newCoins: userData.coins
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      success: false,
      error: 'خطا در اعطای جایزه',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * بروزرسانی اطلاعات تمام کاربران
 * @returns {Promise<Response>}
 */
async function handleRefreshAllUsers() {
  try {
    const usersList = await USER_KV.list();
    let updatedCount = 0;
    const failedUsers = [];
    
    for (const key of usersList.keys) {
      try {
        const userData = await USER_KV.get(key.name, 'json');
        if (userData && !userData.banned) {
          // Get updated data from API
          const apiResponse = await fetch('https://api.example.com/users/' + userData.username);
          
          if (apiResponse.ok) {
            const apiData = await apiResponse.json();
            
            // Update user data while preserving important fields
            const updatedUserData = {
              ...userData,
              coins: apiData.coins || userData.coins,
              handle: apiData.handle || userData.handle,
              lastUpdated: Math.floor(Date.now() / 1000),
              // Preserve other important fields
              secondaryCoins: userData.secondaryCoins || 0,
              energy: userData.energy || 100,
              level: userData.level || 'basic',
              inviteCode: userData.inviteCode || await generateInviteCode(userData.username),
              invitedBy: userData.invitedBy || null,
              inviteCount: userData.inviteCount || 0,
              invitedUsers: userData.invitedUsers || [],
              darkMode: userData.darkMode !== undefined ? userData.darkMode : true
            };
            
            await USER_KV.put(userData.username, JSON.stringify(updatedUserData));
            updatedCount++;
          } else {
            failedUsers.push(userData.username);
          }
        }
      } catch (error) {
        console.error(`Error updating user ${key.name}:`, error);
        failedUsers.push(key.name);
      }
    }
    
    const result = {
      success: true,
      message: `اطلاعات ${updatedCount} کاربر با موفقیت بروزرسانی شد`,
      count: updatedCount
    };
    
    if (failedUsers.length > 0) {
      result.warning = `${failedUsers.length} کاربر با خطا مواجه شدند`;
      result.failedUsers = failedUsers;
    }
    
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error refreshing all users:', error);
    return new Response(JSON.stringify({ 
      success: false,
      error: 'خطا در بروزرسانی کاربران',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

function getBanEndTime(duration) {
  const now = Math.floor(Date.now() / 1000);
  const durations = {
    '5m': 300,
    '30m': 1800,
    '1h': 3600,
    '4h': 14400,
    '24h': 86400,
    'permanent': 0
  };
  
  return durations[duration] !== undefined ? 
    (durations[duration] === 0 ? 0 : now + durations[duration]) : 
    now + 300; // Default 5 minutes
}

// تابع کمکی برای محاسبه زمان پایان مسدودیت
function getBanEndTime(duration) {
  const now = Math.floor(Date.now() / 1000);
  const durations = {
    '5m': 300,
    '30m': 1800,
    '1h': 3600,
    '4h': 14400,
    '24h': 86400,
    'permanent': 0
  };
  
  return durations[duration] !== undefined ? 
    (durations[duration] === 0 ? 0 : now + durations[duration]) : 
    now + 300; // پیش‌فرض 5 دقیقه
}

/**
 * مدیریت پنل کاربران
 * @param {string} usernameFromCookie
 * @param {string} panelId
 * @returns {Promise<Response>}
 */
async function handleUserPanel(usernameFromCookie, panelId) {
  if (!usernameFromCookie) {
    return Response.redirect('/', 302);
  }
  
  const userData = await USER_KV.get(usernameFromCookie, 'json');
  if (!userData) {
    return Response.redirect('/', 302);
  }
  
  // بررسی دسترسی کاربر به این پنل
  const userPanels = USER_PANELS[userData.level] || [];
  if (!userPanels.includes(panelId)) {
    return new Response(getAccessDeniedHTML(), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      status: 403
    });
  }
  
  // نمایش پنل مربوطه
  const panelHTML = getUserPanelHTML(panelId, userData);
  
  return new Response(panelHTML, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function getAccessDeniedHTML() {
  return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>دسترسی محدود</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background: #f5f5f5;
        }
        .access-denied {
          background: white;
          padding: 2rem;
          border-radius: 10px;
          box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
          text-align: center;
          max-width: 500px;
        }
        .icon {
          font-size: 3rem;
          color: #f44336;
          margin-bottom: 1rem;
        }
        .btn {
          background: #6a11cb;
          color: white;
          padding: 0.75rem 1.5rem;
          border: none;
          border-radius: 5px;
          margin-top: 1rem;
          cursor: pointer;
        }
      </style>
    </head>
    <body>
      <div class="access-denied">
        <div class="icon">⛔</div>
        <h1>دسترسی محدود</h1>
        <p>شما به این پنل دسترسی ندارید. برای دسترسی به این بخش باید سطح حساب خود را ارتقا دهید.</p>
        <button class="btn" onclick="window.location.href='/profile'">بازگشت به پروفایل</button>
      </div>
    </body>
    </html>
  `;
}

/**
 * مدیریت درخواست بروزرسانی اطلاعات
 * @param {string} usernameFromCookie
 * @param {URL} url
 * @returns {Promise<Response>}
 */

async function handleRefresh(usernameFromCookie, url) {
  if (!usernameFromCookie) {
    return Response.redirect('/', 302);
  }
  
  try {
    // دریافت اطلاعات کاربر فعلی
    const userData = await USER_KV.get(usernameFromCookie, 'json') || {};
    const currentEnergy = userData.energy || 0;
    
    // دریافت اطلاعات از API
    const apiResponse = await fetch('https://api.sizakgames.ir/shop/site_list_items/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: usernameFromCookie })
    });
    
    if (!apiResponse.ok) throw new Error('خطا در دریافت اطلاعات');
    
    const apiData = await apiResponse.json();
    
    // به‌روزرسانی اطلاعات با حفظ انرژی و سکه دوم
    userData.coins = apiData.coins;
    userData.handle = apiData.handle;
    userData.lastUpdated = Math.floor(Date.now() / 1000);
    userData.energy = currentEnergy; // حفظ انرژی فعلی
    
    await USER_KV.put(usernameFromCookie, JSON.stringify(userData));
    
    return Response.redirect('/profile', 302);
  } catch (error) {
    console.error('Refresh error:', error);
    return Response.redirect('/profile', 302);
  }
}

/**
 * HTML پنل کاربران
 * @param {string} panelId
 * @param {object} userData
 * @returns {string}
 */
function getAdminPanelHTML(users) {
  const levelNames = {
    'basic': 'عادی',
    'silver': 'نقره‌ای',
    'gold': 'طلایی',
    'platinum': 'پلاتینیوم',
    'vip': 'ویژه'
  };

  const levelColors = {
    'basic': '#E0E0E0',
    'silver': '#E0F7FA',
    'gold': '#FFF8E1',
    'platinum': '#F3E5F5',
    'vip': '#E8EAF6'
  };

  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>پنل مدیریت ادمین</title>
  <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/font.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --primary: #6a11cb;
      --secondary: #2575fc;
      --bg: #121212;
      --text: #ffffff;
      --card: #1e1e1e;
      --border: rgba(255, 255, 255, 0.1);
      --success: #4CAF50;
      --danger: #F44336;
      --warning: #FF9800;
      --info: #2196F3;
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: Vazirmatn, sans-serif;
    }
    
    body {
      background: var(--bg);
      color: var(--text);
    }
    
    .header {
      background: linear-gradient(to right, var(--primary), var(--secondary));
      padding: 1.5rem;
      text-align: center;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    
    .header h1 {
      font-size: 1.5rem;
      margin: 0;
    }
    
    .container {
      padding: 1.5rem;
      max-width: 1400px;
      margin: 0 auto;
      padding-bottom: 100px;
    }
    
    .search-box {
      display: flex;
      background: var(--card);
      border-radius: 8px;
      overflow: hidden;
      margin: 1.5rem 0;
      border: 1px solid var(--border);
    }
    
    .search-box input {
      flex: 1;
      padding: 0.75rem 1rem;
      background: transparent;
      border: none;
      color: var(--text);
      font-size: 1rem;
      outline: none;
    }
    
    .search-box button {
      padding: 0 1.5rem;
      background: var(--primary);
      color: white;
      border: none;
      cursor: pointer;
      transition: background 0.3s ease;
    }
    
    .search-box button:hover {
      background: var(--secondary);
    }
    
    .users-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 15px;
      margin-top: 20px;
    }
    
    .user-card {
      background: var(--card);
      border-radius: 10px;
      overflow: hidden;
      transition: transform 0.3s ease;
      border: 1px solid var(--border);
    }
    
    .user-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
    }
    
    .user-header {
      padding: 15px;
      border-bottom: 1px solid var(--border);
    }
    
    .user-main {
      display: flex;
      align-items: center;
      gap: 15px;
      margin-bottom: 10px;
    }
    
    .user-avatar {
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-weight: bold;
      font-size: 1.2rem;
      flex-shrink: 0;
    }
    
    .user-info {
      flex-grow: 1;
      overflow: hidden;
    }
    
    .username {
      font-weight: bold;
      font-size: 1.1rem;
      margin-bottom: 5px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    
    .user-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 0.8rem;
      color: rgba(255, 255, 255, 0.7);
    }
    
    .badge {
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: bold;
    }
    
    .level-badge {
      background: var(--level-color);
      color: #333;
    }
    
    .status-badge {
      background: var(--status-bg);
      color: var(--status-color);
    }
    
    .user-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    
    .action-btn {
      padding: 6px 10px;
      border-radius: 4px;
      font-size: 0.75rem;
      cursor: pointer;
      border: none;
      display: flex;
      align-items: center;
      gap: 5px;
      transition: all 0.2s;
      flex-grow: 1;
      justify-content: center;
    }
    
    .edit-btn { background: var(--info); color: white; }
    .coins-btn { background: var(--success); color: white; }
    .ban-btn { background: var(--warning); color: white; }
    .unban-btn { background: #9C27B0; color: white; }
    .delete-btn { background: var(--danger); color: white; }
    .refresh-btn { background: #607D8B; color: white; }
    .reward-btn { background: #FF5722; color: white; }
    
    .user-stats {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      padding: 15px;
    }
    
    .stat-item {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 8px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 6px;
    }
    
    .stat-value {
      font-weight: bold;
      font-size: 1rem;
    }
    
    .stat-label {
      font-size: 0.7rem;
      color: rgba(255, 255, 255, 0.6);
    }
    
    /* مودال‌ها */
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      z-index: 1000;
      justify-content: center;
      align-items: center;
    }
    
    .modal-content {
      background: var(--card);
      padding: 1.5rem;
      border-radius: 10px;
      width: 90%;
      max-width: 500px;
      box-shadow: 0 5px 30px rgba(0, 0, 0, 0.3);
      animation: modalFadeIn 0.3s ease;
      border: 1px solid var(--border);
    }
    
    .modal-title {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    
    .modal-close {
      background: none;
      border: none;
      font-size: 1.5rem;
      cursor: pointer;
      color: rgba(255, 255, 255, 0.6);
    }
    
    .modal-body {
      margin-bottom: 1.5rem;
    }
    
    .modal-input {
      width: 100%;
      padding: 0.75rem;
      margin-top: 0.5rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-family: inherit;
    }
    
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    
    .modal-btn {
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.2s;
    }
    
    .modal-btn-cancel {
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid var(--border);
      color: var(--text);
    }
    
    .modal-btn-confirm {
      background: var(--primary);
      color: white;
      border: none;
    }
    
    .modal-btn-confirm:hover {
      background: var(--secondary);
    }
    
    /* دکمه‌های ثابت */
    .fixed-btn {
      position: fixed;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
      z-index: 100;
      border: none;
      color: white;
    }
    
    .logout-btn {
      bottom: 1.5rem;
      left: 1.5rem;
      background: var(--danger);
    }
    
    .refresh-btn {
      bottom: 1.5rem;
      right: 1.5rem;
      background: var(--info);
    }
    
    @keyframes modalFadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    @media (max-width: 768px) {
      .users-grid {
        grid-template-columns: 1fr;
      }
      
      .fixed-btn {
        padding: 0.75rem 1rem;
        font-size: 0.9rem;
      }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>
      <i class="fas fa-user-shield"></i> پنل مدیریت ادمین
    </h1>
  </div>
  
  <div class="container">
    <div class="search-box">
      <input type="text" id="searchInput" placeholder="جستجوی کاربر..." oninput="searchUsers()">
      <button onclick="searchUsers()">
        <i class="fas fa-search"></i>
      </button>
    </div>
    
    <div class="users-grid" id="usersList">
      ${users.map(user => `
        <div class="user-card" data-username="${user.username}" data-status="${user.banned ? 'banned' : 'active'}">
          <div class="user-header">
            <div class="user-main">
              <div class="user-avatar">
                ${user.username ? user.username.charAt(0).toUpperCase() : '?'}
              </div>
              <div class="user-info">
                <div class="username" title="${user.username || 'نامشخص'}">${user.username || 'نامشخص'}</div>
                <div class="user-meta">
                  <span class="badge level-badge" 
                        style="--level-color: ${levelColors[user.level] || levelColors.basic}">
                    ${levelNames[user.level] || 'عادی'}
                  </span>
                  <span class="badge status-badge" 
                        style="--status-bg: ${user.banned ? 'rgba(255, 0, 0, 0.1)' : 'rgba(0, 255, 0, 0.1)'};
                               --status-color: ${user.banned ? '#ff6b6b' : '#4CAF50'}">
                    ${user.banned ? 'مسدود' : 'فعال'}
                  </span>
                </div>
              </div>
            </div>
            <div class="user-actions">
              <button class="action-btn edit-btn" onclick="showEditModal('${user.username}')">
                <i class="fas fa-edit"></i>
              </button>
              <button class="action-btn coins-btn" onclick="showCoinsModal('${user.username}')">
                <i class="fas fa-coins"></i>
              </button>
              <button class="action-btn ${user.banned ? 'unban-btn' : 'ban-btn'}" 
                onclick="showBanModal('${user.username}', ${!!user.banned})">
                <i class="fas ${user.banned ? 'fa-unlock' : 'fa-lock'}"></i>
              </button>
              <button class="action-btn delete-btn" onclick="showDeleteModal('${user.username}')">
                <i class="fas fa-trash"></i>
              </button>
              <button class="action-btn refresh-btn" onclick="refreshSingleUser('${user.username}')">
                <i class="fas fa-sync-alt"></i>
              </button>
              <button class="action-btn reward-btn" onclick="giveReward('${user.username}')">
                <i class="fas fa-gift"></i>
              </button>
            </div>
          </div>
          <div class="user-stats">
            <div class="stat-item">
              <span class="stat-value">${user.coins || 0}</span>
              <span class="stat-label">سکه‌ها</span>
            </div>
            <div class="stat-item">
              <span class="stat-value">${user.handle || 'ندارد'}</span>
              <span class="stat-label">اسم</span>
            </div>
            <div class="stat-item">
              <span class="stat-value">${user.energy || 0}</span>
              <span class="stat-label">انرژی</span>
            </div>
            <div class="stat-item">
              <span class="stat-value">${user.inviteCount || 0}</span>
              <span class="stat-label">دعوت‌ها</span>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
  </div>
  
  <!-- مودال ویرایش کاربر -->
  <div id="editModal" class="modal">
    <div class="modal-content">
      <div class="modal-title">
        <span>ویرایش کاربر</span>
        <button class="modal-close" onclick="closeModal('editModal')">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="editUsername">
        <div>
          <label>اسم:</label>
          <input type="text" id="editName" class="modal-input">
        </div>
        <div>
          <label>سطح:</label>
          <select id="editLevel" class="modal-input">
            <option value="basic">عادی</option>
            <option value="silver">نقره‌ای</option>
            <option value="gold">طلایی</option>
            <option value="platinum">پلاتینیوم</option>
            <option value="vip">ویژه</option>
          </select>
        </div>
        <div>
          <label>تم:</label>
          <select id="editTheme" class="modal-input">
            <option value="true">تیره</option>
            <option value="false">روشن</option>
          </select>
        </div>
      </div>
      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" onclick="closeModal('editModal')">انصراف</button>
        <button class="modal-btn modal-btn-confirm" onclick="updateUser()">ذخیره</button>
      </div>
    </div>
  </div>
  
  <!-- مودال مدیریت سکه‌ها -->
  <div id="coinsModal" class="modal">
    <div class="modal-content">
      <div class="modal-title">
        <span>مدیریت سکه‌های کاربر</span>
        <button class="modal-close" onclick="closeModal('coinsModal')">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="coinsUsername">
        <div>
          <label>عملیات:</label>
          <select id="coinsAction" class="modal-input" onchange="toggleCoinsAmount()">
            <option value="add">افزایش سکه</option>
            <option value="subtract">کاهش سکه</option>
            <option value="set">تنظیم مقدار دقیق</option>
            <option value="double">دو برابر کردن</option>
          </select>
        </div>
        <div id="coinsAmountContainer">
          <label>مقدار:</label>
          <input type="number" id="coinsAmount" class="modal-input" value="0">
        </div>
      </div>
      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" onclick="closeModal('coinsModal')">انصراف</button>
        <button class="modal-btn modal-btn-confirm" onclick="updateCoins()">تایید</button>
      </div>
    </div>
  </div>
  
  <!-- مودال مسدود کردن کاربر -->
  <div id="banModal" class="modal">
    <div class="modal-content">
      <div class="modal-title" id="banModalTitle">
        <span>مسدود کردن کاربر</span>
        <button class="modal-close" onclick="closeModal('banModal')">&times;</button>
      </div>
      <div class="modal-body" id="banFields">
        <input type="hidden" id="banUsername">
        <div>
          <label>مدت زمان:</label>
          <select id="banDuration" class="modal-input">
            <option value="5m">5 دقیقه</option>
            <option value="30m">30 دقیقه</option>
            <option value="1h">1 ساعت</option>
            <option value="4h">4 ساعت</option>
            <option value="24h">24 ساعت</option>
            <option value="permanent">دائمی</option>
          </select>
        </div>
        <div>
          <label>دلیل:</label>
          <input type="text" id="banReason" class="modal-input" placeholder="دلیل مسدودیت (اختیاری)">
        </div>
      </div>
      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" onclick="closeModal('banModal')">انصراف</button>
        <button class="modal-btn modal-btn-confirm" id="banConfirmBtn" onclick="banUser()">تایید</button>
      </div>
    </div>
  </div>
  
  <!-- مودال حذف کاربر -->
  <div id="deleteModal" class="modal">
    <div class="modal-content">
      <div class="modal-title">
        <span>حذف کاربر</span>
        <button class="modal-close" onclick="closeModal('deleteModal')">&times;</button>
      </div>
      <div class="modal-body">
        <input type="hidden" id="deleteUsername">
        <p>آیا مطمئن هستید که می‌خواهید این کاربر را حذف کنید؟ این عمل غیرقابل بازگشت است.</p>
      </div>
      <div class="modal-actions">
        <button class="modal-btn modal-btn-cancel" onclick="closeModal('deleteModal')">انصراف</button>
        <button class="modal-btn modal-btn-confirm" onclick="deleteUser()">حذف کاربر</button>
      </div>
    </div>
  </div>
  
  <button class="fixed-btn logout-btn" onclick="logoutAdmin()">
    <i class="fas fa-sign-out-alt"></i> خروج
  </button>
  
  <button class="fixed-btn refresh-btn" onclick="refreshAllUsers()">
    <i class="fas fa-sync-alt"></i> بروزرسانی همه
  </button>
  
  <script>
    // تابع جستجوی کاربران
    function searchUsers() {
      const input = document.getElementById('searchInput');
      const filter = input.value.toUpperCase();
      const usersList = document.getElementById('usersList');
      const userCards = usersList.getElementsByClassName('user-card');
      
      for (let i = 0; i < userCards.length; i++) {
        const username = userCards[i].getAttribute('data-username') || '';
        if (username.toUpperCase().indexOf(filter) > -1) {
          userCards[i].style.display = '';
        } else {
          userCards[i].style.display = 'none';
        }
      }
    }
    
    // نمایش مودال ویرایش
    async function showEditModal(username) {
      try {
        const modal = document.getElementById('editModal');
        const modalBody = modal.querySelector('.modal-body');
        
        // نمایش اسکلت بارگذاری
        modal.style.display = 'flex';
        modalBody.innerHTML = '<div style="text-align:center;padding:20px;"><i class="fas fa-spinner fa-spin fa-2x"></i><p>در حال دریافت اطلاعات کاربر...</p></div>';
        
        // دریافت اطلاعات کاربر
        const response = await fetch('/admin/user-data?username=' + encodeURIComponent(username));
        
        if (!response.ok) {
          throw new Error('خطا در دریافت اطلاعات: ' + response.status);
        }
        
        const userData = await response.json();
        
        // پر کردن فرم
        document.getElementById('editUsername').value = username;
        document.getElementById('editName').value = userData.handle || '';
        document.getElementById('editLevel').value = userData.level || 'basic';
        document.getElementById('editTheme').value = userData.darkMode !== false ? 'true' : 'false';
        
      } catch (error) {
        console.error('Error:', error);
        alert(error.message);
        closeModal('editModal');
      }
    }
    
    // نمایش مودال سکه‌ها
    async function showCoinsModal(username) {
      try {
        const response = await fetch('/admin/user-data?username=' + encodeURIComponent(username));
        if (response.ok) {
          const userData = await response.json();
          document.getElementById('coinsUsername').value = username;
          document.getElementById('coinsAmount').value = userData.coins || 0;
          document.getElementById('coinsModal').style.display = 'flex';
        } else {
          throw new Error('خطا در دریافت اطلاعات کاربر');
        }
      } catch (error) {
        console.error('Error:', error);
        alert(error.message);
      }
    }
    
    // نمایش/مخفی کردن مقدار سکه
    function toggleCoinsAmount() {
      const action = document.getElementById('coinsAction').value;
      const container = document.getElementById('coinsAmountContainer');
      container.style.display = action === 'double' ? 'none' : 'block';
    }
    
    // نمایش مودال مسدود کردن/رفع مسدودیت
    async function showBanModal(username, isBanned) {
      document.getElementById('banUsername').value = username;
      const modal = document.getElementById('banModal');
      const title = modal.querySelector('span');
      const btn = document.getElementById('banConfirmBtn');
      const fields = document.getElementById('banFields');
      
      if (isBanned) {
        title.textContent = 'رفع مسدودیت کاربر';
        fields.style.display = 'none';
        btn.textContent = 'رفع مسدودیت';
        btn.onclick = unbanUser;
      } else {
        title.textContent = 'مسدود کردن کاربر';
        fields.style.display = 'block';
        btn.textContent = 'مسدود کردن';
        btn.onclick = banUser;
      }
      
      modal.style.display = 'flex';
    }
    
    // نمایش مودال حذف
    function showDeleteModal(username) {
      document.getElementById('deleteUsername').value = username;
      document.getElementById('deleteModal').style.display = 'flex';
    }
    
    // بستن مودال
    function closeModal(modalId) {
      document.getElementById(modalId).style.display = 'none';
    }
    
    // به‌روزرسانی کاربر
    async function updateUser() {
      const username = document.getElementById('editUsername').value;
      const name = document.getElementById('editName').value;
      const level = document.getElementById('editLevel').value;
      const darkMode = document.getElementById('editTheme').value === 'true';
      
      try {
        const submitBtn = document.querySelector('#editModal .modal-btn-confirm');
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> در حال ذخیره...';
        submitBtn.disabled = true;
        
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'update_user',
            username: username,
            handle: name,
            level: level,
            darkMode: darkMode
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
        
        const submitBtn = document.querySelector('#editModal .modal-btn-confirm');
        submitBtn.innerHTML = 'ذخیره';
        submitBtn.disabled = false;
      }
    }

    // در اسکریپت پنل ادمین این توابع را اضافه کنید
 
    // به‌روزرسانی سکه‌ها
    async function updateCoins() {
      const username = document.getElementById('coinsUsername').value;
      const action = document.getElementById('coinsAction').value;
      const amount = parseInt(document.getElementById('coinsAmount').value) || 0;
      
      try {
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'update_coins',
            username: username,
            coins_action: action,
            coins_amount: amount
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
      }
    }
    
    // مسدود کردن کاربر
    async function banUser() {
      const username = document.getElementById('banUsername').value;
      const duration = document.getElementById('banDuration').value;
      const reason = document.getElementById('banReason').value || 'بدون دلیل مشخص';
      
      try {
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'ban_user',
            username: username,
            ban_duration: duration,
            ban_reason: reason
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
      }
    }
    
    // رفع مسدودیت کاربر
    async function unbanUser() {
      const username = document.getElementById('banUsername').value;
      
      try {
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'unban_user',
            username: username
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
      }
    }
    
    // حذف کاربر
    async function deleteUser() {
      const username = document.getElementById('deleteUsername').value;
      
      try {
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'delete_user',
            username: username
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
      }
    }
    
    // بروزرسانی کاربر خاص
    async function refreshSingleUser(username) {
      try {
        if (!confirm('آیا مطمئن هستید که می‌خواهید این کاربر را بروزرسانی کنید؟')) {
          return;
        }
        
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'refresh_single_user',
            username: username
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
      }
    }
    
    // اعطای جایزه به کاربر
    async function giveReward(username) {
      try {
        if (!confirm('آیا مطمئن هستید که می‌خواهید به این کاربر 300 سکه جایزه دهید؟')) {
          return;
        }
        
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            action: 'give_reward',
            username: username
          })
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert('جایزه با موفقیت اعطا شد. موجودی جدید: ' + result.newCoins + ' سکه');
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
      }
    }
    
    // بروزرسانی همه کاربران
    async function refreshAllUsers() {
      try {
        if (!confirm('آیا مطمئن هستید که می‌خواهید اطلاعات همه کاربران را بروزرسانی کنید؟')) {
          return;
        }
        
        const refreshBtn = document.querySelector('.refresh-btn');
        refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> در حال بروزرسانی...';
        refreshBtn.disabled = true;
        
        const response = await fetch('/admin/actions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'action=refresh_all_users'
        });
        
        if (!response.ok) throw new Error(await response.text());
        
        const result = await response.json();
        alert(result.message);
        location.reload();
        
      } catch (error) {
        console.error('Error:', error);
        alert('خطا: ' + error.message);
        
        const refreshBtn = document.querySelector('.refresh-btn');
        refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> بروزرسانی همه';
        refreshBtn.disabled = false;
      }
    }
    
    // خروج از پنل ادمین
    function logoutAdmin() {
      document.cookie = 'admin_authenticated=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
      window.location.href = '/admin/login';
    }
  </script>
</body>
</html>`;
}

/**
 * HTML پنل مدیریت ادمین
 * @param {Array} users
 * @returns {string}
 */
/**
 * HTML پنل مدیریت ادمین
 * @param {Array} users
 * @returns {string}
 */
function getAdminLoginHTML(errorMessage = '') {
  return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ورود ادمین</title>
      <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/font.css" rel="stylesheet">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: Vazirmatn, sans-serif;
        }
        
        body {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 1rem;
        }
        
        .login-container {
          width: 100%;
          max-width: 400px;
          background: rgba(255, 255, 255, 0.05);
          border-radius: 15px;
          padding: 2rem;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
          backdrop-filter: blur(10px);
          border: 1px solid rgba(255, 255, 255, 0.1);
          animation: fadeIn 0.5s ease;
        }
        
        .login-header {
          text-align: center;
          margin-bottom: 2rem;
          color: white;
        }
        
        .login-header i {
          font-size: 2.5rem;
          margin-bottom: 1rem;
          color: #6a11cb;
        }
        
        .login-header h1 {
          font-size: 1.5rem;
        }
        
        .error-message {
          background: rgba(255, 0, 0, 0.1);
          color: #ff6b6b;
          padding: 0.75rem;
          border-radius: 8px;
          margin-bottom: 1.5rem;
          text-align: center;
          border: 1px solid rgba(255, 0, 0, 0.2);
          animation: shake 0.5s;
        }
        
        .login-form {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
        }
        
        .input-group {
          position: relative;
        }
        
        .input-group i {
          position: absolute;
          left: 15px;
          top: 50%;
          transform: translateY(-50%);
          color: rgba(255, 255, 255, 0.5);
        }
        
        input {
          width: 100%;
          padding: 0.75rem 0.75rem 0.75rem 40px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          color: white;
          font-size: 1rem;
          transition: all 0.3s ease;
        }
        
        input:focus {
          border-color: #6a11cb;
          box-shadow: 0 0 0 3px rgba(106, 17, 203, 0.3);
          outline: none;
        }
        
        button {
          width: 100%;
          padding: 0.75rem;
          background: linear-gradient(to right, #6a11cb, #2575fc);
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 1rem;
          font-weight: bold;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }
        
        button:hover {
          transform: translateY(-2px);
          box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        
        .loading {
          pointer-events: none;
          opacity: 0.7;
        }
        
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          20%, 60% { transform: translateX(-5px); }
          40%, 80% { transform: translateX(5px); }
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="login-header">
          <i class="fas fa-user-shield"></i>
          <h1>ورود به پنل مدیریت</h1>
        </div>
        
        ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
        
        <form class="login-form" method="POST" action="/admin/login">
          <div class="input-group">
            <i class="fas fa-key"></i>
            <input type="password" name="password" placeholder="رمز عبور" required>
          </div>
          <button type="submit" id="loginBtn">
            <i class="fas fa-sign-in-alt"></i> ورود
          </button>
        </form>
      </div>

      <script>
        const loginForm = document.querySelector('.login-form');
        const loginBtn = document.getElementById('loginBtn');
        
        loginForm.addEventListener('submit', function(e) {
          e.preventDefault();
          
          loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> در حال ورود...';
          loginBtn.classList.add('loading');
          
          // ارسال فرم
          this.submit();
        });
      </script>
    </body>
    </html>
  `;
}



/**
 * محاسبه زمان پایان مسدودیت
 * @param {string} duration
 * @returns {number}
 */
function getBanEndTime(duration) {
  const now = Math.floor(Date.now() / 1000);
  
  const durations = {
    '5m': 300,
    '30m': 1800,
    '1h': 3600,
    '4h': 14400,
    '24h': 86400,
    'permanent': 0
  };
  
  return durations[duration] !== undefined ? 
    (durations[duration] === 0 ? 0 : now + durations[duration]) : 
    now + 300; // پیش‌فرض 5 دقیقه
}
/**
 * تبدیل ثانیه به زمان قابل خواندن
 * @param {number} seconds
 * @returns {string}
 */


/**
 * تبدیل تایمستمپ به تاریخ قابل خواندن
 * @param {number} timestamp
 * @returns {string}
 */
function formatDate(timestamp) {
  if (!timestamp) return 'نامشخص';
  const date = new Date(timestamp * 1000);
  return date.toLocaleString('fa-IR');
}

/**
 * دریافت نام پنل
 * @param {string} panelId
 * @returns {string}
 */
function getPanelName(panelId) {
  switch (panelId) {
    case 'panel1': return 'مدیریت سکه‌ها';
    case 'panel2': return 'آمار و اطلاعات';
    case 'panel3': return 'تنظیمات پیشرفته';
    case 'panel4': return 'پنل ویژه';
    default: return 'پنل کاربری';
  }
}

/**
 * دریافت آیکون پنل
 * @param {string} panelId
 * @returns {string}
 */
function getPanelIcon(panelId) {
  switch (panelId) {
    case 'panel1': return 'fa-coins';
    case 'panel2': return 'fa-chart-bar';
    case 'panel3': return 'fa-cogs';
    case 'panel4': return 'fa-crown';
    default: return 'fa-user';
  }
}


async function handleInvitePage(request) {
  try {
    const cookie = request.headers.get('cookie') || '';
    const username = getUsernameFromCookie(cookie);
    
    if (!username) {
      return Response.redirect('/', 302);
    }

    const userData = await USER_KV.get(username, 'json') || {};
    
    // Ensure user has a valid invite code
    if (!userData.inviteCode || typeof userData.inviteCode !== 'string' || userData.inviteCode.length < 8) {
      userData.inviteCode = await generateStableInviteCode(username);
      await USER_KV.put(username, JSON.stringify(userData));
      await USER_KV.put(`invite:${userData.inviteCode}`, username);
    }

    // Check if this is a POST request (claiming reward)
    if (request.method === 'POST') {
      return handleInviteReward(request, userData);
    }

    return new Response(await getInvitePageHTML(userData, request), {
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }
    });

  } catch (error) {
    console.error('Error in handleInvitePage:', error);
    return new Response(getErrorHTML('خطا در بارگذاری صفحه دعوت', error.message), {
      status: 500,
      headers: { 'Content-Type': 'text/html' }
    });
  }
}

async function handleInviteReward(request, userData) {
  try {
    const formData = await request.formData();
    const rewardId = formData.get('rewardId');
    
    if (!rewardId) {
      return new Response(JSON.stringify({ error: 'شناسه جایزه نامعتبر است' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify reward eligibility
    if (userData.claimedRewards?.includes(rewardId)) {
      return new Response(JSON.stringify({ error: 'این جایزه قبلاً دریافت شده است' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Add reward
    const rewardAmount = 300;
    userData.secondaryCoins = (userData.secondaryCoins || 0) + rewardAmount;
    userData.claimedRewards = userData.claimedRewards || [];
    userData.claimedRewards.push(rewardId);
    
    await USER_KV.put(userData.username, JSON.stringify(userData));
    
    return new Response(JSON.stringify({ 
      success: true,
      newCoins: userData.secondaryCoins
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Error claiming invite reward:', error);
    return new Response(JSON.stringify({ 
      error: 'خطا در دریافت جایزه',
      details: error.message
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function getInvitePageHTML(userData, request) {
  const url = new URL(request.url);
  const inviteLink = `${url.origin}/?invite=${encodeURIComponent(userData.inviteCode)}`;
  const shareText = `به بازی سکه‌ها بپیوندید! از کد دعوت ${userData.inviteCode} استفاده کنید و ${INVITE_REWARD} سکه رایگان دریافت کنید!`;

  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>دعوت دوستان</title>
  <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/font.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --primary: #6a11cb;
      --secondary: #2575fc;
      --bg: #121212;
      --text: #ffffff;
      --card: #1e1e1e;
      --border: rgba(255,255,255,0.1);
      --success: #4CAF50;
      --coin: #FFD700;
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      font-family: Vazirmatn, sans-serif;
    }
    
    body {
      background: var(--bg);
      color: var(--text);
      padding: 20px;
    }
    
    .header {
      display: flex;
      align-items: center;
      gap: 15px;
      margin-bottom: 25px;
    }
    
    .back-btn {
      background: var(--card);
      border: none;
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      color: var(--text);
    }
    
    .title {
      font-size: 1.5rem;
    }
    
    .stats-container {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-bottom: 25px;
    }
    
    .stat-card {
      background: var(--card);
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      border: 1px solid var(--border);
    }
    
    .stat-value {
      font-size: 1.8rem;
      font-weight: bold;
      color: var(--coin);
      margin: 10px 0;
    }
    
    .stat-label {
      font-size: 0.9rem;
      opacity: 0.8;
    }
    
    .invite-section {
      background: var(--card);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 25px;
      border: 1px solid var(--border);
    }
    
    .section-title {
      font-size: 1.2rem;
      margin-bottom: 15px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .invite-code-container {
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 20px 0;
    }
    
    .invite-code {
      flex: 1;
      background: rgba(255,255,255,0.05);
      padding: 15px;
      border-radius: 8px;
      font-family: monospace;
      font-size: 1.1rem;
      text-align: center;
      word-break: break-all;
    }
    
    .copy-btn {
      background: var(--primary);
      color: white;
      border: none;
      padding: 15px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.3s ease;
    }
    
    .copy-btn:hover {
      background: var(--secondary);
    }
    
    .invite-link {
      margin: 20px 0;
      word-break: break-all;
      padding: 15px;
      background: rgba(255,255,255,0.05);
      border-radius: 8px;
    }
    
    .share-buttons {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }
    
    .share-btn {
      flex: 1;
      min-width: 120px;
      padding: 12px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: all 0.3s ease;
    }
    
    .telegram {
      background: #0088cc;
      color: white;
    }
    
    .whatsapp {
      background: #25D366;
      color: white;
    }
    
    .other {
      background: var(--card);
      color: var(--text);
      border: 1px solid var(--border);
    }
    
    .invited-users {
      margin-top: 30px;
    }
    
    .user-list {
      margin-top: 15px;
    }
    
    .user-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px solid var(--border);
    }
    
    .user-name {
      font-weight: bold;
    }
    
    .user-date {
      font-size: 0.8rem;
      opacity: 0.7;
    }
    
    .empty-state {
      text-align: center;
      padding: 40px 0;
      opacity: 0.7;
    }
    
    .notification {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--success);
      color: white;
      padding: 15px 25px;
      border-radius: 8px;
      box-shadow: 0 5px 15px rgba(0,0,0,0.2);
      transform: translateY(100px);
      opacity: 0;
      transition: all 0.3s ease;
      z-index: 1000;
    }
    
    .notification.show {
      transform: translateY(0);
      opacity: 1;
    }
    
    .reward-banner {
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      padding: 15px;
      border-radius: 8px;
      margin: 20px 0;
      text-align: center;
      display: ${userData.inviteCount >= 3 && !userData.claimedRewards?.includes('invite_3') ? 'block' : 'none'};
    }
    
    .reward-btn {
      background: white;
      color: var(--primary);
      border: none;
      padding: 8px 16px;
      border-radius: 20px;
      margin-top: 10px;
      font-weight: bold;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="header">
    <button class="back-btn" onclick="window.location.href='/profile'">
      <i class="fas fa-arrow-left"></i>
    </button>
    <h1 class="title">دعوت دوستان</h1>
  </div>
  
  <div class="stats-container">
    <div class="stat-card">
      <div class="stat-label">تعداد دعوت‌ها</div>
      <div class="stat-value">${userData.inviteCount || 0}</div>
      <div class="stat-label">دوستان دعوت شده</div>
    </div>
    
    <div class="stat-card">
      <div class="stat-label">سکه‌های کسب شده</div>
      <div class="stat-value">${(userData.inviteCount || 0) * INVITE_REWARD}</div>
      <div class="stat-label">از طریق دعوت</div>
    </div>
  </div>
  
  <div class="reward-banner" id="rewardBanner">
    <h3>تبریک! شما ۳ دعوت موفق داشته‌اید</h3>
    <p>جایزه ۳۰۰ سکه‌ای خود را دریافت کنید</p>
    <button class="reward-btn" onclick="claimReward()">دریافت جایزه</button>
  </div>
  
  <div class="invite-section">
    <h2 class="section-title">
      <i class="fas fa-user-plus"></i>
      کد دعوت شما
    </h2>
    
    <p>با دعوت هر دوست ${INVITE_REWARD} سکه رایگان دریافت کنید!</p>
    
    <div class="invite-code-container">
      <div class="invite-code" id="inviteCode">${userData.inviteCode}</div>
      <button class="copy-btn" onclick="copyInviteCode()">
        <i class="fas fa-copy"></i>
      </button>
    </div>
    
    <p>یا از لینک دعوت زیر استفاده کنید:</p>
    <div class="invite-link" id="inviteLink">${inviteLink}</div>
    
    <div class="share-buttons">
      <button class="share-btn telegram" onclick="shareToTelegram()">
        <i class="fab fa-telegram"></i> تلگرام
      </button>
      <button class="share-btn whatsapp" onclick="shareToWhatsApp()">
        <i class="fab fa-whatsapp"></i> واتساپ
      </button>
      <button class="share-btn other" onclick="shareToOther()">
        <i class="fas fa-share-alt"></i> سایر
      </button>
    </div>
  </div>
  
  <div class="invited-users">
    <h2 class="section-title">
      <i class="fas fa-users"></i>
      دوستان دعوت شده
    </h2>
    
    <div class="user-list">
      ${userData.invitedUsers?.length > 0 ? 
        userData.invitedUsers.map(user => `
          <div class="user-item">
            <span class="user-name">${escapeHtml(user.username)}</span>
            <span class="user-date">${new Date(user.date).toLocaleDateString('fa-IR')}</span>
          </div>
        `).join('') : `
        <div class="empty-state">
          <i class="fas fa-user-friends" style="font-size: 2rem; margin-bottom: 10px;"></i>
          <p>هنوز دوستی دعوت نکرده‌اید</p>
        </div>
      `}
    </div>
  </div>
  
  <div class="notification" id="notification"></div>
  
  <script>
    function copyInviteCode() {
      const code = document.getElementById('inviteCode').textContent;
      navigator.clipboard.writeText(code)
        .then(() => showNotification('کد دعوت با موفقیت کپی شد!'))
        .catch(() => {
          // Fallback for older browsers
          const textarea = document.createElement('textarea');
          textarea.value = code;
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
          showNotification('کد دعوت کپی شد!');
        });
    }
    
    function shareToTelegram() {
      const text = encodeURIComponent('${escapeHtml(shareText)}');
      const url = encodeURIComponent('${inviteLink}');
      window.open('https://t.me/share/url?url=' + url + '&text=' + text, '_blank');
    }
    
    function shareToWhatsApp() {
      const text = encodeURIComponent('${escapeHtml(shareText)}');
      window.open('https://wa.me/?text=' + text, '_blank');
    }
    
    function shareToOther() {
      const text = '${escapeHtml(shareText)}';
      if (navigator.share) {
        navigator.share({
          title: 'دعوت به بازی سکه‌ها',
          text: text,
          url: '${inviteLink}'
        }).catch(err => {
          console.log('Error sharing:', err);
        });
      } else {
        copyInviteCode();
        showNotification('لینک دعوت کپی شد، می‌توانید آن را در برنامه مورد نظر paste کنید');
      }
    }
    
    async function claimReward() {
      try {
        const btn = document.querySelector('.reward-btn');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> در حال پردازش...';
        btn.disabled = true;
        
        const response = await fetch('/invite', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'rewardId=invite_3'
        });
        
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.error || 'خطا در دریافت جایزه');
        }
        
        const result = await response.json();
        showNotification('جایزه با موفقیت دریافت شد! ۳۰۰ سکه به حساب شما اضافه شد');
        document.getElementById('rewardBanner').style.display = 'none';
        
      } catch (error) {
        showNotification(error.message, false);
        console.error('Error claiming reward:', error);
      }
    }
    
    function showNotification(message, isSuccess = true) {
      const notification = document.getElementById('notification');
      notification.textContent = message;
      notification.style.background = isSuccess ? 'var(--success)' : 'var(--danger)';
      notification.classList.add('show');
      
      setTimeout(() => {
        notification.classList.remove('show');
      }, 3000);
    }
  </script>
</body>
</html>`;
}

// Helper function to escape HTML

// Helper function to escape HTML
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}







function getUpgradeHTML(userData) {
  const upgrades = userData.upgrades || {
    energy: 0,
    multiClick: 0,
    recharge: 0,
    autoClicker: 0
  };

  const turboTime = userData.turboEndTime ? 
    Math.max(0, userData.turboEndTime - Math.floor(Date.now()/1000)) : 0;

  const isDarkMode = userData.darkMode !== undefined ? userData.darkMode : true;

  return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl" class="${isDarkMode ? 'dark-mode' : ''}">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>فروشگاه ارتقاء</title>
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
        :root {
          --primary: ${isDarkMode ? '#6a11cb' : '#2575fc'};
          --secondary: ${isDarkMode ? '#2575fc' : '#6a11cb'};
          --bg: ${isDarkMode ? '#121212' : '#f8f9fa'};
          --text: ${isDarkMode ? '#ffffff' : '#212529'};
          --card: ${isDarkMode ? '#1e1e1e' : '#ffffff'};
          --border: ${isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'};
          --success: #4CAF50;
          --warning: #FFC107;
          --danger: #F44336;
          --info: #2196F3;
          --coin: #FFD700;
          --energy: #FF6B35;
        }
        
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: 'Vazirmatn', sans-serif;
        }
        
        body {
          background: var(--bg);
          color: var(--text);
          min-height: 100vh;
          padding: 20px;
        }
        
        .header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          padding-bottom: 15px;
          border-bottom: 1px solid var(--border);
        }
        
        .back-btn {
          background: var(--card);
          border: none;
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          color: var(--text);
          box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .coins-display {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 1.2rem;
          font-weight: bold;
        }
        
        .coins-display i {
          color: var(--coin);
        }
        
        .boosts-section {
          margin: 25px 0;
        }
        
        .section-title {
          font-size: 1.1rem;
          margin-bottom: 15px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        
        .boosts-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
          gap: 15px;
        }
        
        .boost-card {
          background: var(--card);
          border-radius: 12px;
          padding: 15px;
          box-shadow: 0 3px 10px rgba(0,0,0,0.1);
          transition: transform 0.3s ease;
          border: 1px solid var(--border);
        }
        
        .boost-card:hover {
          transform: translateY(-5px);
        }
        
        .boost-card.disabled {
          opacity: 0.6;
          pointer-events: none;
        }
        
        .boost-header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 10px;
        }
        
        .boost-icon {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.2rem;
        }
        
        .turbo-icon {
          background: rgba(255, 193, 7, 0.2);
          color: var(--warning);
        }
        
        .refill-icon {
          background: rgba(33, 150, 243, 0.2);
          color: var(--info);
        }
        
        .boost-title {
          font-weight: bold;
          font-size: 1rem;
        }
        
        .boost-desc {
          font-size: 0.85rem;
          color: ${isDarkMode ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.6)'};
          margin-bottom: 15px;
        }
        
        .boost-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .boost-count {
          font-size: 0.9rem;
          color: ${isDarkMode ? 'rgba(255,255,255,0.5)' : 'rgba(0,0,0,0.5)'};
        }
        
        .boost-btn {
          padding: 8px 15px;
          border-radius: 8px;
          border: none;
          background: var(--primary);
          color: white;
          font-weight: bold;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
          gap: 5px;
        }
        
        .boost-btn:hover {
          background: var(--secondary);
          transform: translateY(-2px);
        }
        
        .boost-btn:disabled {
          background: ${isDarkMode ? '#333' : '#ddd'};
          color: ${isDarkMode ? '#666' : '#888'};
          cursor: not-allowed;
        }
        
        .timer {
          font-size: 0.8rem;
          color: var(--warning);
          margin-top: 5px;
        }
        
        .upgrades-section {
          margin-top: 30px;
        }
        
        .upgrades-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 15px;
        }
        
        .upgrade-card {
          background: var(--card);
          border-radius: 12px;
          padding: 15px;
          box-shadow: 0 3px 10px rgba(0,0,0,0.1);
          transition: transform 0.3s ease;
          border: 1px solid var(--border);
        }
        
        .upgrade-card:hover {
          transform: translateY(-5px);
        }
        
        .upgrade-header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 10px;
        }
        
        .upgrade-icon {
          width: 40px;
          height: 40px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 1.2rem;
          background: rgba(106, 17, 203, 0.2);
          color: var(--primary);
        }
        
        .upgrade-title {
          font-weight: bold;
          font-size: 1rem;
        }
        
        .upgrade-desc {
          font-size: 0.85rem;
          color: ${isDarkMode ? 'rgba(255,255,255,0.7)' : 'rgba(0,0,0,0.6)'};
          margin-bottom: 10px;
        }
        
        .upgrade-level {
          font-size: 0.9rem;
          margin-bottom: 5px;
        }
        
        .upgrade-price {
          display: flex;
          align-items: center;
          gap: 5px;
          font-weight: bold;
          margin-bottom: 15px;
        }
        
        .upgrade-btn {
          width: 100%;
          padding: 10px;
          border-radius: 8px;
          border: none;
          background: var(--primary);
          color: white;
          font-weight: bold;
          cursor: pointer;
          transition: all 0.3s ease;
        }
        
        .upgrade-btn:hover {
          background: var(--secondary);
        }
        
        .upgrade-btn:disabled {
          background: ${isDarkMode ? '#333' : '#ddd'};
          color: ${isDarkMode ? '#666' : '#888'};
          cursor: not-allowed;
        }
        
        .notification {
          position: fixed;
          bottom: 20px;
          right: 20px;
          background: var(--success);
          color: white;
          padding: 15px 20px;
          border-radius: 8px;
          box-shadow: 0 5px 15px rgba(0,0,0,0.2);
          transform: translateY(100px);
          opacity: 0;
          transition: all 0.3s ease;
          z-index: 1000;
        }
        
        .notification.show {
          transform: translateY(0);
          opacity: 1;
        }
        
        @media (max-width: 768px) {
          .boosts-grid, .upgrades-grid {
            grid-template-columns: 1fr;
          }
        }
      </style>
    </head>
    <body>
      <div class="header">
        <button class="back-btn" onclick="window.location.href='/profile'">
          <i class="fas fa-arrow-left"></i>
        </button>
        <div class="coins-display">
          <i class="fas fa-coins"></i>
          <span id="coinsValue">${userData.secondaryCoins || 0}</span>
        </div>
      </div>
      
      <div class="boosts-section">
        <h3 class="section-title">
          <i class="fas fa-bolt"></i>
          تقویت‌کننده‌های روزانه
        </h3>
        
        <div class="boosts-grid">
          <div class="boost-card ${userData.dailyTurbo <= 0 ? 'disabled' : ''}">
            <div class="boost-header">
              <div class="boost-icon turbo-icon">
                <i class="fas fa-rocket"></i>
              </div>
              <div class="boost-title">حالت توربو</div>
            </div>
            <div class="boost-desc">
              برای 30 ثانیه هر کلیک 3 سکه به شما می‌دهد!
            </div>
            <div class="boost-footer">
              <div class="boost-count">${userData.dailyTurbo || 0}/3 باقی مانده</div>
              <button 
                class="boost-btn" 
                onclick="useBoost('turbo')" 
                ${userData.dailyTurbo <= 0 ? 'disabled' : ''}
              >
                <i class="fas fa-play"></i> فعال‌سازی
              </button>
            </div>
            ${turboTime > 0 ? `
              <div class="timer">
                <i class="fas fa-clock"></i> ${turboTime} ثانیه باقی‌مانده
              </div>
            ` : ''}
          </div>
          
          <div class="boost-card ${userData.dailyRefill <= 0 ? 'disabled' : ''}">
            <div class="boost-header">
              <div class="boost-icon refill-icon">
                <i class="fas fa-battery-full"></i>
              </div>
              <div class="boost-title">شارژ انرژی</div>
            </div>
            <div class="boost-desc">
              انرژی شما را کاملاً شارژ می‌کند
            </div>
            <div class="boost-footer">
              <div class="boost-count">${userData.dailyRefill || 0}/3 باقی مانده</div>
              <button 
                class="boost-btn" 
                onclick="useBoost('refill')" 
                ${userData.dailyRefill <= 0 ? 'disabled' : ''}
              >
                <i class="fas fa-bolt"></i> استفاده
              </button>
            </div>
          </div>
        </div>
      </div>
      
      <div class="upgrades-section">
        <h3 class="section-title">
          <i class="fas fa-level-up-alt"></i>
          ارتقاء دائمی
        </h3>
        
        <div class="upgrades-grid">
          <div class="upgrade-card">
            <div class="upgrade-header">
              <div class="upgrade-icon">
                <i class="fas fa-battery-three-quarters"></i>
              </div>
              <div>
                <div class="upgrade-title">ظرفیت انرژی</div>
                <div class="upgrade-desc">حداکثر انرژی شما را +50 افزایش می‌دهد</div>
              </div>
            </div>
            <div class="upgrade-level">سطح فعلی: ${upgrades.energy}</div>
            <div class="upgrade-price">
              <i class="fas fa-coins" style="color: var(--coin)"></i>
              <span>${calculatePrice(UPGRADES.energy, upgrades.energy)} سکه</span>
            </div>
            <button 
              class="upgrade-btn" 
              onclick="purchaseUpgrade('energy')"
              ${(userData.secondaryCoins || 0) < calculatePrice(UPGRADES.energy, upgrades.energy) ? 'disabled' : ''}
            >
              <i class="fas fa-cart-plus"></i> خرید ارتقاء
            </button>
          </div>
          
          <div class="upgrade-card">
            <div class="upgrade-header">
              <div class="upgrade-icon">
                <i class="fas fa-mouse-pointer"></i>
              </div>
              <div>
                <div class="upgrade-title">کلیک چندگانه</div>
                <div class="upgrade-desc">هر کلیک سکه بیشتری به شما می‌دهد</div>
              </div>
            </div>
            <div class="upgrade-level">سطح فعلی: ${upgrades.multiClick}</div>
            <div class="upgrade-price">
              <i class="fas fa-coins" style="color: var(--coin)"></i>
              <span>${calculatePrice(UPGRADES.multiClick, upgrades.multiClick)} سکه</span>
            </div>
            <button 
              class="upgrade-btn" 
              onclick="purchaseUpgrade('multiClick')"
              ${(userData.secondaryCoins || 0) < calculatePrice(UPGRADES.multiClick, upgrades.multiClick) ? 'disabled' : ''}
            >
              <i class="fas fa-cart-plus"></i> خرید ارتقاء
            </button>
          </div>
          
          <div class="upgrade-card">
            <div class="upgrade-header">
              <div class="upgrade-icon">
                <i class="fas fa-tachometer-alt"></i>
              </div>
              <div>
                <div class="upgrade-title">سرعت شارژ</div>
                <div class="upgrade-desc">انرژی شما سریع‌تر شارژ می‌شود</div>
              </div>
            </div>
            <div class="upgrade-level">سطح فعلی: ${upgrades.recharge}</div>
            <div class="upgrade-price">
              <i class="fas fa-coins" style="color: var(--coin)"></i>
              <span>${calculatePrice(UPGRADES.recharge, upgrades.recharge)} سکه</span>
            </div>
            <button 
              class="upgrade-btn" 
              onclick="purchaseUpgrade('recharge')"
              ${(userData.secondaryCoins || 0) < calculatePrice(UPGRADES.recharge, upgrades.recharge) ? 'disabled' : ''}
            >
              <i class="fas fa-cart-plus"></i> خرید ارتقاء
            </button>
          </div>
          
          <div class="upgrade-card">
            <div class="upgrade-header">
              <div class="upgrade-icon">
                <i class="fas fa-robot"></i>
              </div>
              <div>
                <div class="upgrade-title">ربات کلیک</div>
                <div class="upgrade-desc">حتی وقتی آنلاین نیستید برای شما کلیک می‌کند</div>
              </div>
            </div>
            <div class="upgrade-level">سطح فعلی: ${upgrades.autoClicker}</div>
            <div class="upgrade-price">
              <i class="fas fa-coins" style="color: var(--coin)"></i>
              <span>${calculatePrice(UPGRADES.autoClicker, upgrades.autoClicker)} سکه</span>
            </div>
            <button 
              class="upgrade-btn" 
              onclick="purchaseUpgrade('autoClicker')"
              ${(userData.secondaryCoins || 0) < calculatePrice(UPGRADES.autoClicker, upgrades.autoClicker) ? 'disabled' : ''}
            >
              <i class="fas fa-cart-plus"></i> خرید ارتقاء
            </button>
          </div>
        </div>
      </div>
      
      <div class="notification" id="notification"></div>
      
      <script>
        function calculatePrice(upgrade, level) {
          return Math.floor(upgrade.basePrice * Math.pow(upgrade.multiplier, level));
        }
        
        function showNotification(message, isSuccess = true) {
          const notification = document.getElementById('notification');
          notification.textContent = message;
          notification.style.background = isSuccess ? '#4CAF50' : '#F44336';
          notification.classList.add('show');
          
          setTimeout(() => {
            notification.classList.remove('show');
          }, 3000);
        }
        
        async function useBoost(type) {
          try {
            const response = await fetch('/use-boost', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ type })
            });
            
            if (response.ok) {
              showNotification('تقویت‌کننده با موفقیت فعال شد!');
              setTimeout(() => location.reload(), 1000);
            } else {
              const error = await response.json();
              throw new Error(error.error || 'خطا در فعال‌سازی تقویت‌کننده');
            }
          } catch (error) {
            showNotification(error.message, false);
          }
        }
        
        // در frontend باید چنین درخواستی ارسال شود:
        async function purchaseUpgrade(type) {
          try {
            const response = await fetch('/purchase-upgrade', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ type })
            });
            
            if (!response.ok) {
              const error = await response.json();
              throw new Error(error.error || 'خطا در خرید ارتقاء');
            }
            
            const result = await response.json();
            
            // نمایش پیام موفقیت
            showNotification('ارتقاء با موفقیت خریداری شد!');
            
            // به‌روزرسانی موجودی سکه‌ها در صفحه
            document.getElementById('coinsValue').textContent = result.remainingCoins;
            
            // غیرفعال کردن دکمه اگر سکه کافی نیست
            const price = calculatePrice(UPGRADES[type], result.newLevel);
            if (result.remainingCoins < price) {
              const selector = 'button[onclick="purchaseUpgrade(' + type + ')"]';
              document.querySelector(selector).disabled = true;
            }
            
            // بازگشت به صفحه پروفایل پس از 2 ثانیه
            setTimeout(() => {
              window.location.href = '/profile';
            }, 2000);
            
          } catch (error) {
            showNotification(error.message, false);
            console.error('خطا در خرید:', error);
          }
        }
        }
      </script>
    </body>
    </html>
  `;
}

async function handleBoost(request) {
  const { type } = await request.json();
  const username = getUsernameFromCookie(request.headers.get('cookie'));
  
  const userData = await USER_KV.get(username, 'json') || {};
  
  if (type === 'turbo' && userData.dailyTurbo > 0) {
    userData.dailyTurbo--;
    userData.turboEndTime = Math.floor(Date.now()/1000) + 30;
  }
  
  if (type === 'refill' && userData.dailyRefill > 0) {
    userData.dailyRefill--;
    userData.energy = userData.maxEnergy || 250;
  }
  
  await USER_KV.put(username, JSON.stringify(userData));
  return new Response(JSON.stringify({ success: true }));
}

async function handlePurchase(request) {
  const { type } = await request.json();
  const username = getUsernameFromCookie(request.headers.get('cookie'));
  const userData = await USER_KV.get(username, 'json') || {};
  
  const upgrade = UPGRADES[type];
  const currentLevel = userData.upgrades?.[type] || 0;
  const price = Math.floor(upgrade.basePrice * Math.pow(upgrade.multiplier, currentLevel));
  
  if ((userData.secondaryCoins || 0) < price) {
    return new Response(JSON.stringify({ error: 'سکه کافی نیست' }), { status: 400 });
  }
  
  userData.secondaryCoins -= price;
  userData.upgrades = userData.upgrades || {};
  userData.upgrades[type] = (userData.upgrades[type] || 0) + 1;
  
  // اعمال اثرات ارتقاء
  if (type === 'energy') {
    userData.maxEnergy = 250 + (50 * userData.upgrades.energy);
  }
  
  await USER_KV.put(username, JSON.stringify(userData));
  return new Response(JSON.stringify({ success: true }));
}

function getRewardPageHTML(rewardId, userData) {
  const isDarkMode = userData.darkMode !== false;
  const coins = userData.coins || 0;
  
  return `
    <!DOCTYPE html>
    <html lang="fa" dir="rtl" class="${isDarkMode ? 'dark-mode' : ''}">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>دریافت جایزه</title>
      <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/font.css" rel="stylesheet">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
        :root {
          --primary: ${isDarkMode ? '#6a11cb' : '#2575fc'};
          --secondary: ${isDarkMode ? '#2575fc' : '#6a11cb'};
          --bg: ${isDarkMode ? '#121212' : '#f8f9fa'};
          --text: ${isDarkMode ? '#ffffff' : '#212529'};
          --card: ${isDarkMode ? '#1e1e1e' : '#ffffff'};
          --border: ${isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'};
          --success: #4CAF50;
          --coin: #FFD700;
        }
        
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: Vazirmatn, sans-serif;
        }
        
        body {
          background: var(--bg);
          color: var(--text);
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 1rem;
        }
        
        .reward-container {
          background: var(--card);
          border-radius: 15px;
          padding: 2rem;
          box-shadow: 0 10px 30px rgba(0,0,0,0.2);
          text-align: center;
          max-width: 500px;
          width: 100%;
          border: 1px solid var(--border);
          animation: fadeIn 0.5s ease;
        }
        
        .reward-icon {
          font-size: 4rem;
          color: var(--coin);
          margin-bottom: 1.5rem;
          animation: bounce 2s infinite;
        }
        
        .reward-title {
          font-size: 1.8rem;
          margin-bottom: 1rem;
          color: var(--coin);
        }
        
        .reward-amount {
          font-size: 2.5rem;
          font-weight: bold;
          margin: 1.5rem 0;
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 10px;
        }
        
        .reward-amount i {
          color: var(--coin);
        }
        
        .reward-reason {
          background: rgba(255,255,255,0.05);
          padding: 1rem;
          border-radius: 10px;
          margin: 1.5rem 0;
          border-right: 3px solid var(--primary);
        }
        
        .reward-btn {
          background: var(--primary);
          color: white;
          border: none;
          padding: 1rem 2rem;
          border-radius: 50px;
          font-size: 1.2rem;
          cursor: pointer;
          transition: all 0.3s ease;
          margin-top: 1.5rem;
          display: inline-flex;
          align-items: center;
          gap: 10px;
          box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .reward-btn:hover {
          background: var(--secondary);
          transform: translateY(-3px);
          box-shadow: 0 8px 20px rgba(0,0,0,0.3);
        }
        
        .coins-display {
          position: fixed;
          top: 1rem;
          left: 1rem;
          background: var(--card);
          padding: 0.5rem 1rem;
          border-radius: 50px;
          display: flex;
          align-items: center;
          gap: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          border: 1px solid var(--border);
        }
        
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes bounce {
          0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
          40% { transform: translateY(-20px); }
          60% { transform: translateY(-10px); }
        }
      </style>
    </head>
    <body>
      <div class="coins-display">
        <i class="fas fa-coins" style="color: var(--coin)"></i>
        <span id="coinsValue">${coins}</span>
      </div>
      
      <div class="reward-container">
        <div class="reward-icon">
          <i class="fas fa-gift"></i>
        </div>
        <h1 class="reward-title">جایزه ویژه شما!</h1>
        
        <div class="reward-amount">
          <span>300</span>
          <i class="fas fa-coins"></i>
        </div>
        
        <div class="reward-reason">
          <p>به دلیل مشارکت فعال در بازی، این جایزه به شما تعلق گرفته است.</p>
        </div>
        
        <button class="reward-btn" id="claimBtn" onclick="claimReward()">
          <i class="fas fa-gift"></i> دریافت جایزه
        </button>
      </div>
      
      <script>
        async function claimReward() {
          const btn = document.getElementById('claimBtn');
          btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> در حال پردازش...';
          btn.disabled = true;
          
          try {
            const response = await fetch('/reward?id=${rewardId}', {
              method: 'POST'
            });
            
            if (!response.ok) {
              const error = await response.json();
              throw new Error(error.error || 'خطا در دریافت جایزه');
            }
            
            const result = await response.json();
            
            // به‌روزرسانی موجودی سکه‌ها
            document.getElementById('coinsValue').textContent = result.newCoins;
            
            // تغییر دکمه به حالت موفقیت
            btn.innerHTML = '<i class="fas fa-check"></i> جایزه دریافت شد!';
            btn.style.background = '#4CAF50';
            
            // بازگشت به صفحه پروفایل پس از 2 ثانیه
            setTimeout(() => {
              window.location.href = '/profile';
            }, 2000);
            
          } catch (error) {
            alert(error.message);
            btn.innerHTML = '<i class="fas fa-gift"></i> دریافت جایزه';
            btn.disabled = false;
          }
        }
      </script>
    </body>
    </html>
  `;
}

async function handleError1101(request) {
  try {
    const url = new URL(request.url);
    const isAdminRequest = url.pathname.startsWith('/admin');
    
    return new Response(getError1101HTML(isAdminRequest), {
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      },
      status: 403
    });
  } catch (error) {
    return new Response(getMinimalErrorHTML(), {
      headers: { 'Content-Type': 'text/html' },
      status: 500
    });
  }
}

function getFallbackErrorHTML() {
  return `
    <!DOCTYPE html>
    <html>
    <head><title>خطای سرور</title></head>
    <body>
      <h1>500 - خطای سرور داخلی</h1>
      <p>مشکلی در سرور رخ داده است. لطفاً بعداً تلاش کنید.</p>
    </body>
    </html>
  `;
}



function getMinimalErrorHTML() {
  return `
    <!DOCTYPE html>
    <html>
    <head><title>خطای سرور</title></head>
    <body>
      <h1>500 - خطای سرور داخلی</h1>
      <p>مشکلی در سرور رخ داده است. لطفاً بعداً تلاش کنید.</p>
    </body>
    </html>
  `;
}
