// تولید ID تصادفی با طول دلخواه
export function generateId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// فاصله بین دو نقطه
export function distance(x1, y1, z1, x2, y2, z2) {
    return Math.sqrt(
        Math.pow(x2 - x1, 2) +
        Math.pow(y2 - y1, 2) +
        Math.pow(z2 - z1, 2)
    );
}

// محدود کردن عدد بین دو مقدار
export function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
}

// بررسی اینکه آیا بازیکنی در محدوده مشخصی است
export function isInRange(x1, y1, z1, x2, y2, z2, range) {
    return distance(x1, y1, z1, x2, y2, z2) <= range;
}

// لاگ با رنگ (برای کنسول)
export function log(color, ...args) {
    const colors = {
        red: '\x1b[31m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
        blue: '\x1b[34m',
        magenta: '\x1b[35m',
        cyan: '\x1b[36m',
        reset: '\x1b[0m'
    };
    
    console.log(colors[color] || colors.reset, ...args, colors.reset);
}

// تاخیر (برای async/await)
export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// تبدیل تاریخ به فرمت readable
export function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString('fa-IR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// اشیاء قابل کپی
export function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

// بررسی اینکه آیا رشته معتبر است
export function isValidString(str, minLength = 1, maxLength = 100) {
    return typeof str === 'string' && 
           str.trim().length >= minLength && 
           str.trim().length <= maxLength;
}

// گرفتن IP کلاینت (برای Railway)
export function getClientIP(req) {
    return req.headers['x-forwarded-for'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           'unknown';
}

// بررسی وجود یک کلید در آبجکت
export function hasKey(obj, key) {
    return obj && typeof obj === 'object' && key in obj;
}

// ایمن کردن نام (جلوگیری از XSS)
export function sanitizeName(name) {
    return name.replace(/[<>]/g, '').trim().slice(0, 20);
}
