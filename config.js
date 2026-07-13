export const config = {
    // سرور
    port: process.env.PORT || 8080,
    host: process.env.HOST || '0.0.0.0',

    // بازی
    maxPlayers: 100,
    maxRooms: 50,
    maxPlayersPerRoom: 10,
    minPlayersToStart: 2,
    gameTimeLimit: 600, // ثانیه (10 دقیقه)

    // بازیکن
    playerNameMaxLength: 20,
    playerDefaultName: 'Player',
    jobs: ['None', 'Warrior', 'Mage', 'Archer', 'Healer', 'Assassin'],

    // چت
    chatMaxLength: 200,
    chatHistoryLimit: 50,

    // حافظه و بهینه‌سازی
    cleanupInterval: 300000, // 5 دقیقه
    maxIdleTime: 3600000, // 1 ساعت
    maxPlayersHistory: 1000,

    // موقعیت‌ها (محدوده حرکت)
    world: {
        minX: -100,
        maxX: 100,
        minZ: -100,
        maxZ: 100,
        minY: -10,
        maxY: 10
    },

    // تنظیمات شبکه
    ws: {
        pingInterval: 30000, // 30 ثانیه
        maxPayloadSize: 1024 * 1024, // 1MB
        idleTimeout: 60000 // 1 دقیقه
    },

    // حالت‌های مختلف سرور
    environment: process.env.NODE_ENV || 'development',
    debug: process.env.DEBUG === 'true' || false,

    // اطلاعات اتصال
    get serverUrl() {
        if (this.environment === 'production') {
            return process.env.RAILWAY_PUBLIC_DOMAIN || 'https://your-domain.railway.app';
        }
        return `http://localhost:${this.port}`;
    }
};

// لاگ کردن تنظیمات در حالت دیباگ
if (config.debug) {
    console.log('🔧 Config loaded:', config);
}

export default config;
