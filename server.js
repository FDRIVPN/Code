const WebSocket = require('ws');
const http = require('http');
const url = require('url');

// تنظیمات
const PORT = process.env.PORT || 8080;
const ALLOWED_JOBS = ["آشپز", "بیکار", "کارمند", "بازاریاب", "کشاورز"];

// داده‌های درون حافظه
const clients = new Map(); // userId -> { ws, name, job, position, rotation, id }
const userIdMap = new Map(); // webSocketId -> userId
let nextId = 1;

// تابع تولید شناسه یکتا
function generateUniqueId() {
    return (nextId++).toString();
}

// ایجاد سرور HTTP و WebSocket
const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('WebSocket server is running');
});

const wss = new WebSocket.Server({ server });

// ============================================================
// اتصال WebSocket
// ============================================================
wss.on('connection', (ws, req) => {
    const clientId = generateUniqueId();
    console.log(`🟢 New client connected: ${clientId}`);

    // ارسال خوش‌آمدگویی با لیست بازیکنان فعلی
    const playersList = [];
    for (const [userId, client] of clients) {
        if (userId !== clientId) {
            playersList.push({
                id: userId,
                name: client.name || 'بازیکن',
                job: client.job || 'بیکار',
                x: client.position?.x || 0,
                y: client.position?.y || 0,
                z: client.position?.z || 0,
                rot: client.rotation || 0,
                animation: client.animation || 'idle'
            });
        }
    }

    ws.send(JSON.stringify({
        type: 'welcome',
        id: clientId,
        players: playersList
    }));

    // مدیریت پیام‌ها
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            handleMessage(ws, clientId, data);
        } catch (error) {
            console.error('❌ Error parsing message:', error);
        }
    });

    // قطع اتصال
    ws.on('close', () => {
        console.log(`🔴 Client disconnected: ${clientId}`);
        // حذف از لیست کلاینت‌ها
        const userId = userIdMap.get(clientId);
        if (userId) {
            clients.delete(userId);
            userIdMap.delete(clientId);
            // اطلاع‌رسانی به دیگران
            broadcast({
                type: 'player_left',
                id: userId
            }, clientId);
        }
    });

    ws.on('error', (error) => {
        console.error('❌ WebSocket error:', error);
    });
});

// ============================================================
// مدیریت پیام‌ها
// ============================================================
function handleMessage(ws, clientId, data) {
    switch (data.type) {
        case 'set_id':
            handleSetId(ws, clientId, data);
            break;
        case 'update':
            handleUpdate(ws, clientId, data);
            break;
        case 'chat':
            handleChat(ws, clientId, data);
            break;
        case 'ping':
            ws.send(JSON.stringify({ type: 'pong' }));
            break;
        case 'ban':
            handleBan(ws, clientId, data);
            break;
        default:
            console.log(`⚠️ Unknown message type: ${data.type}`);
    }
}

// ============================================================
// احراز هویت با userId
// ============================================================
function handleSetId(ws, clientId, data) {
    const userId = data.id;
    if (!userId) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'userId is required'
        }));
        return;
    }

    // اگر کاربر قبلاً با این userId متصل است، اتصال قبلی را قطع کن
    for (const [existingClientId, existingWs] of wss.clients) {
        if (existingWs !== ws && existingWs.readyState === WebSocket.OPEN) {
            const existingUserId = userIdMap.get(existingClientId);
            if (existingUserId === userId) {
                console.log(`🔄 Kicking duplicate connection for user: ${userId}`);
                existingWs.send(JSON.stringify({
                    type: 'error',
                    message: 'Duplicate connection, you are being kicked'
                }));
                existingWs.close();
                // حذف از لیست
                clients.delete(userId);
                userIdMap.delete(existingClientId);
                break;
            }
        }
    }

    // ذخیره اطلاعات کاربر
    const name = data.name || 'بازیکن';
    const job = data.job || 'بیکار';
    
    // بررسی معتبر بودن شغل
    const validJob = ALLOWED_JOBS.includes(job) ? job : 'بیکار';

    clients.set(userId, {
        ws: ws,
        name: name,
        job: validJob,
        position: { x: 0, y: 0, z: 0 },
        rotation: 0,
        animation: 'idle'
    });
    
    userIdMap.set(clientId, userId);

    console.log(`👤 User set: ${userId} (${name}) - Job: ${validJob}`);

    // اطلاع‌رسانی به همه درباره ورود کاربر جدید
    broadcast({
        type: 'player_joined',
        player: {
            id: userId,
            name: name,
            job: validJob,
            x: 0,
            y: 0,
            z: 0,
            rot: 0,
            animation: 'idle'
        }
    }, clientId);

    // ارسال لیست کامل بازیکنان به کاربر جدید (به‌جز خودش)
    const playersList = [];
    for (const [otherUserId, client] of clients) {
        if (otherUserId !== userId) {
            playersList.push({
                id: otherUserId,
                name: client.name || 'بازیکن',
                job: client.job || 'بیکار',
                x: client.position?.x || 0,
                y: client.position?.y || 0,
                z: client.position?.z || 0,
                rot: client.rotation || 0,
                animation: client.animation || 'idle'
            });
        }
    }

    if (playersList.length > 0) {
        ws.send(JSON.stringify({
            type: 'players',
            players: playersList
        }));
    }
}

// ============================================================
// به‌روزرسانی موقعیت
// ============================================================
function handleUpdate(ws, clientId, data) {
    const userId = userIdMap.get(clientId);
    if (!userId || !clients.has(userId)) {
        return;
    }

    const client = clients.get(userId);
    
    // به‌روزرسانی موقعیت
    if (data.x !== undefined && data.y !== undefined && data.z !== undefined) {
        client.position = { x: data.x, y: data.y, z: data.z };
    }
    if (data.rot !== undefined) {
        client.rotation = data.rot;
    }
    if (data.animation !== undefined) {
        client.animation = data.animation;
    }

    // ارسال به‌روزرسانی به همه (به‌جز خود فرستنده)
    broadcast({
        type: 'update',
        id: userId,
        x: client.position.x,
        y: client.position.y,
        z: client.position.z,
        rot: client.rotation,
        animation: client.animation
    }, clientId);
}

// ============================================================
// مدیریت چت
// ============================================================
function handleChat(ws, clientId, data) {
    const userId = userIdMap.get(clientId);
    if (!userId || !clients.has(userId)) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'You are not authenticated'
        }));
        return;
    }

    const message = data.message;
    if (!message || message.trim().length === 0) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Message cannot be empty'
        }));
        return;
    }

    const client = clients.get(userId);
    
    // ارسال پیام به همه (شامل خود فرستنده)
    broadcast({
        type: 'chat',
        name: client.name,
        job: client.job,
        message: message.trim().substring(0, 500)
    });
}

// ============================================================
// مدیریت بن (فقط برای کاربران با سطح بالا)
// ============================================================
function handleBan(ws, clientId, data) {
    const userId = userIdMap.get(clientId);
    if (!userId || !clients.has(userId)) {
        return;
    }

    const targetUserId = data.targetId;
    if (!targetUserId) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'targetId is required'
        }));
        return;
    }

    // اینجا می‌توانید سطح کاربر را بررسی کنید
    // مثلاً اگر کاربر با userId خاصی ادمین است
    // برای نمونه، فقط کاربر با userId 'admin' می‌تواند بن کند
    if (userId !== 'admin') {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'You do not have permission to ban'
        }));
        return;
    }

    // بن کردن کاربر
    if (clients.has(targetUserId)) {
        const targetClient = clients.get(targetUserId);
        targetClient.ws.send(JSON.stringify({
            type: 'error',
            message: 'You have been banned by an admin'
        }));
        targetClient.ws.close();
        
        // حذف از لیست
        clients.delete(targetUserId);
        // پیدا کردن clientId مربوطه
        for (const [cid, uid] of userIdMap) {
            if (uid === targetUserId) {
                userIdMap.delete(cid);
                break;
            }
        }
        
        // اطلاع‌رسانی به همه
        broadcast({
            type: 'player_left',
            id: targetUserId
        });
        
        console.log(`🔨 User ${targetUserId} was banned by ${userId}`);
    } else {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'User not found or already disconnected'
        }));
    }
}

// ============================================================
// تابع پخش همگانی
// ============================================================
function broadcast(data, excludeClientId = null) {
    const message = JSON.stringify(data);
    for (const [clientId, ws] of wss.clients) {
        if (ws.readyState === WebSocket.OPEN) {
            if (excludeClientId !== null && clientId === excludeClientId) {
                continue;
            }
            ws.send(message);
        }
    }
}

// ============================================================
// شروع سرور
// ============================================================
server.listen(PORT, () => {
    console.log(`🚀 WebSocket server running on port ${PORT}`);
    console.log(`📍 WebSocket URL: ws://localhost:${PORT}`);
});

// مدیریت خاموش شدن
process.on('SIGINT', () => {
    console.log('🛑 Shutting down server...');
    wss.close(() => {
        server.close(() => {
            process.exit(0);
        });
    });
});
