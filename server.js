const WebSocket = require('ws');

const PORT = process.env.PORT || 8080;

// ذخیره‌سازی بازیکنان: userId -> { ws, name, job, position, rotation }
const players = new Map();

const wss = new WebSocket.Server({ port: PORT });

console.log(`✅ WebSocket server running on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
    console.log('🔗 New client connected');

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            handleMessage(ws, data);
        } catch (e) {
            console.error('❌ Error parsing message:', e);
            sendError(ws, 'Invalid JSON');
        }
    });

    ws.on('close', () => {
        handleDisconnect(ws);
    });
});

// ============================================================
// 📨 پردازش پیام‌ها
// ============================================================
function handleMessage(ws, data) {
    const { type } = data;

    switch (type) {
        case 'set_id':
            handleSetId(ws, data);
            break;
        case 'update':
            handleUpdate(ws, data);
            break;
        case 'chat':
            handleChat(ws, data);
            break;
        case 'ping':
            handlePing(ws);
            break;
        default:
            console.warn(`⚠️ Unknown message type: ${type}`);
            sendError(ws, `Unknown type: ${type}`);
    }
}

// ============================================================
// 👤 احراز هویت با userId (بدون توکن)
// ============================================================
function handleSetId(ws, data) {
    const userId = data.id;
    const name = data.name || 'بازیکن';
    const job = data.job || 'بیکار';

    if (!userId) {
        sendError(ws, 'Missing userId');
        return;
    }

    // اگر کاربر قبلاً با این ID متصل است، اتصال قبلی را قطع کن
    if (players.has(userId)) {
        const old = players.get(userId);
        if (old.ws !== ws) {
            try { old.ws.close(); } catch (e) {}
        }
    }

    // ذخیره اطلاعات
    players.set(userId, {
        ws: ws,
        name: name,
        job: job,
        userId: userId,
        position: { x: 0, y: 0, z: 0 },
        rotation: 0,
    });

    console.log(`👤 Player connected: ${userId} - ${name} (${job})`);

    // ارسال لیست بازیکنان فعلی به خودش
    sendToClient(ws, {
        type: 'welcome',
        id: userId,
        players: getPlayersList(),
    });

    // اعلام به سایرین
    broadcastToOthers(userId, {
        type: 'player_joined',
        player: {
            id: userId,
            name: name,
            job: job,
            x: 0, y: 0, z: 0,
            rot: 0,
        },
    });
}

// ============================================================
// 📍 بروزرسانی موقعیت
// ============================================================
function handleUpdate(ws, data) {
    const userId = getUserIdByWs(ws);
    if (!userId) return;

    const player = players.get(userId);
    if (!player) return;

    player.position = {
        x: data.x || 0,
        y: data.y || 0,
        z: data.z || 0,
    };
    player.rotation = data.rot || 0;

    broadcastToOthers(userId, {
        type: 'update',
        id: userId,
        x: player.position.x,
        y: player.position.y,
        z: player.position.z,
        rot: player.rotation,
        animation: data.animation || 'idle',
    });
}

// ============================================================
// 💬 چت
// ============================================================
function handleChat(ws, data) {
    const userId = getUserIdByWs(ws);
    if (!userId) return;

    const player = players.get(userId);
    if (!player) return;

    const msg = (data.message || '').trim();
    if (!msg) return;

    broadcastToAll({
        type: 'chat',
        id: userId,
        name: player.name,
        job: player.job,
        message: msg,
    });

    console.log(`💬 [${player.name}] ${msg}`);
}

// ============================================================
// 🏓 Ping
// ============================================================
function handlePing(ws) {
    sendToClient(ws, { type: 'pong' });
}

// ============================================================
// ❌ قطع اتصال
// ============================================================
function handleDisconnect(ws) {
    const userId = getUserIdByWs(ws);
    if (userId) {
        players.delete(userId);
        console.log(`👤 Player disconnected: ${userId}`);
        broadcastToAll({
            type: 'player_left',
            id: userId,
        });
    }
}

// ============================================================
// 🛠️ توابع کمکی
// ============================================================
function getUserIdByWs(ws) {
    for (const [id, p] of players) {
        if (p.ws === ws) return id;
    }
    return null;
}

function getPlayersList() {
    const list = [];
    for (const [id, p] of players) {
        list.push({
            id: id,
            name: p.name,
            job: p.job,
            x: p.position.x,
            y: p.position.y,
            z: p.position.z,
            rot: p.rotation,
        });
    }
    return list;
}

function sendToClient(ws, data) {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(data));
    }
}

function broadcastToOthers(excludeId, data) {
    for (const [id, p] of players) {
        if (id !== excludeId && p.ws.readyState === WebSocket.OPEN) {
            p.ws.send(JSON.stringify(data));
        }
    }
}

function broadcastToAll(data) {
    for (const [id, p] of players) {
        if (p.ws.readyState === WebSocket.OPEN) {
            p.ws.send(JSON.stringify(data));
        }
    }
}

function sendError(ws, msg) {
    sendToClient(ws, { type: 'error', message: msg });
}

// ============================================================
// 📊 آمار
// ============================================================
setInterval(() => {
    console.log(`📊 Online players: ${players.size}`);
}, 30000);
