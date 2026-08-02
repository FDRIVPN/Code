const fs = require("fs");
const path = require("path");
const http = require("http");
const url = require("url");
const WebSocket = require("ws");

// ============================================================
// 📋 تنظیمات
// ============================================================
const CONFIG = {
    PORT: process.env.PORT || 8080,
    MAX_MESSAGE_SIZE: 1024 * 1024 * 5,
    HEARTBEAT_INTERVAL: 30000,
    IDLE_TIMEOUT: 60000,
    MAX_PLAYERS: 100,
    MAX_NAME_LENGTH: 30,
    WORD_FILTER: ["کیر", "کس", "کونی", "جاکش", "مادرجنده", "حرومزاده", "خاک بر سر"],
};

// ============================================================
// 📊 وضعیت
// ============================================================
const clients = new Map();
const bannedUsers = new Map();

// ============================================================
// 🛠 توابع کمکی
// ============================================================
function log(emoji, message, ...args) {
    const time = new Date().toLocaleTimeString("fa-IR");
    console.log(`[${time}] ${emoji} ${message}`, ...args);
}

function generateId() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
}

function filterBadWords(text) {
    let filtered = text;
    for (const word of CONFIG.WORD_FILTER) {
        const regex = new RegExp(word, "gi");
        filtered = filtered.replace(regex, "***");
    }
    return filtered;
}

function getRandomColor() {
    const colors = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEAA7", "#DDA0DD", "#98D8C8", "#F7DC6F"];
    return colors[Math.floor(Math.random() * colors.length)];
}

function getAllPlayersSnapshot() {
    const result = [];
    for (const [wsId, client] of clients) {
        result.push({
            id: wsId,
            userId: client.userId || "anonymous",
            name: client.name || "بازیکن",
            job: client.job || "بیکار",
            level: client.level || 0,
            x: client.x || 0,
            y: client.y || 0.5,
            z: client.z || 0,
            rot: client.rot || 0,
            animation: client.animation || "idle",
            color: client.color || "#4ECDC4",
            joinedAt: client.joinedAt || Date.now(),
        });
    }
    return result;
}

function isUserBanned(userId) {
    if (bannedUsers.has(userId)) {
        const ban = bannedUsers.get(userId);
        if (ban.expires && Date.now() > ban.expires) {
            bannedUsers.delete(userId);
            return false;
        }
        return true;
    }
    return false;
}

function banUser(userId, duration, reason = "تخلف") {
    const expires = duration === "permanent" ? null : Date.now() + duration;
    bannedUsers.set(userId, {
        reason: reason,
        expires: expires,
        bannedAt: Date.now(),
    });
    log("🚫", `User ${userId} banned (${duration}): ${reason}`);
}

function unbanUser(userId) {
    bannedUsers.delete(userId);
    log("✅", `User ${userId} unbanned`);
}

// ============================================================
// 🔌 مدیریت WebSocket
// ============================================================
function handleConnection(ws, req) {
    const wsId = generateId();
    const parsedUrl = url.parse(req.url, true);
    const userId = parsedUrl.query.userId || "";
    const ip = req.socket.remoteAddress || "unknown";

    if (clients.size >= CONFIG.MAX_PLAYERS) {
        ws.close(1008, "Server is full");
        log("🚫", `Connection rejected (full): ${ip}`);
        return;
    }

    if (userId && isUserBanned(userId)) {
        const ban = bannedUsers.get(userId);
        ws.close(1008, `You are banned: ${ban.reason}`);
        log("🚫", `Banned user tried to connect: ${userId}`);
        return;
    }

    const client = {
        ws: ws,
        userId: userId,
        name: "بازیکن_" + Math.floor(Math.random() * 10000),
        job: "بیکار",
        level: 0,
        x: 0,
        y: 0.5,
        z: 0,
        rot: 0,
        animation: "idle",
        color: getRandomColor(),
        joinedAt: Date.now(),
        lastActivity: Date.now(),
        isAdmin: false,
    };

    clients.set(wsId, client);
    log("👤", `New connection: ${wsId} (User: ${userId || "anonymous"})`);

    // 🎁 Welcome message
    ws.send(JSON.stringify({
        type: "welcome",
        id: wsId,
        userId: userId,
        players: getAllPlayersSnapshot(),
        serverTime: new Date().toISOString(),
    }));

    // 📢 Notify others
    broadcast({
        type: "player_joined",
        player: {
            id: wsId,
            userId: userId,
            name: client.name,
            job: client.job,
            level: client.level,
            x: client.x,
            y: client.y,
            z: client.z,
            rot: client.rot,
            color: client.color,
        },
    }, wsId);

    // 📨 Handle messages
    ws.on("message", (message) => {
        try {
            const data = JSON.parse(message.toString());
            handleClientMessage(wsId, data);
        } catch (e) {
            log("⚠️", `Invalid message from ${wsId}:`, e.message);
        }
    });

    ws.on("close", (code, reason) => {
        clients.delete(wsId);
        log("❌", `Connection closed: ${wsId} (${code})`);
        broadcast({
            type: "player_left",
            id: wsId,
            userId: userId,
        });
    });

    ws.on("error", (err) => {
        log("❌", `WebSocket error for ${wsId}:`, err.message);
    });
}

// ============================================================
// 📨 مدیریت پیام‌های کلاینت
// ============================================================
function handleClientMessage(wsId, data) {
    const client = clients.get(wsId);
    if (!client) return;

    client.lastActivity = Date.now();

    if (client.userId && isUserBanned(client.userId)) {
        client.ws.close(1008, "You are banned");
        return;
    }

    switch (data.type) {
        case "ping":
            client.ws.send(JSON.stringify({ type: "pong", time: Date.now() }));
            break;

        case "set_name":
            if (data.name && data.name.length <= CONFIG.MAX_NAME_LENGTH) {
                const filteredName = filterBadWords(data.name);
                client.name = filteredName || "بازیکن";
                client.job = data.job || "بیکار";
                if (data.userId) {
                    client.userId = data.userId;
                }
                log("📛", `${wsId} set name: ${client.name} (${client.job})`);
                broadcast({
                    type: "player_update",
                    id: wsId,
                    userId: client.userId,
                    name: client.name,
                    job: client.job,
                    level: client.level,
                });
            }
            break;

        case "update":
            if (typeof data.x === "number") client.x = data.x;
            if (typeof data.y === "number") client.y = data.y;
            if (typeof data.z === "number") client.z = data.z;
            if (typeof data.rot === "number") client.rot = data.rot;
            if (data.animation) client.animation = data.animation;
            break;

        case "chat":
            const message = data.message ? filterBadWords(data.message.trim()) : "";
            if (message) {
                log("💬", `${client.name}: ${message}`);
                broadcast({
                    type: "chat",
                    id: wsId,
                    userId: client.userId,
                    name: client.name,
                    job: client.job,
                    message: message,
                });
            }
            break;

        case "admin_ban":
            if (client.isAdmin && client.userId) {
                const targetId = data.targetId;
                const duration = data.duration || "1h";
                const reason = data.reason || "تخلف";
                let targetWsId = null;
                let targetUser = null;
                for (const [id, c] of clients) {
                    if (c.userId === targetId || id === targetId) {
                        targetWsId = id;
                        targetUser = c;
                        break;
                    }
                }
                if (targetUser && targetUser.userId) {
                    let durationMs;
                    if (duration === "permanent") durationMs = "permanent";
                    else if (duration === "1h") durationMs = 3600000;
                    else if (duration === "24h") durationMs = 86400000;
                    else if (duration === "7d") durationMs = 604800000;
                    else durationMs = 3600000;

                    banUser(targetUser.userId, durationMs, reason);
                    const targetClient = clients.get(targetWsId);
                    if (targetClient) {
                        targetClient.ws.close(1008, `You are banned: ${reason}`);
                    }
                    log("👑", `Admin ${client.name} banned ${targetUser.name} (${duration})`);
                }
            }
            break;

        case "admin_unban":
            if (client.isAdmin && client.userId) {
                const targetId = data.targetId;
                unbanUser(targetId);
                log("👑", `Admin ${client.name} unbanned ${targetId}`);
            }
            break;

        default:
            log("⚠️", `Unknown message type: ${data.type}`);
    }
}

// ============================================================
// 📢 Broadcast
// ============================================================
function broadcast(data, excludeId = null) {
    const message = JSON.stringify(data);
    for (const [id, client] of clients) {
        if (id !== excludeId && client.ws.readyState === WebSocket.OPEN) {
            try {
                client.ws.send(message);
            } catch (e) {
                // ignore
            }
        }
    }
}

// ============================================================
// 📡 پخش موقعیت (Position Broadcast)
// ============================================================
function startPositionBroadcast() {
    setInterval(() => {
        if (clients.size === 0) return;

        const updates = [];
        for (const [id, client] of clients) {
            updates.push({
                id: id,
                userId: client.userId,
                x: client.x,
                y: client.y,
                z: client.z,
                rot: client.rot,
                animation: client.animation,
                name: client.name,
                job: client.job,
                level: client.level,
            });
        }

        const message = JSON.stringify({
            type: "players",
            players: updates,
            count: clients.size,
        });

        for (const [id, client] of clients) {
            if (client.ws.readyState === WebSocket.OPEN) {
                try {
                    client.ws.send(message);
                } catch (e) {
                    // ignore
                }
            }
        }
    }, 1000 / 15); // 15 FPS
}

// ============================================================
// 💓 Heartbeat
// ============================================================
function startHeartbeat() {
    setInterval(() => {
        const now = Date.now();
        for (const [id, client] of clients) {
            if (now - client.lastActivity > CONFIG.IDLE_TIMEOUT) {
                log("⏰", `Closing idle connection: ${id}`);
                client.ws.close(1000, "Idle timeout");
                clients.delete(id);
            } else if (client.ws.readyState !== WebSocket.OPEN) {
                clients.delete(id);
            }
        }
        log("💓", `Server running | Clients: ${clients.size} | Banned: ${bannedUsers.size}`);
    }, CONFIG.HEARTBEAT_INTERVAL);
}

// ============================================================
// 🌐 HTTP Server
// ============================================================
const httpServer = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
        res.writeHead(200);
        res.end();
        return;
    }

    // Health check
    if (parsedUrl.pathname === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            status: "ok",
            clients: clients.size,
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            timestamp: new Date().toISOString(),
        }));
        return;
    }

    // Players list
    if (parsedUrl.pathname === "/players") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
            count: clients.size,
            players: getAllPlayersSnapshot()
        }));
        return;
    }

    // Default
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(`Game Server Running | Players: ${clients.size}`);
});

// ============================================================
// 🚀 WebSocket Server
// ============================================================
const wss = new WebSocket.Server({
    server: httpServer,
    maxPayload: CONFIG.MAX_MESSAGE_SIZE,
    perMessageDeflate: false,
});

wss.on("connection", handleConnection);
wss.on("error", (err) => {
    log("❌", "WebSocket Server Error:", err.message);
});

// ============================================================
// 🎯 استارت سرور
// ============================================================
startPositionBroadcast();
startHeartbeat();

httpServer.listen(CONFIG.PORT, "0.0.0.0", () => {
    log("🚀", `✅ Server started on port ${CONFIG.PORT}`);
    log("🔗", `WebSocket: ws://ggwa.up.railway.app:${CONFIG.PORT}`);
    log("🔗", `WebSocket (SSL): wss://ggwa.up.railway.app`);
    log("📊", `Health check: https://ggwa.up.railway.app/health`);
});
