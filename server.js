const http = require("http");
const url = require("url");
const WebSocket = require("ws");

// تنظیمات
const PORT = process.env.PORT || 8080;
const clients = new Map();

// --------------------------------------------
// HTTP Server (فقط برای health check و راه‌اندازی WebSocket)
// --------------------------------------------
const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
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
        }));
        return;
    }

    // Default
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("Game Server Running");
});

// --------------------------------------------
// WebSocket Server - مستقیماً روی HTTP Server سوار میشه
// --------------------------------------------
const wss = new WebSocket.Server({ 
    server: server,
    perMessageDeflate: false,
});

wss.on("connection", (ws, req) => {
    const wsId = Math.random().toString(36).substring(2, 10);
    const query = url.parse(req.url, true).query;
    const userId = query.userId || "";

    console.log(`✅ New connection: ${wsId} (User: ${userId})`);

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
    };

    clients.set(wsId, client);

    // پیام خوش‌آمدگویی
    ws.send(JSON.stringify({
        type: "welcome",
        id: wsId,
        userId: userId,
        players: [],
        serverTime: new Date().toISOString(),
    }));

    // دریافت پیام‌ها
    ws.on("message", (message) => {
        try {
            const data = JSON.parse(message.toString());
            handleMessage(wsId, data);
        } catch (e) {
            console.error("Invalid message:", e.message);
        }
    });

    ws.on("close", () => {
        console.log(`❌ Connection closed: ${wsId}`);
        clients.delete(wsId);
        broadcast({
            type: "player_left",
            id: wsId,
        });
    });

    ws.on("error", (err) => {
        console.error(`WebSocket error: ${err.message}`);
    });
});

// --------------------------------------------
// مدیریت پیام‌ها
// --------------------------------------------
function handleMessage(wsId, data) {
    const client = clients.get(wsId);
    if (!client) return;

    switch (data.type) {
        case "ping":
            client.ws.send(JSON.stringify({ type: "pong", time: Date.now() }));
            break;

        case "set_name":
            client.name = data.name || client.name;
            client.job = data.job || client.job;
            client.userId = data.userId || client.userId;
            console.log(`📛 ${client.name} (${client.job}) connected`);
            broadcast({
                type: "player_update",
                id: wsId,
                name: client.name,
                job: client.job,
                userId: client.userId,
            });
            break;

        case "update":
            if (typeof data.x === "number") client.x = data.x;
            if (typeof data.y === "number") client.y = data.y;
            if (typeof data.z === "number") client.z = data.z;
            if (typeof data.rot === "number") client.rot = data.rot;
            break;

        case "chat":
            if (data.message) {
                console.log(`💬 ${client.name}: ${data.message}`);
                broadcast({
                    type: "chat",
                    id: wsId,
                    name: client.name,
                    job: client.job,
                    message: data.message,
                });
            }
            break;
    }
}

// --------------------------------------------
// Broadcast
// --------------------------------------------
function broadcast(data, excludeId = null) {
    const message = JSON.stringify(data);
    for (const [id, client] of clients) {
        if (id !== excludeId && client.ws.readyState === 1) { // OPEN
            try {
                client.ws.send(message);
            } catch (e) {
                // ignore
            }
        }
    }
}

// --------------------------------------------
// Position Broadcast (هر ۱/۲۰ ثانیه)
// --------------------------------------------
setInterval(() => {
    if (clients.size === 0) return;
    
    const players = [];
    for (const [id, client] of clients) {
        players.push({
            id: id,
            userId: client.userId,
            name: client.name,
            job: client.job,
            level: client.level,
            x: client.x,
            y: client.y,
            z: client.z,
            rot: client.rot,
        });
    }

    broadcast({
        type: "players",
        players: players,
        count: clients.size,
    });
}, 50); // 20fps

// --------------------------------------------
// Heartbeat
// --------------------------------------------
setInterval(() => {
    console.log(`💓 Clients: ${clients.size}`);
}, 10000);

// --------------------------------------------
// Start Server
// --------------------------------------------
server.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔗 WebSocket: ws://ggwa.up.railway.app:${PORT}`);
    console.log(`🔗 WebSocket (SSL): wss://ggwa.up.railway.app`);
});
