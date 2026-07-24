import { WebSocketServer } from "ws";
import http from "http";

const PORT = process.env.PORT || 8080;

// HTTP Server برای Railway
const server = http.createServer((req, res) => {
    res.writeHead(200, { 
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify({ 
        status: 'online', 
        players: players ? players.size : 0,
        timestamp: Date.now(),
        message: 'Godot Multiplayer Server is running!'
    }));
});

const players = new Map();
let playerIdCounter = 0;

const wss = new WebSocketServer({ 
    server,
    perMessageDeflate: false,
    clientTracking: true
});

console.log(`🚀 Server started on port ${PORT}`);

wss.on('error', (error) => {
    console.error('WebSocket Error:', error);
});

wss.on("connection", (ws, req) => {
    const id = ++playerIdCounter;
    const ip = req.socket.remoteAddress;
    
    // ============================================================
    // ✅ ایجاد بازیکن با نام و شغل پیش‌فرض
    // ============================================================
    players.set(id, { 
        id, 
        name: `بازیکن_${id}`, 
        job: 'بیکار',  // 👈 شغل پیش‌فرض اضافه شد
        x: 0, y: 0, z: 0, 
        rot: 0, 
        animation: "idle",
        ip: ip,
        connectedAt: Date.now()
    });

    console.log(`✅ Player Connected: ${id} from ${ip}`);
    console.log(`📊 Total players: ${players.size}`);

    // ============================================================
    // 📤 ارسال اطلاعات اولیه
    // ============================================================
    try {
        ws.send(JSON.stringify({
            type: "welcome",
            id: id,
            players: getPlayers()
        }));
    } catch(err) {
        console.log('Error sending welcome:', err);
    }

    // ============================================================
    // 📨 دریافت پیام‌ها
    // ============================================================
    ws.on("message", (message) => {
        try {
            const data = JSON.parse(message);
            const player = players.get(id);
            if (!player) return;

            switch(data.type) {
                // ============================================================
                // 📍 به‌روزرسانی موقعیت
                // ============================================================
                case "update":
                    player.x = data.x || 0;
                    player.y = data.y || 0;
                    player.z = data.z || 0;
                    player.rot = data.rot || 0;
                    player.animation = data.animation || "idle";
                    broadcast({
                        type: "players",
                        players: getPlayers()
                    });
                    break;

                // ============================================================
                // 🆔 تنظیم نام و شغل (یکجا)
                // ============================================================
                case "set_name":
                    if (data.name && data.name.length > 0 && data.name.length <= 20) {
                        player.name = data.name;
                    }
                    if (data.job !== undefined) {
                        player.job = data.job || 'بیکار';
                    }
                    
                    console.log(`📛 ${player.name} (${player.id}) - Job: ${player.job}`);
                    
                    // ارسال به همه
                    broadcast({
                        type: "players",
                        players: getPlayers()
                    });
                    
                    // تأیید به خود بازیکن
                    ws.send(JSON.stringify({
                        type: "set_name_ack",
                        name: player.name,
                        job: player.job
                    }));
                    break;

                // ============================================================
                // 💼 تغییر شغل (جداگانه)
                // ============================================================
                case "set_job":
                    if (data.job !== undefined) {
                        const oldJob = player.job;
                        player.job = data.job || 'بیکار';
                        
                        console.log(`💼 ${player.name} (${player.id}) job changed: ${oldJob} → ${player.job}`);
                        
                        // ارسال به همه
                        broadcast({
                            type: "players",
                            players: getPlayers()
                        });
                        
                        // تأیید به خود بازیکن
                        ws.send(JSON.stringify({
                            type: "set_job_ack",
                            job: player.job
                        }));
                    }
                    break;

                // ============================================================
                // 💬 چت
                // ============================================================
                case "chat":
                    if (data.message && data.message.trim()) {
                        const msg = data.message.substring(0, 200);
                        console.log(`💬 ${player.name} (${player.job}): ${msg}`);
                        
                        broadcast({
                            type: "chat",
                            id: id,
                            name: player.name,
                            job: player.job,  // 👈 شغل هم به چت اضافه شد
                            message: msg
                        });
                    }
                    break;

                // ============================================================
                // 🏓 پینگ
                // ============================================================
                case "ping":
                    ws.send(JSON.stringify({ type: "pong", time: Date.now() }));
                    break;

                default:
                    console.log(`Unknown packet type: ${data.type} from ${player.name}`);
            }
        } catch(err) {
            console.log("Error processing message:", err.message);
        }
    });

    // ============================================================
    // 🔌 قطع اتصال
    // ============================================================
    ws.on("close", (code, reason) => {
        const player = players.get(id);
        console.log(`❌ Player Left: ${id} (${player?.name || 'Unknown'})`);
        players.delete(id);
        broadcast({
            type: "players",
            players: getPlayers()
        });
        console.log(`📊 Total players: ${players.size}`);
    });

    ws.on("error", (error) => {
        console.log(`WebSocket error for player ${id}:`, error.message);
    });
});

// ============================================================
// 📋 گرفتن لیست بازیکنان
// ============================================================
function getPlayers() {
    return Array.from(players.values()).map(p => ({
        id: p.id,
        name: p.name,
        job: p.job,  // 👈 شغل اضافه شد
        x: p.x,
        y: p.y,
        z: p.z,
        rot: p.rot,
        animation: p.animation
    }));
}

// ============================================================
// 📢 پخش پیام به همه
// ============================================================
function broadcast(packet) {
    const json = JSON.stringify(packet);
    wss.clients.forEach(client => {
        if (client.readyState === 1) {
            try {
                client.send(json);
            } catch(err) {
                // Client disconnected
            }
        }
    });
}

// ============================================================
// 💚 Health check
// ============================================================
setInterval(() => {
    console.log(`💚 Health: ${players.size} players, ${wss.clients.size} clients`);
}, 30000);

// ============================================================
// 🛑 مدیریت خطاها
// ============================================================
server.on('error', (error) => {
    console.error('Server error:', error);
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ HTTP & WebSocket server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// ============================================================
// 🛑 هندل کردن SIGTERM و SIGINT
// ============================================================
process.on('SIGTERM', () => {
    console.log('Received SIGTERM signal, closing server...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('Received SIGINT signal, closing server...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});
