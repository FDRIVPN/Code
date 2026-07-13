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
    // تنظیمات مهم برای Railway
    perMessageDeflate: false,
    clientTracking: true
});

console.log(`🚀 Server started on port ${PORT}`);

// هندل کردن خطاهای WebSocket
wss.on('error', (error) => {
    console.error('WebSocket Error:', error);
});

wss.on("connection", (ws, req) => {
    const id = ++playerIdCounter;
    const ip = req.socket.remoteAddress;
    
    players.set(id, { 
        id, 
        name: `Player${id}`, 
        x: 0, y: 0, z: 0, 
        rot: 0, animation: "idle",
        ip: ip,
        connectedAt: Date.now()
    });

    console.log(`✅ Player Connected: ${id} from ${ip}`);
    console.log(`📊 Total players: ${players.size}`);

    // ارسال اطلاعات اولیه
    try {
        ws.send(JSON.stringify({
            type: "welcome",
            id: id,
            players: getPlayers()
        }));
    } catch(err) {
        console.log('Error sending welcome:', err);
    }

    ws.on("message", (message) => {
        try {
            const data = JSON.parse(message);
            const player = players.get(id);
            if (!player) return;

            switch(data.type) {
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

                case "set_name":
                    if (data.name && data.name.length > 0 && data.name.length <= 20) {
                        player.name = data.name;
                        broadcast({
                            type: "players",
                            players: getPlayers()
                        });
                    }
                    break;

                case "chat":
                    if (data.message && data.message.trim()) {
                        console.log(`💬 ${player.name}: ${data.message}`);
                        broadcast({
                            type: "chat",
                            id: id,
                            name: player.name,
                            message: data.message.substring(0, 200)
                        });
                    }
                    break;

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

    ws.on("close", (code, reason) => {
        console.log(`❌ Player Left: ${id} (${players.get(id)?.name || 'Unknown'})`);
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

function getPlayers() {
    return Array.from(players.values()).map(p => ({
        id: p.id,
        name: p.name,
        x: p.x,
        y: p.y,
        z: p.z,
        rot: p.rot,
        animation: p.animation
    }));
}

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

// Health check
setInterval(() => {
    console.log(`💚 Health: ${players.size} players, ${wss.clients.size} clients`);
}, 30000);

// جلوگیری از خاموش شدن سرور
server.on('error', (error) => {
    console.error('Server error:', error);
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ HTTP & WebSocket server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// هندل کردن SIGTERM (خاموش شدن توسط Railway)
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
