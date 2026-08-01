import { WebSocketServer } from "ws";
import http from "http";
import url from "url";

const PORT = process.env.PORT || 8080;

// HTTP Server برای Railway/Health Check
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

const players = new Map();          // کلید: userId واقعی از کلاینت
let fallbackIdCounter = 0;         // فقط برای حالت fallback

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
  // ============================================================
  // ✅ دریافت userId از Query String (مثلاً ws://server?userId=xxx)
  // ============================================================
  const parsedUrl = url.parse(req.url || '', true);
  const clientUserId = parsedUrl.query.userId;

  let userId;

  if (clientUserId && typeof clientUserId === 'string' && clientUserId.trim().length > 0) {
    userId = clientUserId.trim();
    console.log(`📥 Client connected with userId: ${userId}`);
  } else {
    // Fallback: اگر کلاینت userId نفرستاد، ID تولید کن (سازگاری با نسخه‌های قدیمی)
    fallbackIdCounter++;
    userId = `guest_${fallbackIdCounter}`;
    console.log(`⚠️ No userId provided, generated fallback ID: ${userId}`);
  }

  // ============================================================
  // ✅ اگر کاربر با همین ID قبلاً متصل است، اتصال قبلی را قطع کن
  // ============================================================
  if (players.has(userId)) {
    console.log(`🔄 User ${userId} already connected. Disconnecting old connection...`);
    for (const client of wss.clients) {
      if (client._userId === userId) {
        try {
          client.close(1000, "Replaced by new connection");
        } catch (e) {
          console.log("Error closing old connection:", e.message);
        }
        break;
      }
    }
    players.delete(userId);
  }

  // ذخیره userId در خود WebSocket برای شناسایی بعدی
  ws._userId = userId;

  const ip = req.socket.remoteAddress || 'unknown';

  // ============================================================
  // ✅ ایجاد بازیکن با ID دریافتی از کلاینت (بدون توکن)
  // ============================================================
  players.set(userId, {
    id: userId,
    name: `بازیکن_${userId}`,
    job: 'بیکار',
    x: 0,
    y: 0,
    z: 0,
    rot: 0,
    animation: "idle",
    ip: ip,
    connectedAt: Date.now()
  });

  console.log(`✅ Player Connected: ${userId} from ${ip}`);
  console.log(`📊 Total players: ${players.size}`);

  // ============================================================
  // ارسال اطلاعات اولیه (با ID واقعی)
  // ============================================================
  try {
    ws.send(JSON.stringify({
      type: "welcome",
      id: userId,              // ✅ ID واقعی را به کلاینت برمی‌گردانیم
      players: getPlayers()
    }));
  } catch (err) {
    console.log('Error sending welcome:', err);
  }

  // ============================================================
  // دریافت پیام‌ها
  // ============================================================
  ws.on("message", (message) => {
    try {
      const data = JSON.parse(message);
      const player = players.get(userId);
      if (!player) return;

      switch (data.type) {

        // ============================================================
        // به‌روزرسانی موقعیت
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
        // تنظیم نام و شغل (با استفاده از userId دریافتی)
        // ============================================================
        case "set_name":
          // اگر کلاینت userId ارسال کرده، از آن استفاده کن
          if (data.userId && data.userId !== userId) {
            console.log(`⚠️ Client sent different userId: ${data.userId} vs ${userId}`);
            // می‌توانید userId را به‌روز کنید، اما پیشنهاد می‌شود کلاینت را اصلاح کنید
          }

          if (data.name && data.name.length > 0 && data.name.length <= 20) {
            player.name = data.name;
          }
          if (data.job !== undefined) {
            player.job = data.job || 'بیکار';
          }

          console.log(`📝 ${player.name} (${player.id}) - Job: ${player.job}`);

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
        // تغییر شغل (جداگانه)
        // ============================================================
        case "set_job":
          if (data.job !== undefined) {
            const oldJob = player.job;
            player.job = data.job || 'بیکار';
            console.log(`🔄 ${player.name} (${player.id}) job changed: ${oldJob} → ${player.job}`);

            broadcast({
              type: "players",
              players: getPlayers()
            });

            ws.send(JSON.stringify({
              type: "set_job_ack",
              job: player.job
            }));
          }
          break;

        // ============================================================
        // چت
        // ============================================================
        case "chat":
          if (data.message && data.message.trim()) {
            const msg = data.message.substring(0, 200);
            console.log(`💬 ${player.name} (${player.job}): ${msg}`);
            broadcast({
              type: "chat",
              id: userId,                    // ✅ ID واقعی
              name: player.name,
              job: player.job,
              message: msg
            });
          }
          break;

        // ============================================================
        // پینگ
        // ============================================================
        case "ping":
          ws.send(JSON.stringify({
            type: "pong",
            time: Date.now()
          }));
          break;

        // ============================================================
        // دستورات ادمین (اختیاری)
        // ============================================================
        case "admin_command":
          // فقط از userId استفاده می‌شود، توکن نادیده گرفته می‌شود
          console.log(`👑 Admin command from ${userId}: ${data.command} on ${data.targetId}`);
          // در اینجا می‌توانید منطق بن را پیاده‌سازی کنید
          // یا از API اصلی برای بن استفاده کنید
          break;

        default:
          console.log(`❓ Unknown packet type: ${data.type} from ${player.name}`);
      }
    } catch (err) {
      console.log("Error processing message:", err.message);
    }
  });

  // ============================================================
  // قطع اتصال
  // ============================================================
  ws.on("close", (code, reason) => {
    const player = players.get(userId);
    console.log(`❌ Player Left: ${userId} (${player?.name || 'Unknown'})`);
    players.delete(userId);
    broadcast({
      type: "players",
      players: getPlayers()
    });
    console.log(`📊 Total players: ${players.size}`);
  });

  ws.on("error", (error) => {
    console.log(`WebSocket error for player ${userId}:`, error.message);
  });
});

// ============================================================
// گرفتن لیست بازیکنان
// ============================================================
function getPlayers() {
  return Array.from(players.values()).map(p => ({
    id: p.id,
    name: p.name,
    job: p.job,
    x: p.x,
    y: p.y,
    z: p.z,
    rot: p.rot,
    animation: p.animation,
    level: p.level || 0
  }));
}

// ============================================================
// پخش پیام به همه
// ============================================================
function broadcast(packet) {
  const json = JSON.stringify(packet);
  wss.clients.forEach(client => {
    if (client.readyState === 1) {
      try {
        client.send(json);
      } catch (err) {
        // Client disconnected
      }
    }
  });
}

// ============================================================
// Health check
// ============================================================
setInterval(() => {
  console.log(`💚 Health: ${players.size} players, ${wss.clients.size} clients`);
}, 30000);

// ============================================================
// مدیریت خطاها
// ============================================================
server.on('error', (error) => {
  console.error('Server error:', error);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ HTTP & WebSocket server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// ============================================================
// هندل کردن SIGTERM و SIGINT
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
