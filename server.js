// ============================================================
// 🖥️ سرور WebSocket - سازگار با کلاینت Godot
// ============================================================
// npm install ws uuid
// node server.js

const WebSocket = require("wss");
const http = require("http");
const { v4: uuidv4 } = require("uuid");
const url = require("url");

// ============================================================
// ⚙️ تنظیمات
// ============================================================
const CONFIG = {
  PORT: process.env.PORT || 8080,
  PING_INTERVAL: 30000,       // هر ۳۰ ثانیه ping
  MAX_MESSAGE_SIZE: 1024 * 64, // 64KB
  MAX_CLIENTS: 500,
  POSITION_BROADCAST_RATE: 80, // ms - هر ۸۰ms موقعیت broadcast بشه
};

// ============================================================
// 📦 ذخیره‌سازی داده
// ============================================================
const clients = new Map();        // wsId -> clientData
const userIdToWsId = new Map();   // userId -> wsId
const chatBans = new Map();       // userId -> banData

// ============================================================
// 🛠️ توابع کمکی
// ============================================================
function sendToClient(ws, data) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(data));
    } catch (err) {
      console.error("❌ Send error:", err.message);
    }
  }
}

function broadcast(data, excludeWsId = null) {
  const msg = JSON.stringify(data);
  clients.forEach((client, wsId) => {
    if (wsId !== excludeWsId && client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(msg);
      } catch (err) {
        console.error("❌ Broadcast error to", wsId, ":", err.message);
      }
    }
  });
}

function getPlayerSnapshot(client) {
  return {
    id: client.userId || client.id,
    wsId: client.id,
    name: client.name || "بازیکن",
    job: client.job || "بیکار",
    level: client.level || 0,
    x: client.x || 0,
    y: client.y || 0,
    z: client.z || 0,
    rot: client.rot || 0,
    animation: client.animation || "idle",
  };
}

function getAllPlayersSnapshot(excludeWsId = null) {
  const players = [];
  clients.forEach((client, wsId) => {
    if (wsId !== excludeWsId) {
      players.push(getPlayerSnapshot(client));
    }
  });
  return players;
}

function log(emoji, ...args) {
  const time = new Date().toLocaleTimeString("fa-IR");
  console.log(`[${time}] ${emoji}`, ...args);
}

// ============================================================
// 🚫 سیستم بن
// ============================================================
function isUserBanned(userId) {
  if (!chatBans.has(userId)) return false;
  const ban = chatBans.get(userId);
  if (ban.permanent) return true;
  if (ban.expiresAt && new Date() < new Date(ban.expiresAt)) return true;
  chatBans.delete(userId);
  return false;
}

function getBanInfo(userId) {
  if (!chatBans.has(userId)) return null;
  const ban = chatBans.get(userId);
  const now = new Date();
  const expires = ban.expiresAt ? new Date(ban.expiresAt) : null;
  const remainingMs = expires ? expires - now : null;
  const remainingMin = remainingMs ? Math.ceil(remainingMs / 60000) : null;
  return {
    reason: ban.reason || "تخلف",
    expires_in: ban.permanent
      ? "دائمی"
      : remainingMin
      ? `${remainingMin} دقیقه`
      : "نامحدود",
    permanent: ban.permanent || false,
  };
}

function banUser(userId, reason, durationHours = 1, permanent = false) {
  const expiresAt = permanent
    ? null
    : new Date(Date.now() + durationHours * 3600 * 1000).toISOString();
  chatBans.set(userId, {
    reason,
    expiresAt,
    permanent,
    bannedAt: new Date().toISOString(),
  });
  log("🚫", `User ${userId} banned. Reason: ${reason}, Expires: ${expiresAt || "Never"}`);

  const wsId = userIdToWsId.get(userId);
  if (wsId && clients.has(wsId)) {
    const client = clients.get(wsId);
    sendToClient(client.ws, {
      type: "ban",
      reason,
      expires_in: permanent ? "دائمی" : `${durationHours} ساعت`,
    });
  }
}

function unbanUser(userId) {
  chatBans.delete(userId);
  log("✅", `User ${userId} unbanned`);

  const wsId = userIdToWsId.get(userId);
  if (wsId && clients.has(wsId)) {
    const client = clients.get(wsId);
    sendToClient(client.ws, { type: "unban" });
  }
}

// ============================================================
// 📨 پردازش پیام‌ها
// ============================================================
function handleMessage(wsId, rawData) {
  let data;
  try {
    data = JSON.parse(rawData.toString());
  } catch {
    log("⚠️", `Invalid JSON from ${wsId}`);
    return;
  }

  const client = clients.get(wsId);
  if (!client) return;

  client.lastSeen = new Date();

  switch (data.type) {
    case "set_name": {
      const oldName = client.name;
      client.name = (data.name || "بازیکن").slice(0, 32);
      client.job = (data.job || "بیکار").slice(0, 32);

      if (data.userId && data.userId !== client.userId) {
        if (client.userId) userIdToWsId.delete(client.userId);
        client.userId = data.userId;
        userIdToWsId.set(data.userId, wsId);
      }

      log("📛", `${wsId} set name: ${client.name} | Job: ${client.job} | UserId: ${client.userId}`);

      broadcast(
        {
          type: "player_updated",
          player: getPlayerSnapshot(client),
        },
        wsId
      );
      break;
    }

    case "update": {
      client.x = typeof data.x === "number" ? data.x : 0;
      client.y = typeof data.y === "number" ? data.y : 0;
      client.z = typeof data.z === "number" ? data.z : 0;
      client.rot = typeof data.rot === "number" ? data.rot : 0;
      client.animation = data.animation || "idle";

      broadcast(
        {
          type: "player_moved",
          id: client.userId || client.id,
          x: client.x,
          y: client.y,
          z: client.z,
          rot: client.rot,
          animation: client.animation,
        },
        wsId
      );
      break;
    }

    case "chat": {
      if (!data.message || typeof data.message !== "string") return;
      const msg = data.message.trim().slice(0, 256);
      if (msg.length === 0) return;

      const userId = client.userId;

      if (isUserBanned(userId)) {
        const banInfo = getBanInfo(userId);
        sendToClient(client.ws, {
          type: "error",
          message: "شما از چت بن شده‌اید",
          data: {
            banned: true,
            reason: banInfo.reason,
            expires_in: banInfo.expires_in,
          },
        });
        return;
      }

      log("💬", `[${client.name}] ${msg}`);

      broadcast({
        type: "chat",
        id: client.userId || client.id,
        name: client.name,
        job: client.job,
        message: msg,
        timestamp: new Date().toISOString(),
      });
      break;
    }

    case "ping": {
      sendToClient(client.ws, { type: "pong" });
      break;
    }

    case "admin_ban": {
      if ((client.level || 0) < 4) {
        sendToClient(client.ws, {
          type: "error",
          message: "دسترسی ادمین لازم است",
        });
        return;
      }
      const targetId = data.targetUserId;
      const reason = data.reason || "تخلف";
      const duration = data.duration || 1;
      const permanent = data.permanent || false;
      banUser(targetId, reason, duration, permanent);
      sendToClient(client.ws, {
        type: "admin_response",
        success: true,
        message: `کاربر ${targetId} بن شد`,
      });
      break;
    }

    case "admin_unban": {
      if ((client.level || 0) < 4) {
        sendToClient(client.ws, {
          type: "error",
          message: "دسترسی ادمین لازم است",
        });
        return;
      }
      unbanUser(data.targetUserId);
      sendToClient(client.ws, {
        type: "admin_response",
        success: true,
        message: `کاربر ${data.targetUserId} آزاد شد`,
      });
      break;
    }

    case "admin_kick": {
      if ((client.level || 0) < 4) return;
      const targetWsId = userIdToWsId.get(data.targetUserId);
      if (targetWsId && clients.has(targetWsId)) {
        const target = clients.get(targetWsId);
        sendToClient(target.ws, {
          type: "kicked",
          reason: data.reason || "اخراج توسط ادمین",
        });
        target.ws.close();
      }
      break;
    }

    default:
      log("⚠️", `Unknown message type: ${data.type} from ${wsId}`);
  }
}

// ============================================================
// 🔌 مدیریت اتصال جدید
// ============================================================
function handleConnection(ws, req) {
  if (clients.size >= CONFIG.MAX_CLIENTS) {
    ws.close(1013, "Server full");
    return;
  }

  const parsedUrl = url.parse(req.url, true);
  const userId = parsedUrl.query.userId || "";
  const wsId = uuidv4();

  log("🔌", `New connection: wsId=${wsId}, userId=${userId}, IP=${req.socket.remoteAddress}`);

  const client = {
    ws,
    id: wsId,
    userId: userId || wsId,
    name: "بازیکن",
    job: "بیکار",
    level: 0,
    x: 0, y: 0, z: 0,
    rot: 0,
    animation: "idle",
    connectedAt: new Date(),
    lastSeen: new Date(),
  };

  if (userId) {
    const existingWsId = userIdToWsId.get(userId);
    if (existingWsId && clients.has(existingWsId)) {
      const existing = clients.get(existingWsId);
      log("⚠️", `Duplicate userId ${userId}, disconnecting old session`);
      sendToClient(existing.ws, {
        type: "error",
        message: "اتصال جدید با همین حساب کاربری برقرار شد",
      });
      existing.ws.close();
    }
    userIdToWsId.set(userId, wsId);
  }

  clients.set(wsId, client);

  sendToClient(ws, {
    type: "welcome",
    id: wsId,
    userId: client.userId,
    players: getAllPlayersSnapshot(wsId),
    serverTime: new Date().toISOString(),
  });

  broadcast(
    {
      type: "player_joined",
      player: getPlayerSnapshot(client),
    },
    wsId
  );

  log("👥", `Total clients: ${clients.size}`);

  ws.on("message", (data) => {
    if (data.length > CONFIG.MAX_MESSAGE_SIZE) {
      log("⚠️", `Message too large from ${wsId}`);
      return;
    }
    handleMessage(wsId, data);
  });

  ws.on("close", (code, reason) => {
    log("👋", `Disconnected: ${wsId} | Code: ${code} | Name: ${client.name}`);

    clients.delete(wsId);

    if (client.userId && userIdToWsId.get(client.userId) === wsId) {
      userIdToWsId.delete(client.userId);
    }

    broadcast({
      type: "player_left",
      id: client.userId || wsId,
      wsId: wsId,
      name: client.name,
    });

    log("👥", `Total clients: ${clients.size}`);
  });

  ws.on("error", (err) => {
    log("❌", `WebSocket error from ${wsId}:`, err.message);
  });
}

// ============================================================
// 🔄 Broadcast موقعیت همه پلیرها
// ============================================================
function startPositionBroadcast() {
  setInterval(() => {
    if (clients.size < 2) return;

    const allPlayers = getAllPlayersSnapshot();

    clients.forEach((client) => {
      if (client.ws.readyState !== WebSocket.OPEN) return;

      const otherPlayers = allPlayers.filter(
        (p) => p.id !== (client.userId || client.id)
      );

      if (otherPlayers.length === 0) return;

      try {
        client.ws.send(
          JSON.stringify({
            type: "players",
            players: otherPlayers,
          })
        );
      } catch (err) {
        // ignore
      }
    });
  }, CONFIG.POSITION_BROADCAST_RATE);
}

// ============================================================
// 🫀 Ping/Pong برای چک کردن اتصال‌های مرده
// ============================================================
function startHeartbeat(wss) {
  setInterval(() => {
    clients.forEach((client, wsId) => {
      if (client.ws.readyState !== WebSocket.OPEN) {
        clients.delete(wsId);
        return;
      }

      const inactiveMs = Date.now() - client.lastSeen.getTime();
      if (inactiveMs > 60000) {
        log("💤", `Inactive client ${wsId}, closing...`);
        client.ws.terminate();
        clients.delete(wsId);
        if (client.userId && userIdToWsId.get(client.userId) === wsId) {
          userIdToWsId.delete(client.userId);
        }
        return;
      }

      try {
        client.ws.ping();
      } catch (err) {
        // ignore
      }
    });
  }, CONFIG.PING_INTERVAL);
}

// ============================================================
// 🌐 HTTP Server (برای Health Check)
// ============================================================
const httpServer = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);

  // Health check - بهبود یافته
  if (parsedUrl.pathname === "/health") {
    res.writeHead(200, { 
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    });
    res.end(
      JSON.stringify({
        status: "ok",
        clients: clients.size,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        timestamp: new Date().toISOString(),
      })
    );
    return;
  }

  // لیست بازیکنان آنلاین
  if (parsedUrl.pathname === "/players") {
    res.writeHead(200, { 
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    });
    res.end(
      JSON.stringify({
        count: clients.size,
        players: getAllPlayersSnapshot(),
      })
    );
    return;
  }

  // پیش‌فرض
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end(`🎮 Game Server Running | Players: ${clients.size}`);
});

// ============================================================
// 🚀 راه‌اندازی WebSocket Server
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

// شروع برنامه‌های جانبی
startPositionBroadcast();
startHeartbeat(wss);

httpServer.listen(CONFIG.PORT, () => {
  log("🚀", `Server started on port ${CONFIG.PORT}`);
  log("🌐", `WebSocket: ws://localhost:${CONFIG.PORT}`);
  log("💊", `Health: http://localhost:${CONFIG.PORT}/health`);
  log("👥", `Players: http://localhost:${CONFIG.PORT}/players`);
  log("✅", `Server is ready to accept connections!`);
});

// ============================================================
// 📊 لاگ وضعیت هر ۵ دقیقه
// ============================================================
setInterval(() => {
  log(
    "📊",
    `Status | Clients: ${clients.size} | Banned: ${chatBans.size} | Uptime: ${Math.floor(process.uptime() / 60)}min`
  );
}, 300000);

// ============================================================
// 🛑 Graceful Shutdown
// ============================================================
process.on("SIGTERM", () => {
  log("🛑", "SIGTERM received, shutting down...");
  broadcast({ type: "server_shutdown", message: "سرور در حال بستن شدن است..." });
  setTimeout(() => {
    wss.close();
    httpServer.close();
    process.exit(0);
  }, 2000);
});

process.on("SIGINT", () => {
  log("🛑", "SIGINT received, shutting down...");
  broadcast({ type: "server_shutdown", message: "سرور در حال بستن شدن است..." });
  setTimeout(() => {
    wss.close();
    httpServer.close();
    process.exit(0);
  }, 2000);
});

// ============================================================
// 💥 Error Handlers - برای جلوگیری از crash
// ============================================================
process.on("uncaughtException", (err) => {
  log("💥", "Uncaught Exception:", err.message);
  console.error(err.stack);
  // سرور را نبندیم، فقط لاگ کنیم
});

process.on("unhandledRejection", (reason, promise) => {
  log("💥", "Unhandled Rejection at:", promise, "reason:", reason);
  // سرور را نبندیم، فقط لاگ کنیم
});

process.on("exit", (code) => {
  log("🔚", `Process exiting with code: ${code}`);
});

// ============================================================
// ✅ Keep-alive برای Railway
// ============================================================
setInterval(() => {
  // هر ۳۰ ثانیه یک لاگ بفرست تا Railway بداند سرور زنده است
  console.log(`[KEEP-ALIVE] Server is running... Clients: ${clients.size}`);
}, 30000);
