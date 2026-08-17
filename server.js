import { WebSocketServer } from 'ws';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';
import config from './config.js';

// ============================================================
// 📦 Packet Types (هماهنگ کامل با کلاینت گودوت)
// ============================================================
const PacketType = {
  SET_ID: 'set_id',
  FULL_STATE: 'full_state',
  UPDATE: 'update',
  PLAYER_LEFT: 'player_left',
  CHAT: 'chat',
  PING: 'ping',
  PONG: 'pong',
  ERROR: 'error',
  VEHICLE_STATE: 'vehicle_state',
  SEAT_UPDATE: 'seat_update',
  VEHICLE_REMOVED: 'vehicle_removed',
  CREATE_VEHICLE: 'create_vehicle',
  JOIN_VEHICLE: 'join_vehicle',
  LEAVE_VEHICLE: 'leave_vehicle',
  UPDATE_VEHICLE: 'update_vehicle',
  BAN_PLAYER: 'ban_player',
  UNBAN_PLAYER: 'unban_player',
  BAN_LIST: 'ban_list',
  YOU_ARE_BANNED: 'you_are_banned'
};

// ============================================================
// مدیریت پوشه داده
// ============================================================
if (!fs.existsSync('./data')) {
  fs.mkdirSync('./data');
}
const banFilePath = path.join(process.cwd(), 'data', 'bans.json');
if (!fs.existsSync(banFilePath)) {
  fs.writeFileSync(banFilePath, JSON.stringify([]));
}
let bans = JSON.parse(fs.readFileSync(banFilePath, 'utf8'));

// ============================================================
// کلاس Vehicle
// ============================================================
class Vehicle {
  constructor(id, type, position, rotation, ownerId) {
    this.id = id;
    this.type = type;
    this.position = position;
    this.rotation = rotation;
    this.ownerId = ownerId;
    this.occupants = new Map();
    this.speed = 0;
    this.fuel = 100;
    this.lastUpdate = Date.now();
  }

  addOccupant(playerId, seatIndex) {
    this.occupants.set(playerId, seatIndex);
  }

  removeOccupant(playerId) {
    this.occupants.delete(playerId);
  }

  update(position, rotation, speed, fuel) {
    this.position = position;
    this.rotation = rotation;
    this.speed = speed;
    this.fuel = Math.max(0, Math.min(100, fuel));
    this.lastUpdate = Date.now();
  }
}

// ============================================================
// کلاس VehicleManager
// ============================================================
class VehicleManager {
  constructor() {
    this.vehicles = new Map();
    this.nextVehicleId = 1;
    this.vehicleTypes = [
      'car', 'motorcycle', 'truck', 'bike', 'boat', 'plane', 'helicopter', 'tank'
    ];
  }

  createVehicle(ownerId) {
    const id = this.nextVehicleId++;
    const position = { x: Math.random() * 5000 - 2500, y: Math.random() * 5000 - 2500, z: 0 };
    const rotation = Math.random() * 360;
    const type = this.vehicleTypes[Math.floor(Math.random() * this.vehicleTypes.length)];
    const vehicle = new Vehicle(id, type, position, rotation, ownerId);
    this.vehicles.set(id, vehicle);
    return vehicle;
  }

  removeVehicle(id) {
    this.vehicles.delete(id);
  }

  getVehicle(id) {
    return this.vehicles.get(id);
  }

  getAllVehicles() {
    return Array.from(this.vehicles.values()).map(v => ({
      id: v.id,
      type: v.type,
      position: v.position,
      rotation: v.rotation,
      speed: v.speed,
      fuel: v.fuel,
      occupants: Array.from(v.occupants.entries())
    }));
  }

  updateVehicle(id, position, rotation, speed, fuel) {
    const vehicle = this.vehicles.get(id);
    if (vehicle) {
      vehicle.update(position, rotation, speed, fuel);
      return true;
    }
    return false;
  }
}

// ============================================================
// کلاس BanManager
// ============================================================
class BanManager {
  constructor() {
    this.bans = new Map();
    this.loadBans();
  }

  loadBans() {
    bans.forEach(ban => {
      this.bans.set(ban.user_id, ban);
    });
  }

  saveBans() {
    bans = Array.from(this.bans.values());
    fs.writeFileSync(banFilePath, JSON.stringify(bans, null, 2));
  }

  banPlayer(user_id, reason, duration = 0) {
    const ban = {
      user_id,
      reason,
      duration,
      banned_at: Date.now(),
      expires_at: duration > 0 ? Date.now() + duration * 24 * 60 * 60 * 1000 : null
    };
    this.bans.set(user_id, ban);
    this.saveBans();
    return ban;
  }

  unbanPlayer(user_id) {
    if (this.bans.delete(user_id)) {
      this.saveBans();
      return true;
    }
    return false;
  }

  isBanned(user_id) {
    if (!this.bans.has(user_id)) return false;
    const ban = this.bans.get(user_id);
    if (ban.expires_at && ban.expires_at < Date.now()) {
      this.unbanPlayer(user_id);
      return false;
    }
    return true;
  }

  getBanList() {
    return Array.from(this.bans.values()).map(ban => ({
      user_id: ban.user_id,
      reason: ban.reason,
      banned_at: ban.banned_at,
      expires_at: ban.expires_at
    }));
  }
}

// ============================================================
// کلاس Chat
// ============================================================
class Chat {
  constructor(banManager) {
    this.banManager = banManager;
  }

  broadcastMessage(wss, senderId, senderName, message) {
    if (message.length > 200) {
      senderName.send({ type: PacketType.ERROR, message: 'Message too long' });
      return;
    }
    if (message.startsWith('/ban ')) {
      const targetUser = message.substring(5).trim();
      if (targetUser) {
        this.banManager.banPlayer(targetUser, `Banned by ${senderName}`);
        const sender = Array.from(wss.clients).find(c => c.userId === senderId);
        if (sender) {
          sender.send({ type: PacketType.BAN_PLAYER, targetUser, reason: `Banned by ${senderName}` });
        }
      }
      return;
    }
    if (message.startsWith('/unban ')) {
      const targetUser = message.substring(7).trim();
      if (targetUser) {
        this.banManager.unbanPlayer(targetUser);
        const sender = Array.from(wss.clients).find(c => c.userId === senderId);
        if (sender) {
          sender.send({ type: PacketType.UNBAN_PLAYER, targetUser });
        }
      }
      return;
    }
    const payload = {
      type: PacketType.CHAT,
      sender_id: senderId,
      sender_name: senderName,
      message: message
    };
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(payload));
      }
    });
  }
}

// ============================================================
// کلاس Player
// ============================================================
class Player {
  constructor(ws, connectionId) {
    this.id = connectionId;
    this.user_id = null;
    this.name = 'Unknown';
    this.job = '';
    this.position = { x: 0, y: 0, z: 0 };
    this.rotation = 0;
    this.vehicleId = null;
    this.seatIndex = null;
    this.isBanned = false;
    this.lastUpdate = Date.now();
    this.ws = ws;
  }

  send(data) {
    try {
      if (this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify(data));
      }
    } catch (e) {}
  }

  close(reason = '') {
    try {
      this.ws.close(1000, reason);
    } catch (e) {}
  }
}

// ============================================================
// Server
// ============================================================
const port = config.port;
const wss = new WebSocketServer({ port });
console.log(`🚀 Server running on port ${port} | Mode: Waiting for player ID from client`);

const players = new Map();
const userMap = new Map();
const vehicleManager = new VehicleManager();
const banManager = new BanManager();
const chat = new Chat(banManager);

// ============================================================
// Broadcast functions
// ============================================================
function broadcast(data, excludeId = null) {
  const payload = JSON.stringify(data);
  players.forEach(player => {
    if (player.ws.readyState === WebSocket.OPEN && player.id !== excludeId) {
      player.send(payload);
    }
  });
}

function broadcastToVehicle(vehicle, data, excludeId = null) {
  const payload = JSON.stringify(data);
  Array.from(vehicle.occupants.keys()).forEach(playerId => {
    const player = players.get(playerId);
    if (player && player.ws.readyState === WebSocket.OPEN && player.id !== excludeId) {
      player.send(payload);
    }
  });
}

// ============================================================
// Periodic status (full state every 2 seconds)
// ============================================================
setInterval(() => {
  const fullState = {
    type: PacketType.FULL_STATE,
    players: Array.from(players.values()).map(p => ({
      id: p.id,
      user_id: p.user_id || p.id,
      name: p.name,
      job: p.job,
      position: p.position,
      rotation: p.rotation
    })),
    vehicles: vehicleManager.getAllVehicles()
  };
  players.forEach(player => {
    if (player.ws.readyState === WebSocket.OPEN) {
      player.send(JSON.stringify(fullState));
    }
  });
}, 2000);

// ============================================================
// Core message handler
// ============================================================
function handleMessage(player, data) {
  if (!data || typeof data !== 'object') {
    player.send({ type: PacketType.ERROR, message: 'Invalid data' });
    return;
  }

  if (player.isBanned) {
    player.send({ type: PacketType.ERROR, message: 'You are banned.' });
    return;
  }

  const type = data.type;

  switch (type) {
    case PacketType.SET_ID: {
      if (data.id) {
        const userId = String(data.id);
        if (/^[A-Za-z0-9_-]{3,50}$/.test(userId)) {
          if (userMap.has(userId)) {
            const oldConnId = userMap.get(userId);
            const oldPlayer = players.get(oldConnId);
            if (oldPlayer) {
              try { oldPlayer.send({ type: PacketType.ERROR, message: 'Replaced by new connection' }); } catch(e) {}
              oldPlayer.close('Replaced by new connection');
              players.delete(oldConnId);
            }
            userMap.delete(userId);
          }
          player.user_id = userId;
          userMap.set(userId, player.id);
          player.send({ type: PacketType.SET_ID, id: player.id });
          console.log(`✅ Player registered: ${userId}`);
        } else {
          player.send({ type: PacketType.ERROR, message: 'Invalid user_id format' });
        }
      }
      break;
    }

    case PacketType.UPDATE: {
      let userId = data.user_id;
      if (userId) {
        userId = String(userId);
        if (!/^[A-Za-z0-9_-]{3,50}$/.test(userId)) {
          player.send({ type: PacketType.ERROR, message: 'Invalid user_id format' });
          return;
        }
      }

      if (userId) {
        const existingConnId = userMap.get(userId);
        if (existingConnId && existingConnId !== player.id) {
          const oldPlayer = players.get(existingConnId);
          if (oldPlayer) {
            try { oldPlayer.send({ type: PacketType.ERROR, message: 'Replaced by new connection' }); } catch(e) {}
            oldPlayer.close('Replaced');
            players.delete(existingConnId);
          }
          userMap.delete(userId);
        }
        player.user_id = userId;
        userMap.set(userId, player.id);
      }

      if (data.name !== undefined) player.name = data.name;
      if (data.job !== undefined) player.job = data.job;
      if (data.position) {
        if (typeof data.position.x === 'number' && typeof data.position.y === 'number' && typeof data.position.z === 'number') {
          player.position = { x: data.position.x, y: data.position.y, z: data.position.z };
        } else {
          player.send({ type: PacketType.ERROR, message: 'Invalid position format' });
          return;
        }
      }
      if (data.rotation !== undefined) player.rotation = data.rotation;
      player.lastUpdate = Date.now();

      broadcast({
        type: PacketType.UPDATE,
        id: player.id,
        user_id: player.user_id || player.id,
        name: player.name,
        job: player.job,
        position: player.position,
        rotation: player.rotation,
        anim: data.anim || 0,
        speed: data.speed || 0,
        is_grounded: data.is_grounded !== undefined ? data.is_grounded : true
      }, player.id);

      if (data.vehicle_id !== undefined) {
        if (data.vehicle_id !== null && data.vehicle_id !== '') {
          let vehicle = vehicleManager.getVehicle(data.vehicle_id);
          if (!vehicle) {
            vehicle = vehicleManager.createVehicle(player.user_id || player.id);
            vehicleManager.updateVehicle(vehicle.id, data.position || { x: 0, y: 0, z: 0 }, data.rotation || 0, data.speed || 0, 100);
          }
          player.vehicleId = vehicle.id;
          player.seatIndex = data.seat_index;
          vehicle.addOccupant(player.id, data.seat_index);
        } else if (player.vehicleId) {
          const vehicle = vehicleManager.getVehicle(player.vehicleId);
          if (vehicle) {
            vehicle.removeOccupant(player.id);
            player.vehicleId = null;
            player.seatIndex = null;
          }
        }
      }

      if (data.vehicle_state) {
        const vehicleId = data.vehicle_state.id;
        if (vehicleManager.getVehicle(vehicleId)) {
          vehicleManager.updateVehicle(vehicleId, data.vehicle_state.position, data.vehicle_state.rotation, data.vehicle_state.speed, data.vehicle_state.fuel);
        }
      }

      break;
    }

    case PacketType.CHAT: {
      chat.broadcastMessage(wss, player.id, player.name, data.message);
      break;
    }

    case PacketType.CREATE_VEHICLE: {
      if (player.user_id) {
        const vehicle = vehicleManager.createVehicle(player.user_id);
        const fullVehicle = {
          id: vehicle.id,
          type: vehicle.type,
          position: vehicle.position,
          rotation: vehicle.rotation,
          occupants: Array.from(vehicle.occupants.entries())
        };
        broadcast({ type: PacketType.CREATE_VEHICLE, vehicle: fullVehicle }, player.id);
      }
      break;
    }

    case PacketType.JOIN_VEHICLE: {
      const vehicle = vehicleManager.getVehicle(data.vehicle_id);
      if (vehicle && data.seat_index >= 0 && data.seat_index < config.vehicle.maxSeats) {
        vehicle.addOccupant(player.id, data.seat_index);
        player.vehicleId = vehicle.id;
        player.seatIndex = data.seat_index;
        broadcastToVehicle(vehicle, { type: PacketType.JOIN_VEHICLE, player_id: player.id, seat_index: data.seat_index }, player.id);
      }
      break;
    }

    case PacketType.LEAVE_VEHICLE: {
      const vehicle = vehicleManager.getVehicle(player.vehicleId);
      if (vehicle) {
        vehicle.removeOccupant(player.id);
        player.vehicleId = null;
        player.seatIndex = null;
        broadcast({ type: PacketType.LEAVE_VEHICLE, player_id: player.id }, player.id);
      }
      break;
    }

    case PacketType.BAN_PLAYER: {
      const targetUser = data.user_id;
      if (player.user_id) {
        banManager.banPlayer(targetUser, `Banned by ${player.name}`);
        broadcast({ type: PacketType.BAN_PLAYER, targetUser, reason: `Banned by ${player.name}` });
      }
      break;
    }

    case PacketType.UNBAN_PLAYER: {
      const targetUser = data.user_id;
      if (player.user_id) {
        banManager.unbanPlayer(targetUser);
        broadcast({ type: PacketType.UNBAN_PLAYER, targetUser });
      }
      break;
    }

    case PacketType.BAN_LIST: {
      player.send({ type: PacketType.BAN_LIST, bans: banManager.getBanList() });
      break;
    }

    default:
      player.send({ type: PacketType.ERROR, message: 'Unknown packet type' });
  }
}

// ============================================================
// WebSocket connection
// ============================================================
wss.on('connection', (ws) => {
  const tempConnectionId = randomUUID();
  const player = new Player(ws, tempConnectionId);
  
  players.set(player.id, player);
  console.log(`🔗 New connection received, waiting for SET_ID...`);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      
      if (data.type === PacketType.SET_ID && data.id) {
        const clientId = String(data.id);
        
        if (!/^[A-Za-z0-9_-]{3,50}$/.test(clientId)) {
          player.send({ type: PacketType.ERROR, message: 'Invalid ID format' });
          player.close('Invalid ID format');
          return;
        }

        if (players.has(clientId)) {
          const oldPlayer = players.get(clientId);
          if (oldPlayer) {
            try { oldPlayer.send({ type: PacketType.ERROR, message: 'Replaced by new connection' }); } catch(e) {}
            oldPlayer.close('Replaced by new connection');
          }
        }

        players.delete(tempConnectionId);
        player.id = clientId;
        players.set(clientId, player);

        player.send({ type: PacketType.SET_ID, id: clientId });
        console.log(`✅ Client connected with ID: ${clientId}`);
      } else {
        handleMessage(player, data);
      }
    } catch (e) {
      console.error('Message parse error:', e);
      player.send({ type: PacketType.ERROR, message: 'Invalid JSON' });
    }
  });

  ws.on('close', () => {
    players.delete(player.id);
    if (player.user_id) {
      userMap.delete(player.user_id);
    }
    if (player.vehicleId) {
      const vehicle = vehicleManager.getVehicle(player.vehicleId);
      if (vehicle) {
        vehicle.removeOccupant(player.id);
      }
    }
    broadcast({ type: PacketType.PLAYER_LEFT, id: player.id });
    console.log(`❌ Client disconnected: ${player.id}`);
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
  });
});

// ============================================================
// Full state on connection
// ============================================================
setTimeout(() => {
  const fullState = {
    type: PacketType.FULL_STATE,
    players: Array.from(players.values()).map(p => ({
      id: p.id,
      user_id: p.user_id || p.id,
      name: p.name,
      job: p.job,
      position: p.position,
      rotation: p.rotation
    })),
    vehicles: vehicleManager.getAllVehicles()
  };
  players.forEach(player => {
    if (player.ws.readyState === WebSocket.OPEN) {
      player.send(JSON.stringify(fullState));
    }
  });
}, 500);

// ============================================================
// Periodic vehicle status
// ============================================================
setInterval(() => {
  const vehicleUpdates = vehicleManager.getAllVehicles().map(v => ({
    id: v.id,
    position: v.position,
    rotation: v.rotation,
    speed: v.speed,
    fuel: v.fuel
  }));
  broadcast({ type: PacketType.VEHICLE_STATE, vehicles: vehicleUpdates });
}, 1000);

// ============================================================
// Keep-alive
// ============================================================
setInterval(() => {
  players.forEach(player => {
    if (player.ws.readyState === WebSocket.OPEN) {
      player.send({ type: PacketType.PING });
    }
  });
}, 10000);

// ============================================================
// Shutdown handling
// ============================================================
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  wss.close();
  process.exit(0);
});

console.log('🚀 Server is ready and waiting for connections!');
