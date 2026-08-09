import { WebSocketServer } from 'ws';
import { randomUUID } from 'crypto';
import fs from 'fs';
import config from './config.js';

// ============================================================
// 📦 Packet Types (هماهنگ با کلاینت گودوت)
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
// 📂 پوشه داده
// ============================================================
if (!fs.existsSync('./data')) {
  fs.mkdirSync('./data');
}

// ============================================================
// 🧩 کلاس Player (با user_id)
// ============================================================
class Player {
  constructor(ws) {
    this.id = randomUUID(); // connection id
    this.user_id = null; // persistent id from client
    this.ws = ws;
    this.name = 'Unknown';
    this.job = '';
    this.position = { x: 0, y: 0, z: 0 };
    this.rotation = 0;
    this.vehicleId = null;
    this.seatIndex = null;
    this.isBanned = false;
    this.lastUpdate = Date.now();
  }

  send(data) {
    if (this.ws && this.ws.readyState === 1) {
      try { this.ws.send(JSON.stringify(data)); } catch (e) {}
    }
  }

  close(reason = '') {
    if (this.ws && this.ws.readyState === 1) {
      try { this.ws.close(1000, reason); } catch (e) {}
    }
  }
}

// ============================================================
// 🚗 Vehicle
// ============================================================
class Vehicle {
  constructor(ownerId, name, job, position, rotation, steering, car_db_id) {
    this.id = randomUUID();
    this.ownerId = ownerId;
    this.name = name;
    this.job = job;
    this.position = { x: position.x, y: position.y, z: position.z };
    this.rotation = rotation || 0;
    this.steering = steering || 0;
    this.car_db_id = car_db_id || null;
    this.seats = [null, null, null, null]; // 4 seats index 0-3
  }

  getState() {
    return {
      id: this.id,
      ownerId: this.ownerId,
      name: this.name,
      job: this.job,
      position: this.position,
      rotation: this.rotation,
      steering: this.steering,
      car_db_id: this.car_db_id,
      seats: this.seats
    };
  }

  addPassenger(playerId, seatIndex) {
    if (seatIndex < 0 || seatIndex >= this.seats.length) return false;
    if (this.seats[seatIndex] !== null) return false;
    this.seats[seatIndex] = playerId;
    return true;
  }

  removePassenger(playerId) {
    for (let i = 0; i < this.seats.length; i++) {
      if (this.seats[i] === playerId) {
        this.seats[i] = null;
        return i;
      }
    }
    return -1;
  }

  updateState(position, rotation, steering) {
    if (position) this.position = position;
    if (rotation !== undefined) this.rotation = rotation;
    if (steering !== undefined) this.steering = steering;
  }
}

// ============================================================
// VehicleManager
// ============================================================
class VehicleManager {
  constructor() {
    this.vehicles = new Map();
  }

  createVehicle(ownerId, name, job, position, rotation, steering, car_db_id) {
    const vehicle = new Vehicle(ownerId, name, job, position, rotation, steering, car_db_id);
    this.vehicles.set(vehicle.id, vehicle);
    return vehicle;
  }

  getVehicle(id) {
    return this.vehicles.get(id) || null;
  }

  removeVehicle(id) {
    return this.vehicles.delete(id);
  }

  findVehicleByPlayer(playerId) {
    for (const [id, vehicle] of this.vehicles) {
      if (vehicle.ownerId === playerId) return vehicle;
      if (vehicle.seats.includes(playerId)) return vehicle;
    }
    return null;
  }

  findVehiclesByOwner(ownerId) {
    const result = [];
    for (const [id, vehicle] of this.vehicles) {
      if (vehicle.ownerId === ownerId) result.push(vehicle);
    }
    return result;
  }

  getAllVehicles() {
    const result = [];
    for (const [id, vehicle] of this.vehicles) result.push(vehicle.getState());
    return result;
  }
}

// ============================================================
// BanManager
// ============================================================
class BanManager {
  constructor() {
    this.bans = new Set();
    this.loadFromFile();
  }

  loadFromFile() {
    try {
      if (fs.existsSync('./data/bans.json')) {
        const data = JSON.parse(fs.readFileSync('./data/bans.json', 'utf8'));
        this.bans = new Set(data);
      }
    } catch (err) {
      console.log('⚠️ Failed to load bans:', err.message);
    }
  }

  saveToFile() {
    try {
      fs.writeFileSync('./data/bans.json', JSON.stringify(Array.from(this.bans)));
    } catch (err) {
      console.log('⚠️ Failed to save bans:', err.message);
    }
  }

  ban(id) {
    this.bans.add(id);
    this.saveToFile();
  }

  unban(id) {
    this.bans.delete(id);
    this.saveToFile();
  }

  isBanned(id) {
    return this.bans.has(id);
  }

  getBanList() {
    return Array.from(this.bans);
  }
}

// ============================================================
// Chat
// ============================================================
class Chat {
  constructor(banManager) {
    this.banManager = banManager;
  }

  processMessage(playerId, message) {
    if (this.banManager.isBanned(playerId)) return null;
    return (message || '').substring(0, 200);
  }
}

// ============================================================
// Server setup
// ============================================================
const port = (typeof config !== 'undefined' && config?.port) ? config.port : (process.env.PORT ? Number(process.env.PORT) : 8080);
const wss = new WebSocketServer({ port });
console.log(`🚀 Server running on port ${port}`);

const players = new Map(); // connectionId -> Player
const userMap = new Map(); // user_id -> connectionId
const vehicleManager = new VehicleManager();
const banManager = new BanManager();
const chat = new Chat(banManager);

// periodic status log
setInterval(() => {
  const playerCount = players.size;
  const vehicleCount = vehicleManager.vehicles.size;
  if (playerCount === 0 && vehicleCount === 0) return;
  console.log(`\n📊 [${new Date().toISOString()}] STATUS UPDATE`);
  console.log(`   Players online: ${playerCount}`);
  console.log(`   Vehicles: ${vehicleCount}`);
  for (const [id, p] of players) {
    console.log(`     - ${id.substring(0,8)}... | User: ${p.user_id || 'N/A'} | Name: "${p.name}" | Pos: (${p.position.x.toFixed(1)}, ${p.position.y.toFixed(1)}, ${p.position.z.toFixed(1)}) | Rot: ${p.rotation.toFixed(2)}`);
  }
}, 500);

// helpers
function broadcast(data, excludeId = null) {
  const message = JSON.stringify(data);
  for (const [id, player] of players) {
    if (id !== excludeId && player.ws && player.ws.readyState === 1 && !player.isBanned) {
      try { player.ws.send(message); } catch (e) {}
    }
  }
}

function findPlayerByUserIdOrConnId(idOrUser) {
  if (players.has(idOrUser)) return players.get(idOrUser);
  if (userMap.has(idOrUser)) {
    const connId = userMap.get(idOrUser);
    return players.get(connId) || null;
  }
  for (const p of players.values()) if (p.user_id === idOrUser) return p;
  return null;
}

function sendFullState(player) {
  const allPlayers = [];
  for (const p of players.values()) {
    if (p.id === player.id) continue;
    allPlayers.push({
      id: p.id,
      user_id: p.user_id || p.id,
      name: p.name || 'Unknown',
      job: p.job || '',
      position: p.position,
      rotation: p.rotation
    });
  }
  player.send({ type: PacketType.FULL_STATE, players: allPlayers, vehicles: vehicleManager.getAllVehicles(), bans: banManager.getBanList() });
  console.log(`📦 Sent full_state to ${player.name} (${allPlayers.length} other players)`);
}

// core message handling
function handleMessage(player, data) {
  if (!data || typeof data !== 'object') return;
  if (player.isBanned) { player.send({ type: PacketType.ERROR, message: 'You are banned.'}); return; }
  const type = data.type;
  switch (type) {
    case PacketType.UPDATE: {
      if (data.user_id) {
        const incomingUserId = String(data.user_id);
        if (player.user_id !== incomingUserId) {
          const existingConnId = userMap.get(incomingUserId);
          if (existingConnId && existingConnId !== player.id) {
            const old = players.get(existingConnId);
            if (old) {
              try { old.send({ type: PacketType.ERROR, message: 'Replaced by new connection' }); } catch(e) {}
              old.close('Replaced');
              players.delete(existingConnId);
            }
            userMap.delete(incomingUserId);
          }
          player.user_id = incomingUserId;
          userMap.set(incomingUserId, player.id);
        }
      }

      if (data.name !== undefined) player.name = data.name;
      if (data.job !== undefined) player.job = data.job;

      if (data.position) {
        if (typeof data.position.x === 'number' && typeof data.position.y === 'number' && typeof data.position.z === 'number') {
          player.position = { x: data.position.x, y: data.position.y, z: data.position.z };
        } else {
          player.send({ type: PacketType.ERROR, message: 'Invalid position format (need x, y, z)' });
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
      break;
    }

    case PacketType.PING: {
      player.send({ type: PacketType.PONG, timestamp: Date.now() });
      break;
    }

    case PacketType.CHAT: {
      const msg = chat.processMessage(player.user_id || player.id, data.message);
      if (msg !== null) {
        broadcast({ type: PacketType.CHAT, from: player.user_id || player.id, name: player.name || 'Unknown', message: msg });
      } else {
        player.send({ type: PacketType.ERROR, message: 'You are banned from chat.'});
      }
      break;
    }

    case PacketType.CREATE_VEHICLE: {
      const { name, job, position, rotation, steering, car_db_id } = data;
      if (!name || !job || !position) { player.send({ type: PacketType.ERROR, message: 'Missing vehicle data' }); return; }
      if (typeof position.x !== 'number' || typeof position.y !== 'number' || typeof position.z !== 'number') { player.send({ type: PacketType.ERROR, message: 'Position must have x, y, z' }); return; }
      const vehicle = vehicleManager.createVehicle(player.id, name, job, position, rotation || 0, steering || 0, car_db_id || null);
      if (!vehicle) { player.send({ type: PacketType.ERROR, message: 'Vehicle creation failed' }); return; }
      player.name = name; player.job = job;
      const stateMsg = { type: PacketType.VEHICLE_STATE, vehicle: vehicle.getState() };
      player.send(stateMsg); broadcast(stateMsg, player.id);
      break;
    }

    case PacketType.JOIN_VEHICLE: {
      const { vehicleId, seatIndex } = data;
      if (seatIndex === undefined || seatIndex < 1 || seatIndex > 3) { player.send({ type: PacketType.ERROR, message: 'Invalid seat (1-3)' }); return; }
      const vehicle = vehicleManager.getVehicle(vehicleId);
      if (!vehicle) { player.send({ type: PacketType.ERROR, message: 'Vehicle not found' }); return; }
      const oldV = vehicleManager.findVehicleByPlayer(player.id);
      if (oldV) {
        if (oldV.ownerId === player.id) { player.send({ type: PacketType.ERROR, message: 'You are owner, cannot join another' }); return; }
        oldV.removePassenger(player.id);
      }
      if (!vehicle.addPassenger(player.id, seatIndex)) { player.send({ type: PacketType.ERROR, message: 'Seat not available' }); return; }
      player.vehicleId = vehicle.id; player.seatIndex = seatIndex;
      broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      break;
    }

    case PacketType.LEAVE_VEHICLE: {
      const vehicle = vehicleManager.findVehicleByPlayer(player.id);
      if (!vehicle) { player.send({ type: PacketType.ERROR, message: 'Not in a vehicle' }); return; }
      if (player.id === vehicle.ownerId) {
        vehicleManager.removeVehicle(vehicle.id);
        broadcast({ type: PacketType.VEHICLE_REMOVED, vehicleId: vehicle.id });
      } else {
        const seat = vehicle.removePassenger(player.id);
        if (seat === -1) { player.send({ type: PacketType.ERROR, message: 'You are not in this vehicle' }); return; }
        broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      }
      player.vehicleId = null; player.seatIndex = null; break;
    }

    case PacketType.UPDATE_VEHICLE: {
      const vehicles = vehicleManager.findVehiclesByOwner(player.id);
      if (vehicles.length === 0) { player.send({ type: PacketType.ERROR, message: "You don't own a vehicle" }); return; }
      const vehicle = vehicles[0]; const { position, rotation, steering } = data;
      if (position) {
        if (typeof position.x !== 'number' || typeof position.y !== 'number' || typeof position.z !== 'number') { player.send({ type: PacketType.ERROR, message: 'Position must have x, y, z' }); return; }
        vehicle.updateState(position, rotation, steering);
      } else vehicle.updateState(null, rotation, steering);
      const stateMsg = { type: PacketType.VEHICLE_STATE, vehicle: vehicle.getState() };
      player.send(stateMsg); broadcast(stateMsg, player.id); break;
    }

    case PacketType.BAN_PLAYER: {
      const { targetId } = data;
      if (!targetId || targetId === player.id || targetId === player.user_id) { player.send({ type: PacketType.ERROR, message: 'Invalid target' }); return; }
      banManager.ban(targetId);
      const target = findPlayerByUserIdOrConnId(targetId);
      if (target) {
        target.isBanned = true; try { target.send({ type: PacketType.YOU_ARE_BANNED, message: 'You have been banned.' }); } catch(e) {}
        target.close('Banned'); players.delete(target.id); if (target.user_id) userMap.delete(target.user_id);
      }
      broadcast({ type: PacketType.BAN_LIST, bans: banManager.getBanList() }); break;
    }

    case PacketType.UNBAN_PLAYER: {
      const { targetId } = data; if (!targetId) { player.send({ type: PacketType.ERROR, message: 'Missing targetId' }); return; }
      banManager.unban(targetId); broadcast({ type: PacketType.BAN_LIST, bans: banManager.getBanList() }); break;
    }

    default: { player.send({ type: PacketType.ERROR, message: `Unknown type: ${type}` }); }
  }
}

// connection handling
wss.on('connection', (ws) => {
  const player = new Player(ws); players.set(player.id, player);
  console.log(`✅ [${new Date().toISOString()}] Player connected: ${player.id.substring(0,8)}...`);
  player.send({ type: PacketType.SET_ID, id: player.id });
  sendFullState(player);

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      handleMessage(player, data);
    } catch (err) {
      console.log(`❌ Invalid JSON from ${player.id.substring(0,8)}...: ${err.message}`);
      player.send({ type: PacketType.ERROR, message: 'Invalid JSON' });
    }
  });

  ws.on('close', () => {
    const vehicle = vehicleManager.findVehicleByPlayer(player.id);
    if (vehicle) {
      if (player.id === vehicle.ownerId) {
        vehicleManager.removeVehicle(vehicle.id);
        broadcast({ type: PacketType.VEHICLE_REMOVED, vehicleId: vehicle.id });
      } else {
        const seat = vehicle.removePassenger(player.id);
        if (seat !== -1) broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      }
    }
    players.delete(player.id); if (player.user_id) userMap.delete(player.user_id);
    broadcast({ type: PacketType.PLAYER_LEFT, id: player.user_id || player.id });
    console.log(`❌ [${new Date().toISOString()}] Player disconnected: ${player.id.substring(0,8)}... (${player.name})`);
  });
});

// cleanup
setInterval(() => {
  for (const [id, p] of players) {
    try {
      if (!p.ws || p.ws.readyState !== 1) {
        players.delete(id); if (p.user_id) userMap.delete(p.user_id);
      }
    } catch(e) { players.delete(id); if (p.user_id) userMap.delete(p.user_id); }
  }
}, 60000);

console.log('🚀 Server is ready!');
