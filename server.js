import { WebSocketServer } from 'ws';
import config from './config.js';
import Player from './Player.js';
import VehicleManager from './VehicleManager.js';
import BanManager from './BanManager.js';
import Chat from './Chat.js';
import { PacketType } from './Packet.js';
import fs from 'fs';

if (!fs.existsSync('./data')) {
  fs.mkdirSync('./data');
}

const wss = new WebSocketServer({ port: config.port });
console.log(`🚀 Server running on port ${config.port}`);

const players = new Map();
const vehicleManager = new VehicleManager();
const banManager = new BanManager();
const chat = new Chat(banManager);

// ============================================================
// 📊 لاگ دوره‌ای وضعیت (هر ۵۰۰ میلی‌ثانیه)
// ============================================================
setInterval(() => {
  const playerCount = players.size;
  const vehicleCount = vehicleManager.vehicles.size;
  
  if (playerCount === 0 && vehicleCount === 0) return;

  console.log(`\n📊 [${new Date().toISOString()}] STATUS UPDATE`);
  console.log(`   👥 Players online: ${playerCount}`);
  console.log(`   🚗 Vehicles: ${vehicleCount}`);

  if (playerCount > 0) {
    console.log(`   📋 Players:`);
    for (const [id, player] of players) {
      console.log(`      - ${id.substring(0, 8)}... | Name: "${player.name || 'Unknown'}" | Pos: (${player.position.x.toFixed(1)}, ${player.position.y.toFixed(1)}) | Rot: ${player.rotation.toFixed(2)} | Vehicle: ${player.vehicleId ? player.vehicleId.substring(0, 8)+'...' : 'None'}`);
    }
  }

  if (vehicleCount > 0) {
    console.log(`   🚗 Vehicles:`);
    for (const [id, vehicle] of vehicleManager.vehicles) {
      const seats = vehicle.seats.map(s => s ? s.substring(0, 8)+'...' : 'Empty');
      console.log(`      - ${id.substring(0, 8)}... | Owner: ${vehicle.ownerId.substring(0, 8)}... | CarDB: ${vehicle.car_db_id || 'N/A'} | Pos: (${vehicle.position.x.toFixed(1)}, ${vehicle.position.y.toFixed(1)}) | Seats: [${seats.join(', ')}]`);
    }
  }
  console.log(`─────────────────────────────────────────────`);
}, 500);

// ============================================================
// 📡 توابع کمکی
// ============================================================
function broadcast(data, excludeId = null) {
  const message = JSON.stringify(data);
  for (const [id, player] of players) {
    if (id !== excludeId && player.ws.readyState === 1 && !player.isBanned) {
      player.ws.send(message);
    }
  }
}

function sendFullState(player) {
  const allPlayers = Array.from(players.values())
    .filter(p => !p.isBanned)
    .map(p => ({
      id: p.id,
      name: p.name,
      job: p.job,
      position: p.position,
      rotation: p.rotation
    }));

  player.send({
    type: PacketType.FULL_STATE,
    players: allPlayers,
    vehicles: vehicleManager.getAllVehicles(),
    bans: banManager.getBanList()
  });
}

// ============================================================
// 🔌 مدیریت اتصال
// ============================================================
wss.on('connection', (ws) => {
  const player = new Player(ws);
  players.set(player.id, player);

  if (banManager.isBanned(player.id)) {
    player.isBanned = true;
    player.send({ type: PacketType.YOU_ARE_BANNED, message: 'شما بن شده‌اید.' });
    player.close('Banned');
    players.delete(player.id);
    console.log(`🚫 Player banned: ${player.id}`);
    return;
  }

  console.log(`✅ [${new Date().toISOString()}] Player connected: ${player.id.substring(0, 8)}...`);
  player.send({ type: PacketType.SET_ID, id: player.id });
  sendFullState(player);

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw);
      handleMessage(player, data);
    } catch (err) {
      console.log(`❌ Invalid JSON from ${player.id.substring(0, 8)}...: ${err.message}`);
      player.send({ type: PacketType.ERROR, message: 'Invalid JSON' });
    }
  });

  ws.on('close', () => {
    const vehicle = vehicleManager.findVehicleByPlayer(player.id);
    if (vehicle) {
      // اگر پلیر مالک است، ماشین را کامل حذف کن
      if (player.id === vehicle.ownerId) {
        vehicleManager.removeVehicle(vehicle.id);
        console.log(`🚗 [${new Date().toISOString()}] Vehicle ${vehicle.id.substring(0, 8)}... (CarDB: ${vehicle.car_db_id}) removed (owner left)`);
        broadcast({ type: PacketType.VEHICLE_REMOVED, vehicleId: vehicle.id });
      } else {
        // اگر مسافر است، فقط از صندلی خارجش کن
        const seat = vehicle.removePassenger(player.id);
        if (seat !== -1) {
          console.log(`🚗 [${new Date().toISOString()}] Passenger ${player.id.substring(0, 8)}... left vehicle (seat ${seat})`);
          broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
        }
      }
    }
    players.delete(player.id);
    broadcast({ type: PacketType.PLAYER_LEFT, id: player.id });
    console.log(`❌ [${new Date().toISOString()}] Player disconnected: ${player.id.substring(0, 8)}...`);
  });
});

// ============================================================
// 📨 پردازش پیام‌ها
// ============================================================
function handleMessage(player, data) {
  if (player.isBanned) {
    player.send({ type: PacketType.ERROR, message: 'You are banned.' });
    return;
  }

  const { type } = data;

  switch (type) {
    case PacketType.UPDATE: {
      if (data.position) {
        player.position = data.position;
        console.log(`🔄 [${new Date().toISOString()}] Player ${player.id.substring(0, 8)}... moved to (${player.position.x.toFixed(1)}, ${player.position.y.toFixed(1)})`);
      }
      if (data.rotation !== undefined) {
        player.rotation = data.rotation;
        console.log(`🔄 [${new Date().toISOString()}] Player ${player.id.substring(0, 8)}... rotated to ${player.rotation.toFixed(2)}`);
      }
      broadcast({ type: PacketType.UPDATE, id: player.id, position: player.position, rotation: player.rotation }, player.id);
      break;
    }

    case PacketType.CHAT: {
      const msg = chat.processMessage(player.id, data.message);
      if (msg !== null) {
        console.log(`💬 [${new Date().toISOString()}] ${player.name || 'Unknown'} (${player.id.substring(0, 8)}...): ${msg}`);
        broadcast({ type: PacketType.CHAT, from: player.id, name: player.name || 'Unknown', message: msg });
      } else {
        player.send({ type: PacketType.ERROR, message: 'You are banned from chat.' });
      }
      break;
    }

    case PacketType.CREATE_VEHICLE: {
      const { name, job, position, rotation, steering, car_db_id } = data;
      if (!name || !job || !position) {
        player.send({ type: PacketType.ERROR, message: 'Missing vehicle data' });
        return;
      }
      // بررسی اینکه آیا قبلاً ماشین دارد یا نه (اختیاری)
      // اگر می‌خواهید هر مالک فقط یک ماشین داشته باشد، این بخش را فعال کنید:
      // if (vehicleManager.findVehiclesByOwner(player.id).length > 0) {
      //   player.send({ type: PacketType.ERROR, message: 'You already own a vehicle' });
      //   return;
      // }

      const vehicle = vehicleManager.createVehicle(
        player.id,
        name,
        job,
        position,
        rotation || 0,
        steering || 0,
        car_db_id || null  // اضافه کردن car_db_id
      );
      if (!vehicle) {
        player.send({ type: PacketType.ERROR, message: 'Vehicle creation failed' });
        return;
      }
      player.name = name;
      player.job = job;
      console.log(`🚗 [${new Date().toISOString()}] Vehicle created by ${player.id.substring(0, 8)}... (ID: ${vehicle.id.substring(0, 8)}..., CarDB: ${vehicle.car_db_id}) at (${position.x}, ${position.y})`);
      broadcast({ type: PacketType.VEHICLE_STATE, vehicle: vehicle.getState() });
      break;
    }

    case PacketType.JOIN_VEHICLE: {
      const { vehicleId, seatIndex } = data;
      if (seatIndex === undefined || seatIndex < 1 || seatIndex > 3) {
        player.send({ type: PacketType.ERROR, message: 'Invalid seat (1-3)' });
        return;
      }
      const vehicle = vehicleManager.getVehicle(vehicleId);
      if (!vehicle) {
        player.send({ type: PacketType.ERROR, message: 'Vehicle not found' });
        return;
      }
      const oldV = vehicleManager.findVehicleByPlayer(player.id);
      if (oldV) {
        if (oldV.ownerId === player.id) {
          player.send({ type: PacketType.ERROR, message: 'You are owner, cannot join another' });
          return;
        }
        oldV.removePassenger(player.id);
        console.log(`🚗 [${new Date().toISOString()}] Player ${player.id.substring(0, 8)}... left vehicle ${oldV.id.substring(0, 8)}...`);
      }
      if (!vehicle.addPassenger(player.id, seatIndex)) {
        player.send({ type: PacketType.ERROR, message: 'Seat not available' });
        return;
      }
      player.vehicleId = vehicle.id;
      player.seatIndex = seatIndex;
      console.log(`🚗 [${new Date().toISOString()}] Player ${player.id.substring(0, 8)}... joined vehicle ${vehicle.id.substring(0, 8)}... (seat ${seatIndex})`);
      broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      break;
    }

    case PacketType.LEAVE_VEHICLE: {
      const vehicle = vehicleManager.findVehicleByPlayer(player.id);
      if (!vehicle) {
        player.send({ type: PacketType.ERROR, message: 'Not in a vehicle' });
        return;
      }
      // اگر مالک است، ماشین را کامل حذف کن
      if (player.id === vehicle.ownerId) {
        vehicleManager.removeVehicle(vehicle.id);
        console.log(`🚗 [${new Date().toISOString()}] Vehicle ${vehicle.id.substring(0, 8)}... (CarDB: ${vehicle.car_db_id}) removed (owner left)`);
        broadcast({ type: PacketType.VEHICLE_REMOVED, vehicleId: vehicle.id });
        player.vehicleId = null;
        player.seatIndex = null;
      } else {
        // اگر مسافر است، فقط از صندلی خارجش کن
        const seat = vehicle.removePassenger(player.id);
        if (seat === -1) {
          player.send({ type: PacketType.ERROR, message: 'You are not in this vehicle' });
          return;
        }
        console.log(`🚗 [${new Date().toISOString()}] Passenger ${player.id.substring(0, 8)}... left vehicle (seat ${seat})`);
        broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
        player.vehicleId = null;
        player.seatIndex = null;
      }
      break;
    }

    case PacketType.UPDATE_VEHICLE: {
      const vehicle = vehicleManager.getVehicle(player.id);
      if (!vehicle) {
        player.send({ type: PacketType.ERROR, message: 'You don\'t own a vehicle' });
        return;
      }
      const { position, rotation, steering } = data;
      vehicle.updateState(position, rotation, steering);
      console.log(`🚗 [${new Date().toISOString()}] Vehicle ${vehicle.id.substring(0, 8)}... (CarDB: ${vehicle.car_db_id}) updated: Pos(${vehicle.position.x.toFixed(1)}, ${vehicle.position.y.toFixed(1)}) Rot: ${vehicle.rotation.toFixed(2)} Steer: ${vehicle.steering.toFixed(2)}`);
      broadcast({ type: PacketType.VEHICLE_STATE, vehicle: vehicle.getState() });
      break;
    }

    case PacketType.BAN_PLAYER: {
      const { targetId } = data;
      if (!targetId || targetId === player.id) {
        player.send({ type: PacketType.ERROR, message: 'Invalid target' });
        return;
      }
      banManager.ban(targetId);
      const target = players.get(targetId);
      if (target) {
        target.isBanned = true;
        target.send({ type: PacketType.YOU_ARE_BANNED, message: 'You have been banned.' });
        target.close('Banned');
        players.delete(targetId);
        console.log(`🚫 [${new Date().toISOString()}] Player ${player.id.substring(0, 8)}... banned ${targetId.substring(0, 8)}...`);
      }
      broadcast({ type: PacketType.BAN_LIST, bans: banManager.getBanList() });
      break;
    }

    case PacketType.UNBAN_PLAYER: {
      const { targetId } = data;
      if (!targetId) {
        player.send({ type: PacketType.ERROR, message: 'Missing targetId' });
        return;
      }
      banManager.unban(targetId);
      console.log(`🔓 [${new Date().toISOString()}] Player ${player.id.substring(0, 8)}... unbanned ${targetId.substring(0, 8)}...`);
      broadcast({ type: PacketType.BAN_LIST, bans: banManager.getBanList() });
      break;
    }

    case PacketType.PING:
      player.send({ type: PacketType.PING, timestamp: Date.now() });
      break;

    default:
      console.log(`⚠️ [${new Date().toISOString()}] Unknown message type from ${player.id.substring(0, 8)}...: ${type}`);
      player.send({ type: PacketType.ERROR, message: `Unknown type: ${type}` });
  }
}
