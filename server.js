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

wss.on('connection', (ws) => {
  const player = new Player(ws);
  players.set(player.id, player);

  if (banManager.isBanned(player.id)) {
    player.isBanned = true;
    player.send({ type: PacketType.YOU_ARE_BANNED, message: 'شما بن شده‌اید.' });
    player.close('Banned');
    players.delete(player.id);
    return;
  }

  console.log(`✅ Player connected: ${player.id}`);
  player.send({ type: PacketType.SET_ID, id: player.id });
  sendFullState(player);

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw);
      handleMessage(player, data);
    } catch (err) {
      player.send({ type: PacketType.ERROR, message: 'Invalid JSON' });
    }
  });

  ws.on('close', () => {
    const vehicle = vehicleManager.findVehicleByPlayer(player.id);
    if (vehicle) {
      const seat = vehicle.removePassenger(player.id);
      if (seat !== -1) {
        // ✅ تغییر: ماشین را حذف نکن، فقط صندلی را خالی کن
        broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      }
    }
    players.delete(player.id);
    broadcast({ type: PacketType.PLAYER_LEFT, id: player.id });
    console.log(`❌ Player disconnected: ${player.id}`);
  });
});

function handleMessage(player, data) {
  if (player.isBanned) {
    player.send({ type: PacketType.ERROR, message: 'You are banned.' });
    return;
  }

  const { type } = data;

  switch (type) {
    case PacketType.UPDATE:
      if (data.position) player.position = data.position;
      if (data.rotation !== undefined) player.rotation = data.rotation;
      broadcast({ type: PacketType.UPDATE, id: player.id, position: player.position, rotation: player.rotation }, player.id);
      break;

    case PacketType.CHAT: {
      const msg = chat.processMessage(player.id, data.message);
      if (msg !== null) {
        broadcast({ type: PacketType.CHAT, from: player.id, name: player.name || 'Unknown', message: msg });
      } else {
        player.send({ type: PacketType.ERROR, message: 'You are banned from chat.' });
      }
      break;
    }

    case PacketType.CREATE_VEHICLE: {
      const { name, job, position, rotation, steering } = data;
      if (!name || !job || !position) {
        player.send({ type: PacketType.ERROR, message: 'Missing vehicle data' });
        return;
      }
      if (vehicleManager.getVehicle(player.id)) {
        player.send({ type: PacketType.ERROR, message: 'You already own a vehicle' });
        return;
      }
      if (vehicleManager.findVehicleByPlayer(player.id)) {
        player.send({ type: PacketType.ERROR, message: 'You are already in a vehicle' });
        return;
      }
      const vehicle = vehicleManager.createVehicle(player.id, name, job, position, rotation || 0, steering || 0);
      if (!vehicle) {
        player.send({ type: PacketType.ERROR, message: 'Vehicle creation failed' });
        return;
      }
      player.name = name;
      player.job = job;
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
      }
      if (!vehicle.addPassenger(player.id, seatIndex)) {
        player.send({ type: PacketType.ERROR, message: 'Seat not available' });
        return;
      }
      player.vehicleId = vehicle.id;
      player.seatIndex = seatIndex;
      broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      break;
    }

    case PacketType.LEAVE_VEHICLE: {
      const vehicle = vehicleManager.findVehicleByPlayer(player.id);
      if (!vehicle) {
        player.send({ type: PacketType.ERROR, message: 'Not in a vehicle' });
        return;
      }
      const seat = vehicle.removePassenger(player.id);
      if (seat === -1) {
        player.send({ type: PacketType.ERROR, message: 'You are not in this vehicle' });
        return;
      }
      // ✅ تغییر: ماشین را حذف نکن، فقط صندلی را خالی کن
      broadcast({ type: PacketType.SEAT_UPDATE, vehicleId: vehicle.id, seats: vehicle.seats });
      player.vehicleId = null;
      player.seatIndex = null;
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
      broadcast({ type: PacketType.BAN_LIST, bans: banManager.getBanList() });
      break;
    }

    case PacketType.PING:
      player.send({ type: PacketType.PING, timestamp: Date.now() });
      break;

    default:
      player.send({ type: PacketType.ERROR, message: `Unknown type: ${type}` });
  }
}
