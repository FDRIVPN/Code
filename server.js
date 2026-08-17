import { WebSocketServer } from 'ws';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';
import config from './config.js';

// ============================================================
// Packet Types (هماهنگ کامل با کلاینت گودوت)
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
            'car', 'motorcycle', 'truck', 'bike',
            'boat', 'plane', 'helicopter', 'tank'
        ];
    }

    createVehicle(ownerId) {
        const id = this.nextVehicleId++;
        const position = {
            x: Math.random() * 5000 - 2500,
            y: Math.random() * 5000 - 2500,
            z: 0
        };
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
// نمونه‌های اصلی
// ============================================================
const wss = new WebSocketServer({ port: config.port || 8080 });
const vehicleManager = new VehicleManager();
const players = new Map();
const userMap = new Map();

// ============================================================
// توابع کمکی
// ============================================================
function broadcast(message) {
    const data = JSON.stringify(message);
    for (const player of players.values()) {
        // ✅ اصلاح: استفاده از عدد 1 به جای WebSocket.OPEN
        if (player.ws.readyState === 1) { // 1 = WebSocket.OPEN
            try {
                player.ws.send(data);
            } catch (e) {
                // خطای ارسال را نادیده بگیر
            }
        }
    }
}

function sendToPlayer(playerId, message) {
    const player = players.get(playerId);
    if (player && player.ws.readyState === 1) {
        try {
            player.ws.send(JSON.stringify(message));
        } catch (e) {
            // خطای ارسال را نادیده بگیر
        }
    }
}

// ============================================================
// مدیریت اتصالات WebSocket
// ============================================================
wss.on('connection', (ws) => {
    const player = {
        id: null,
        user_id: null,
        name: 'Unknown',
        job: 'بیکار',
        position: { x: 0, y: 0, z: 0 },
        rotation: 0,
        ws: ws,
        vehicleId: null,
        send: function(data) {
            if (this.ws.readyState === 1) {
                try {
                    this.ws.send(JSON.stringify(data));
                } catch (e) {}
            }
        },
        close: function(reason) {
            try {
                this.ws.close(1000, reason);
            } catch (e) {}
        }
    };

    // شناسه موقت تا زمانی که کلاینت SET_ID بفرستد
    const tempId = randomUUID();
    player.id = tempId;
    players.set(tempId, player);

    console.log('🔗 New connection received, waiting for SET_ID...');

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            const { type, id, user_id, name, job, position, rotation } = message;

            if (type === PacketType.SET_ID) {
                const clientId = id || user_id;
                if (!clientId) {
                    player.send({ type: PacketType.ERROR, message: 'Missing ID' });
                    return;
                }

                // بررسی بن بودن کاربر
                const isBanned = bans.some(b => b.id === clientId && (!b.expires || b.expires > Date.now()));
                if (isBanned) {
                    player.send({ type: PacketType.YOU_ARE_BANNED, message: 'You are banned from this server' });
                    player.close('Banned');
                    players.delete(tempId);
                    return;
                }

                // اگر کاربر قبلاً با این ID متصل است، اتصال قبلی را قطع کن
                const existingPlayer = userMap.get(clientId);
                if (existingPlayer) {
                    const oldPlayer = players.get(existingPlayer);
                    if (oldPlayer) {
                        try {
                            oldPlayer.send({ type: PacketType.ERROR, message: 'Replaced by new connection' });
                        } catch(e) {}
                        oldPlayer.close('Replaced by new connection');
                    }
                    players.delete(existingPlayer);
                }

                // انتقال داده‌های بازیکن از اتصال موقت به اتصال اصلی
                players.delete(tempId);
                player.id = clientId;
                player.user_id = clientId;
                if (name) player.name = name;
                if (job) player.job = job;
                if (position) player.position = position;
                if (rotation !== undefined) player.rotation = rotation;

                players.set(clientId, player);
                userMap.set(clientId, clientId);

                player.send({ type: PacketType.SET_ID, id: clientId });
                console.log(`✅ Client connected with ID: ${clientId}`);

                // ارسال وضعیت کامل به بازیکن جدید
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
                player.send(fullState);

                // اطلاع‌رسانی به سایر بازیکنان
                broadcast({
                    type: PacketType.UPDATE,
                    id: clientId,
                    user_id: clientId,
                    name: player.name,
                    job: player.job,
                    position: player.position,
                    rotation: player.rotation
                });

                return;
            }

            // پردازش پیام‌های بعد از احراز هویت
            if (!player.user_id) {
                player.send({ type: PacketType.ERROR, message: 'Not authenticated' });
                return;
            }

            handleMessage(player, message);

        } catch (e) {
            console.error('Message parse error:', e);
            try {
                player.send({ type: PacketType.ERROR, message: 'Invalid JSON' });
            } catch(err) {}
        }
    });

    ws.on('close', () => {
        const pid = player.id;
        if (pid) {
            players.delete(pid);
            if (player.user_id) {
                userMap.delete(player.user_id);
            }
            if (player.vehicleId) {
                const vehicle = vehicleManager.getVehicle(player.vehicleId);
                if (vehicle) {
                    vehicle.removeOccupant(player.id);
                }
            }
            broadcast({ type: PacketType.PLAYER_LEFT, id: pid });
            console.log(`❌ Client disconnected: ${pid}`);
        }
    });

    ws.on('error', (err) => {
        console.error('WebSocket error:', err);
    });
});

// ============================================================
// پردازش پیام‌های دریافتی
// ============================================================
function handleMessage(player, message) {
    const { type } = message;

    switch (type) {
        case PacketType.UPDATE:
            // به‌روزرسانی موقعیت بازیکن
            if (message.position) {
                player.position = message.position;
            }
            if (message.rotation !== undefined) {
                player.rotation = message.rotation;
            }
            if (message.name) {
                player.name = message.name;
            }
            if (message.job) {
                player.job = message.job;
            }

            // ارسال به‌روزرسانی به سایر بازیکنان
            broadcast({
                type: PacketType.UPDATE,
                id: player.id,
                user_id: player.user_id,
                name: player.name,
                job: player.job,
                position: player.position,
                rotation: player.rotation,
                anim: message.anim,
                speed: message.speed,
                is_grounded: message.is_grounded
            });
            break;

        case PacketType.CHAT:
            broadcast({
                type: PacketType.CHAT,
                sender_id: player.id,
                sender_name: player.name,
                message: message.message
            });
            break;

        case PacketType.PING:
            player.send({ type: PacketType.PONG });
            break;

        case PacketType.PONG:
            // کلاینت پونگ را دریافت می‌کند، کاری نمی‌کنیم
            break;

        case PacketType.CREATE_VEHICLE:
            const vehicle = vehicleManager.createVehicle(player.id);
            player.vehicleId = vehicle.id;
            vehicle.addOccupant(player.id, 0);
            broadcast({
                type: PacketType.VEHICLE_STATE,
                vehicles: vehicleManager.getAllVehicles()
            });
            break;

        case PacketType.JOIN_VEHICLE:
            const joinVid = message.vehicleId;
            const joinVehicle = vehicleManager.getVehicle(joinVid);
            if (joinVehicle) {
                const seatIndex = message.seatIndex || 0;
                joinVehicle.addOccupant(player.id, seatIndex);
                player.vehicleId = joinVid;
                broadcast({
                    type: PacketType.SEAT_UPDATE,
                    vehicleId: joinVid,
                    occupants: Array.from(joinVehicle.occupants.entries())
                });
            }
            break;

        case PacketType.LEAVE_VEHICLE:
            const leaveVid = player.vehicleId;
            if (leaveVid) {
                const leaveVehicle = vehicleManager.getVehicle(leaveVid);
                if (leaveVehicle) {
                    leaveVehicle.removeOccupant(player.id);
                }
                player.vehicleId = null;
                broadcast({
                    type: PacketType.SEAT_UPDATE,
                    vehicleId: leaveVid,
                    occupants: leaveVehicle ? Array.from(leaveVehicle.occupants.entries()) : []
                });
            }
            break;

        case PacketType.UPDATE_VEHICLE:
            if (message.vehicleId && message.position) {
                const updated = vehicleManager.updateVehicle(
                    message.vehicleId,
                    message.position,
                    message.rotation,
                    message.speed,
                    message.fuel
                );
                if (updated) {
                    broadcast({
                        type: PacketType.VEHICLE_STATE,
                        vehicles: vehicleManager.getAllVehicles()
                    });
                }
            }
            break;

        case PacketType.BAN_PLAYER:
            // فقط ادمین‌ها می‌توانند بن کنند (در اینجا ساده شده)
            if (player.job === 'ادمین') {
                const targetId = message.targetId;
                const duration = message.duration || 3600000; // 1 ساعت پیش‌فرض
                const reason = message.reason || 'No reason provided';
                const banEntry = {
                    id: targetId,
                    reason: reason,
                    expires: Date.now() + duration
                };
                bans.push(banEntry);
                fs.writeFileSync(banFilePath, JSON.stringify(bans));

                // قطع کردن بازیکن بن شده
                const targetPlayer = players.get(targetId);
                if (targetPlayer) {
                    targetPlayer.send({ type: PacketType.YOU_ARE_BANNED, message: `You are banned: ${reason}` });
                    targetPlayer.close('Banned');
                    players.delete(targetId);
                    userMap.delete(targetId);
                }
                broadcast({ type: PacketType.BAN_LIST, bans: bans });
            }
            break;

        case PacketType.UNBAN_PLAYER:
            if (player.job === 'ادمین') {
                const targetId = message.targetId;
                bans = bans.filter(b => b.id !== targetId);
                fs.writeFileSync(banFilePath, JSON.stringify(bans));
                broadcast({ type: PacketType.BAN_LIST, bans: bans });
            }
            break;

        case PacketType.BAN_LIST:
            if (player.job === 'ادمین') {
                player.send({ type: PacketType.BAN_LIST, bans: bans });
            }
            break;

        default:
            console.log(`⚠️ Unknown message type: ${type}`);
    }
}

// ============================================================
// ارسال وضعیت کامل به همه بازیکنان (هر ۵۰۰ms)
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

    for (const player of players.values()) {
        // ✅ اصلاح: استفاده از عدد 1 به جای WebSocket.OPEN
        if (player.ws.readyState === 1) {
            try {
                player.ws.send(JSON.stringify(fullState));
            } catch (e) {
                // خطا را نادیده بگیر
            }
        }
    }
}, 500);

// ============================================================
// به‌روزرسانی دوره‌ای وضعیت ماشین‌ها (هر ۱ ثانیه)
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
// Keep-alive (هر ۱۰ ثانیه)
// ============================================================
setInterval(() => {
    for (const player of players.values()) {
        // ✅ اصلاح: استفاده از عدد 1 به جای WebSocket.OPEN
        if (player.ws.readyState === 1) {
            try {
                player.ws.send(JSON.stringify({ type: PacketType.PING }));
            } catch (e) {
                // خطا را نادیده بگیر
            }
        }
    }
}, 10000);

// ============================================================
// مدیریت خاموش شدن
// ============================================================
process.on('SIGTERM', () => {
    console.log('Shutting down...');
    wss.close();
    process.exit(0);
});

console.log(`🚀 Server running on port ${config.port || 8080} | Mode: Waiting for player ID from client`);
console.log('🚀 Server is ready and waiting for connections!');
