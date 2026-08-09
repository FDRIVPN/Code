import { WebSocketServer } from 'ws';
import { randomUUID } from 'crypto';
import fs from 'fs';

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
    PONG: 'pong',           // 🔥 اضافه شد
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
# 🧩 کلاس Player (با user_id)
// ============================================================
class Player {
    constructor(ws) {
        this.id = randomUUID();           // شناسه اتصال (موقتی)
        this.user_id = null;              // 🔥 شناسه دائمی کاربر (از کلاینت)
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
            this.ws.send(JSON.stringify(data));
        }
    }

    close(reason = '') {
        if (this.ws && this.ws.readyState === 1) {
            this.ws.close(1000, reason);
        }
    }
}

// ============================================================
# 🚗 کلاس Vehicle
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
        this.seats = [null, null, null, null]; // 4 صندلی (index 0-3)
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
# 🚗 کلاس VehicleManager
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
        for (const [id, vehicle] of this.vehicles) {
            result.push(vehicle.getState());
        }
        return result;
    }
}

// ============================================================
# 🚫 کلاس BanManager
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
# 💬 کلاس Chat
// ============================================================
class Chat {
    constructor(banManager) {
        this.banManager = banManager;
    }

    processMessage(playerId, message) {
        if (this.banManager.isBanned(playerId)) return null;
        return message.substring(0, 200);
    }
}

// ============================================================
# 🌐 سرور اصلی
// ============================================================
const wss = new WebSocketServer({ port: config?.port || 8080 });
console.log(`🚀 Server running on port ${config?.port || 8080}`);

const players = new Map();
const vehicleManager = new VehicleManager();
const banManager = new BanManager();
const chat = new Chat(banManager);

// ============================================================
# 📊 لاگ دوره‌ای (هر ۵۰۰ms)
// ============================================================
setInterval(() => {
    const playerCount = players.size;
    const vehicleCount = vehicleManager.vehicles.size;
    if (playerCount === 0 && vehicleCount === 0) return;
    console.log(`\n📊 [${new Date().toISOString()}] STATUS UPDATE`);
    console.log(`   Players online: ${playerCount}`);
    console.log(`   Vehicles: ${vehicleCount}`);
    if (playerCount > 0) {
        console.log(`   Players:`);
        for (const [id, player] of players) {
            console.log(`     - ${id.substring(0, 8)}... | User: ${player.user_id || 'N/A'} | Name: "${player.name}" | Pos: (${player.position.x.toFixed(1)}, ${player.position.y.toFixed(1)}, ${player.position.z.toFixed(1)})`);
        }
    }
    if (vehicleCount > 0) {
        console.log(`   Vehicles:`);
        for (const [id, vehicle] of vehicleManager.vehicles) {
            const seats = vehicle.seats.map(s => s ? s.substring(0, 8)+'...' : 'Empty');
            console.log(`     - ${id.substring(0, 8)}... | Owner: ${vehicle.ownerId.substring(0, 8)}... | CarDB: ${vehicle.car_db_id || 'N/A'} | Seats: [${seats.join(', ')}]`);
        }
    }
    console.log(`─────────────────────────────────────────────`);
}, 500);

// ============================================================
# 📤 توابع ارسال
// ============================================================
function broadcast(data, excludeId = null) {
    const message = JSON.stringify(data);
    for (const [id, player] of players) {
        if (id !== excludeId && player.ws.readyState === 1 && !player.isBanned) {
            player.ws.send(message);
        }
    }
}

function broadcastToOthers(senderId, data) {
    broadcast(data, senderId);
}

function sendFullState(player) {
    const allPlayers = [];
    for (const [id, p] of players) {
        if (p.id === player.id) continue;
        allPlayers.push({
            id: p.id,                         // شناسه اتصال
            user_id: p.user_id || p.id,       // 🔥 شناسه دائمی
            name: p.name || 'Unknown',
            job: p.job || '',
            position: p.position,
            rotation: p.rotation
        });
    }

    player.send({
        type: PacketType.FULL_STATE,
        players: allPlayers,
        vehicles: vehicleManager.getAllVehicles(),
        bans: banManager.getBanList()
    });

    console.log(`📦 Sent full_state to ${player.name} (${allPlayers.length} other players)`);
}

// ============================================================
# 📨 پردازش پیام‌ها
// ============================================================
function handleMessage(player, data) {
    if (player.isBanned) {
        player.send({ type: PacketType.ERROR, message: 'You are banned.' });
        return;
    }

    const { type } = data;

    switch (type) {
        // ============================================================
        // 📤 به‌روزرسانی موقعیت (با user_id)
        // ============================================================
        case PacketType.UPDATE: {
            // 🔥 دریافت و ذخیره user_id
            if (data.user_id) {
                player.user_id = data.user_id;
            }

            // دریافت name و job
            if (data.name !== undefined) {
                player.name = data.name;
            }
            if (data.job !== undefined) {
                player.job = data.job;
            }

            // به‌روزرسانی موقعیت
            if (data.position) {
                if (typeof data.position.x === 'number' &&
                    typeof data.position.y === 'number' &&
                    typeof data.position.z === 'number') {
                    player.position = {
                        x: data.position.x,
                        y: data.position.y,
                        z: data.position.z
                    };
                } else {
                    player.send({
                        type: PacketType.ERROR,
                        message: 'Invalid position format (need x, y, z)'
                    });
                    return;
                }
            }

            if (data.rotation !== undefined) {
                player.rotation = data.rotation;
            }

            player.lastUpdate = Date.now();

            // 🔥 ارسال به سایر بازیکنان (همراه با user_id)
            broadcast({
                type: PacketType.UPDATE,
                id: player.id,                        // شناسه اتصال
                user_id: player.user_id || player.id, // 🔥 شناسه دائمی
                name: player.name,
                job: player.job,
                position: player.position,
                rotation: player.rotation,
                anim: data.anim || 0,
                speed: data.speed || 0,
                is_grounded: data.is_grounded !== undefined ? data.is_grounded : true
            }, player.id);

            console.log(`📤 [${new Date().toISOString()}] ${player.name} (${player.id.substring(0, 8)}...) -> (${player.position.x.toFixed(1)}, ${player.position.y.toFixed(1)}, ${player.position.z.toFixed(1)})`);
            break;
        }

        // ============================================================
        // 🏓 پینگ (پاسخ با pong) 🔥 رفع شد
        // ============================================================
        case PacketType.PING: {
            player.send({
                type: PacketType.PONG,  // 🔥 به جای PING
                timestamp: Date.now()
            });
            break;
        }

        // ============================================================
        // 💬 چت
        // ============================================================
        case PacketType.CHAT: {
            const msg = chat.processMessage(player.id, data.message);
            if (msg !== null) {
                console.log(`💬 [${new Date().toISOString()}] ${player.name || 'Unknown'} (${player.id.substring(0, 8)}...): ${msg}`);
                broadcast({
                    type: PacketType.CHAT,
                    from: player.id,
                    name: player.name || 'Unknown',
                    message: msg
                });
            } else {
                player.send({
                    type: PacketType.ERROR,
                    message: 'You are banned from chat.'
                });
            }
            break;
        }

        // ============================================================
        // 🚗 ایجاد ماشین
        // ============================================================
        case PacketType.CREATE_VEHICLE: {
            const { name, job, position, rotation, steering, car_db_id } = data;
            if (!name || !job || !position) {
                player.send({ type: PacketType.ERROR, message: 'Missing vehicle data' });
                return;
            }
            if (typeof position.x !== 'number' || typeof position.y !== 'number' || typeof position.z !== 'number') {
                player.send({ type: PacketType.ERROR, message: 'Position must have x, y, z' });
                return;
            }

            const vehicle = vehicleManager.createVehicle(
                player.id, name, job, position, rotation || 0, steering || 0, car_db_id || null
            );

            if (!vehicle) {
                player.send({ type: PacketType.ERROR, message: 'Vehicle creation failed' });
                return;
            }

            player.name = name;
            player.job = job;

            console.log(`🚗 [${new Date().toISOString()}] Vehicle created by ${player.id.substring(0, 8)}... (ID: ${vehicle.id.substring(0, 8)}..., CarDB: ${vehicle.car_db_id})`);

            const stateMsg = {
                type: PacketType.VEHICLE_STATE,
                vehicle: vehicle.getState()
            };
            player.send(stateMsg);
            broadcast(stateMsg, player.id);
            break;
        }

        // ============================================================
        // 🚗 سوار شدن به ماشین
        // ============================================================
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

            console.log(`🚗 [${new Date().toISOString()}] ${player.id.substring(0, 8)}... joined vehicle ${vehicle.id.substring(0, 8)}... (seat ${seatIndex})`);

            const seatMsg = {
                type: PacketType.SEAT_UPDATE,
                vehicleId: vehicle.id,
                seats: vehicle.seats
            };
            broadcast(seatMsg);
            break;
        }

        // ============================================================
        // 🚗 پیاده شدن از ماشین
        // ============================================================
        case PacketType.LEAVE_VEHICLE: {
            const vehicle = vehicleManager.findVehicleByPlayer(player.id);
            if (!vehicle) {
                player.send({ type: PacketType.ERROR, message: 'Not in a vehicle' });
                return;
            }

            if (player.id === vehicle.ownerId) {
                vehicleManager.removeVehicle(vehicle.id);
                console.log(`🚗 [${new Date().toISOString()}] Vehicle ${vehicle.id.substring(0, 8)}... removed (owner left)`);
                const removedMsg = {
                    type: PacketType.VEHICLE_REMOVED,
                    vehicleId: vehicle.id
                };
                player.send(removedMsg);
                broadcast(removedMsg, player.id);
            } else {
                const seat = vehicle.removePassenger(player.id);
                if (seat === -1) {
                    player.send({ type: PacketType.ERROR, message: 'You are not in this vehicle' });
                    return;
                }
                console.log(`🚗 [${new Date().toISOString()}] ${player.id.substring(0, 8)}... left vehicle (seat ${seat})`);
                const seatMsg = {
                    type: PacketType.SEAT_UPDATE,
                    vehicleId: vehicle.id,
                    seats: vehicle.seats
                };
                broadcast(seatMsg);
            }

            player.vehicleId = null;
            player.seatIndex = null;
            break;
        }

        // ============================================================
        // 🚗 به‌روزرسانی ماشین
        // ============================================================
        case PacketType.UPDATE_VEHICLE: {
            const vehicles = vehicleManager.findVehiclesByOwner(player.id);
            if (vehicles.length === 0) {
                player.send({ type: PacketType.ERROR, message: 'You don\'t own a vehicle' });
                return;
            }

            const vehicle = vehicles[0];
            const { position, rotation, steering } = data;

            if (position) {
                if (typeof position.x !== 'number' || typeof position.y !== 'number' || typeof position.z !== 'number') {
                    player.send({ type: PacketType.ERROR, message: 'Position must have x, y, z' });
                    return;
                }
                vehicle.updateState(position, rotation, steering);
            } else {
                vehicle.updateState(null, rotation, steering);
            }

            const stateMsg = {
                type: PacketType.VEHICLE_STATE,
                vehicle: vehicle.getState()
            };
            player.send(stateMsg);
            broadcast(stateMsg, player.id);
            break;
        }

        // ============================================================
        // 🚫 مدیریت بن
        // ============================================================
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

            console.log(`🚫 [${new Date().toISOString()}] ${player.id.substring(0, 8)}... banned ${targetId.substring(0, 8)}...`);
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
            console.log(`✅ [${new Date().toISOString()}] ${player.id.substring(0, 8)}... unbanned ${targetId.substring(0, 8)}...`);
            broadcast({ type: PacketType.BAN_LIST, bans: banManager.getBanList() });
            break;
        }

        default: {
            console.log(`⚠️ [${new Date().toISOString()}] Unknown message type from ${player.id.substring(0, 8)}...: ${type}`);
            player.send({ type: PacketType.ERROR, message: `Unknown type: ${type}` });
        }
    }
}

// ============================================================
# 🔗 مدیریت اتصالات
// ============================================================
wss.on('connection', (ws) => {
    const player = new Player(ws);
    players.set(player.id, player);

    // بررسی بن
    if (banManager.isBanned(player.id)) {
        player.isBanned = true;
        player.send({ type: PacketType.YOU_ARE_BANNED, message: 'شما بن شدهاید.' });
        player.close('Banned');
        players.delete(player.id);
        console.log(`🚫 Player banned: ${player.id}`);
        return;
    }

    console.log(`✅ [${new Date().toISOString()}] Player connected: ${player.id.substring(0, 8)}...`);

    // ارسال شناسه اتصال
    player.send({ type: PacketType.SET_ID, id: player.id });

    // ارسال وضعیت کامل (با user_id)
    sendFullState(player);

    // ============================================================
    // 📨 دریافت پیام
    // ============================================================
    ws.on('message', (raw) => {
        try {
            const data = JSON.parse(raw);
            handleMessage(player, data);
        } catch (err) {
            console.log(`❌ Invalid JSON from ${player.id.substring(0, 8)}...: ${err.message}`);
            player.send({ type: PacketType.ERROR, message: 'Invalid JSON' });
        }
    });

    // ============================================================
    // ❌ قطع اتصال
    // ============================================================
    ws.on('close', () => {
        // بررسی ماشین
        const vehicle = vehicleManager.findVehicleByPlayer(player.id);
        if (vehicle) {
            if (player.id === vehicle.ownerId) {
                vehicleManager.removeVehicle(vehicle.id);
                console.log(`🚗 [${new Date().toISOString()}] Vehicle ${vehicle.id.substring(0, 8)}... removed (owner left)`);
                broadcast({ type: PacketType.VEHICLE_REMOVED, vehicleId: vehicle.id });
            } else {
                const seat = vehicle.removePassenger(player.id);
                if (seat !== -1) {
                    console.log(`🚗 [${new Date().toISOString()}] Passenger ${player.id.substring(0, 8)}... left vehicle (seat ${seat})`);
                    broadcast({
                        type: PacketType.SEAT_UPDATE,
                        vehicleId: vehicle.id,
                        seats: vehicle.seats
                    });
                }
            }
        }

        // حذف بازیکن
        players.delete(player.id);

        // 🔥 ارسال PLAYER_LEFT با user_id
        broadcast({
            type: PacketType.PLAYER_LEFT,
            id: player.user_id || player.id   // 🔥 ارسال user_id
        });

        console.log(`❌ [${new Date().toISOString()}] Player disconnected: ${player.id.substring(0, 8)}... (${player.name})`);
    });
});

// ============================================================
# 🧹 پاک‌سازی دوره‌ای
// ============================================================
setInterval(() => {
    const now = Date.now();
    const timeout = 60000; // ۶۰ ثانیه
    for (const [id, player] of players) {
        if (player.ws.readyState !== 1) {
            players.delete(id);
            console.log(`🧹 Cleaned up disconnected player: ${id}`);
        }
    }
}, 60000);

console.log(`🚀 Server is ready!`);
