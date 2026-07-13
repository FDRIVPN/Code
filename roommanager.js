import Room from "./Room.js";

class RoomManager {
    constructor() {
        this.rooms = new Map(); // roomId -> Room object
        this.maxRooms = 100;
    }

    // ساخت اتاق جدید
    createRoom(creatorId, name, maxPlayers = 10, isPrivate = false, password = null) {
        if (this.rooms.size >= this.maxRooms) {
            return { success: false, message: "Maximum rooms reached" };
        }

        const room = new Room(creatorId, name, maxPlayers);
        room.private = isPrivate;
        room.password = password;
        
        this.rooms.set(room.id, room);
        return { success: true, roomId: room.id, room: room.toJSON() };
    }

    // اضافه کردن بازیکن به اتاق
    joinRoom(roomId, player, password = null) {
        const room = this.rooms.get(roomId);
        if (!room) {
            return { success: false, message: "Room not found" };
        }

        // بررسی رمز اتاق خصوصی
        if (room.private && room.password !== password) {
            return { success: false, message: "Wrong password" };
        }

        return room.addPlayer(player);
    }

    // خروج از اتاق
    leaveRoom(roomId, playerId) {
        const room = this.rooms.get(roomId);
        if (!room) {
            return { success: false, message: "Room not found" };
        }

        const result = room.removePlayer(playerId);
        
        // اگر اتاق خالی شد، حذفش کن
        if (room.isEmpty()) {
            this.rooms.delete(roomId);
        }

        return result;
    }

    // شروع بازی در اتاق
    startGame(roomId, playerId) {
        const room = this.rooms.get(roomId);
        if (!room) {
            return { success: false, message: "Room not found" };
        }

        // فقط سازنده اتاق می‌تواند بازی را شروع کند
        if (room.creatorId !== playerId) {
            return { success: false, message: "Only the creator can start the game" };
        }

        return room.startGame();
    }

    // گرفتن لیست تمام اتاق‌ها
    getRoomsList() {
        return Array.from(this.rooms.values())
            .filter(room => !room.private) // اتاق‌های عمومی را نشان بده
            .map(room => room.toJSON());
    }

    // گرفتن اطلاعات یک اتاق
    getRoom(roomId) {
        const room = this.rooms.get(roomId);
        return room ? room.toJSON() : null;
    }

    // پیدا کردن اتاقی که بازیکن در آن است
    findPlayerRoom(playerId) {
        for (const [roomId, room] of this.rooms) {
            if (room.players.has(playerId)) {
                return roomId;
            }
        }
        return null;
    }

    // حذف اتاق‌های قدیمی (اختیاری)
    cleanupOldRooms(maxAge = 3600000) { // 1 ساعت
        const now = Date.now();
        for (const [roomId, room] of this.rooms) {
            if (room.isEmpty() && (now - room.createdAt > maxAge)) {
                this.rooms.delete(roomId);
            }
        }
    }
}

export default RoomManager;
