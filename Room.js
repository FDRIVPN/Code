import { randomUUID } from "crypto";

class Room {
    constructor(creatorId, name = "New Room", maxPlayers = 10) {
        this.id = randomUUID();
        this.name = name;
        this.creatorId = creatorId;
        this.players = new Map(); // id -> Player object
        this.maxPlayers = maxPlayers;
        this.gameState = "waiting"; // waiting, playing, finished
        this.createdAt = Date.now();
        this.private = false;
        this.password = null;
    }

    // اضافه کردن بازیکن به اتاق
    addPlayer(player) {
        if (this.players.size >= this.maxPlayers) {
            return { success: false, message: "Room is full" };
        }
        
        if (this.players.has(player.id)) {
            return { success: false, message: "Player already in room" };
        }

        this.players.set(player.id, player);
        return { success: true, message: "Added to room" };
    }

    // حذف بازیکن از اتاق
    removePlayer(playerId) {
        if (!this.players.has(playerId)) {
            return { success: false, message: "Player not in room" };
        }

        this.players.delete(playerId);
        
        // اگر سازنده اتاق خارج شد، اتاق را حذف کن یا به نفر بعدی بده
        if (playerId === this.creatorId && this.players.size > 0) {
            this.creatorId = this.players.keys().next().value;
        }

        return { success: true, message: "Removed from room" };
    }

    // شروع بازی
    startGame() {
        if (this.players.size < 2) {
            return { success: false, message: "Not enough players (min 2)" };
        }
        
        this.gameState = "playing";
        return { success: true, message: "Game started" };
    }

    // گرفتن لیست بازیکن‌های اتاق
    getPlayersList() {
        return Array.from(this.players.values()).map(p => p.toJSON());
    }

    // اطلاعات کامل اتاق برای ارسال
    toJSON() {
        return {
            id: this.id,
            name: this.name,
            creatorId: this.creatorId,
            playerCount: this.players.size,
            maxPlayers: this.maxPlayers,
            gameState: this.gameState,
            private: this.private,
            players: this.getPlayersList()
        };
    }

    // بررسی اینکه اتاق پر شده
    isFull() {
        return this.players.size >= this.maxPlayers;
    }

    // بررسی اینکه اتاق خالی است
    isEmpty() {
        return this.players.size === 0;
    }
}

export default Room;
