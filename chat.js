class ChatManager {
    constructor() {
        this.messages = [];
        this.maxMessages = 100;
        this.privateChats = new Map(); // `${id1}-${id2}` -> [messages]
    }

    // پیام عمومی
    addPublicMessage(playerId, playerName, message) {
        const msg = {
            id: Date.now() + Math.random(),
            type: "public",
            playerId,
            playerName,
            message: message.trim(),
            timestamp: Date.now()
        };

        this.messages.push(msg);
        
        // حذف پیام‌های قدیمی
        if (this.messages.length > this.maxMessages) {
            this.messages.shift();
        }

        return msg;
    }

    // پیام خصوصی
    addPrivateMessage(fromId, fromName, toId, toName, message) {
        const msg = {
            id: Date.now() + Math.random(),
            type: "private",
            fromId,
            fromName,
            toId,
            toName,
            message: message.trim(),
            timestamp: Date.now()
        };

        // کلید یکتا برای چت خصوصی (همیشه ترتیب یکسان)
        const key = [fromId, toId].sort().join("-");
        
        if (!this.privateChats.has(key)) {
            this.privateChats.set(key, []);
        }

        const chat = this.privateChats.get(key);
        chat.push(msg);

        // محدود کردن تعداد پیام‌های خصوصی
        if (chat.length > 50) {
            chat.shift();
        }

        return msg;
    }

    // پیام گروهی (اتاق)
    addRoomMessage(roomId, playerId, playerName, message) {
        const msg = {
            id: Date.now() + Math.random(),
            type: "room",
            roomId,
            playerId,
            playerName,
            message: message.trim(),
            timestamp: Date.now()
        };

        // ذخیره در اتاق‌ها (با کلید مخصوص)
        const key = `room_${roomId}`;
        if (!this.privateChats.has(key)) {
            this.privateChats.set(key, []);
        }

        const chat = this.privateChats.get(key);
        chat.push(msg);

        if (chat.length > 50) {
            chat.shift();
        }

        return msg;
    }

    // گرفتن تاریخچه چت عمومی
    getPublicHistory(limit = 20) {
        return this.messages.slice(-limit);
    }

    // گرفتن تاریخچه چت خصوصی بین دو نفر
    getPrivateHistory(id1, id2, limit = 20) {
        const key = [id1, id2].sort().join("-");
        const chat = this.privateChats.get(key) || [];
        return chat.slice(-limit);
    }

    // گرفتن تاریخچه چت اتاق
    getRoomHistory(roomId, limit = 20) {
        const key = `room_${roomId}`;
        const chat = this.privateChats.get(key) || [];
        return chat.slice(-limit);
    }

    // پاک کردن تاریخچه
    clearHistory() {
        this.messages = [];
        this.privateChats.clear();
    }

    // تعداد پیام‌ها
    getStats() {
        return {
            publicMessages: this.messages.length,
            privateChats: this.privateChats.size,
            totalPrivateMessages: Array.from(this.privateChats.values())
                .reduce((sum, chat) => sum + chat.length, 0)
        };
    }
}

export default ChatManager;
