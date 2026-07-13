// انواع پکت‌ها
export const PacketType = {
    // ورودی از کلاینت
    UPDATE: "update",
    SET_NAME: "set_name",
    SET_JOB: "set_job",
    CHAT: "chat",
    PING: "ping",
    CREATE_ROOM: "create_room",
    JOIN_ROOM: "join_room",
    LEAVE_ROOM: "leave_room",
    START_GAME: "start_game",
    LIST_ROOMS: "list_rooms",
    PRIVATE_CHAT: "private_chat",
    ROOM_CHAT: "room_chat",
    REQUEST_HISTORY: "request_history",

    // خروجی از سرور
    WELCOME: "welcome",
    PLAYERS: "players",
    ROOMS: "rooms",
    ROOM_CREATED: "room_created",
    ROOM_JOINED: "room_joined",
    ROOM_LEFT: "room_left",
    GAME_STARTED: "game_started",
    CHAT_MESSAGE: "chat_message",
    PRIVATE_MESSAGE: "private_message",
    ROOM_MESSAGE: "room_message",
    HISTORY: "history",
    PONG: "pong",
    ERROR: "error"
};

// ساخت پکت
export function createPacket(type, data = {}) {
    return {
        type,
        ...data,
        timestamp: Date.now()
    };
}

// اعتبارسنجی پکت
export function validatePacket(packet) {
    if (!packet || typeof packet !== 'object') {
        return { valid: false, error: "Invalid packet" };
    }

    if (!packet.type || typeof packet.type !== 'string') {
        return { valid: false, error: "Missing packet type" };
    }

    // بررسی نوع پکت
    const validTypes = Object.values(PacketType);
    if (!validTypes.includes(packet.type)) {
        return { valid: false, error: `Unknown packet type: ${packet.type}` };
    }

    return { valid: true };
}

// پکت‌های آماده
export const Packets = {
    welcome: (id, players) => createPacket(PacketType.WELCOME, { id, players }),
    players: (players) => createPacket(PacketType.PLAYERS, { players }),
    rooms: (rooms) => createPacket(PacketType.ROOMS, { rooms }),
    roomCreated: (roomId, room) => createPacket(PacketType.ROOM_CREATED, { roomId, room }),
    roomJoined: (roomId, room) => createPacket(PacketType.ROOM_JOINED, { roomId, room }),
    roomLeft: (roomId) => createPacket(PacketType.ROOM_LEFT, { roomId }),
    gameStarted: (roomId) => createPacket(PacketType.GAME_STARTED, { roomId }),
    chatMessage: (id, name, message) => createPacket(PacketType.CHAT_MESSAGE, { id, name, message }),
    privateMessage: (fromId, fromName, message) => createPacket(PacketType.PRIVATE_MESSAGE, { fromId, fromName, message }),
    roomMessage: (roomId, playerId, playerName, message) => createPacket(PacketType.ROOM_MESSAGE, { roomId, playerId, playerName, message }),
    history: (messages) => createPacket(PacketType.HISTORY, { messages }),
    pong: () => createPacket(PacketType.PONG),
    error: (message) => createPacket(PacketType.ERROR, { message })
};

// Parse کردن پکت از JSON
export function parsePacket(data) {
    try {
        const packet = JSON.parse(data);
        const validation = validatePacket(packet);
        
        if (!validation.valid) {
            throw new Error(validation.error);
        }
        
        return packet;
    } catch (error) {
        throw new Error(`Failed to parse packet: ${error.message}`);
    }
}

// تبدیل پکت به JSON
export function stringifyPacket(packet) {
    try {
        return JSON.stringify(packet);
    } catch (error) {
        throw new Error(`Failed to stringify packet: ${error.message}`);
    }
}
