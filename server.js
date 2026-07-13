import { WebSocketServer } from "ws";
import http from "http";
import Player from "./Player.js";
import RoomManager from "./RoomManager.js";
import ChatManager from "./Chat.js";
import { Packets, parsePacket } from "./Packet.js";
import config from "./config.js";

const PORT = process.env.PORT || 8080;

// ایجاد HTTP Server
const server = http.createServer((req, res) => {
    // پاسخ به درخواست‌های HTTP برای Railway
    if (req.url === '/health' || req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
            status: 'online', 
            players: players.size,
            rooms: roomManager.rooms.size,
            timestamp: Date.now()
        }));
        return;
    }
    
    res.writeHead(404);
    res.end('Not Found');
});

// اتصال WebSocket به HTTP Server
const wss = new WebSocketServer({ 
    server,
    maxPayload: config.ws.maxPayloadSize 
});

const players = new Map();
const roomManager = new RoomManager();
const chatManager = new ChatManager();

console.log(`🚀 Server started on port ${PORT}`);
console.log(`🌍 Environment: ${config.environment}`);

// بقیه کدهای WebSocket مثل قبل...
wss.on("connection", (ws) => {
    const player = new Player();
    players.set(player.id, { ws, player });

    console.log(`✅ Player Connected: ${player.id}`);

    ws.send(JSON.stringify(Packets.welcome(player.id, getPlayersList())));
    sendRoomList(ws);
    ws.send(JSON.stringify(Packets.history(chatManager.getPublicHistory())));

    ws.on("message", (message) => {
        try {
            const packet = parsePacket(message);
            const playerData = players.get(player.id);
            
            if (!playerData) return;

            const { player: currentPlayer, ws: clientWs } = playerData;

            switch (packet.type) {
                case "update":
                    currentPlayer.updatePosition(
                        packet.x, packet.y, packet.z, 
                        packet.rot, packet.animation
                    );
                    broadcastPlayers();
                    break;

                case "set_name":
                    if (currentPlayer.setName(packet.name)) {
                        broadcastPlayers();
                    } else {
                        ws.send(JSON.stringify(Packets.error("Invalid name")));
                    }
                    break;

                case "set_job":
                    if (currentPlayer.setJob(packet.job)) {
                        broadcastPlayers();
                    } else {
                        ws.send(JSON.stringify(Packets.error("Invalid job")));
                    }
                    break;

                case "chat":
                    if (packet.message && packet.message.trim()) {
                        const msg = chatManager.addPublicMessage(
                            player.id, 
                            currentPlayer.name, 
                            packet.message
                        );
                        
                        broadcast(JSON.stringify(Packets.chatMessage(
                            player.id,
                            currentPlayer.name,
                            msg.message
                        )));
                    }
                    break;

                case "private_chat":
                    if (packet.toId && packet.message) {
                        const msg = chatManager.addPrivateMessage(
                            player.id,
                            currentPlayer.name,
                            packet.toId,
                            packet.toName || "Unknown",
                            packet.message
                        );
                        
                        ws.send(JSON.stringify(Packets.privateMessage(
                            player.id,
                            currentPlayer.name,
                            msg.message
                        )));
                        
                        const target = players.get(packet.toId);
                        if (target && target.ws.readyState === 1) {
                            target.ws.send(JSON.stringify(Packets.privateMessage(
                                player.id,
                                currentPlayer.name,
                                msg.message
                            )));
                        }
                    }
                    break;

                case "room_chat":
                    const roomId = roomManager.findPlayerRoom(player.id);
                    if (roomId && packet.message) {
                        const msg = chatManager.addRoomMessage(
                            roomId,
                            player.id,
                            currentPlayer.name,
                            packet.message
                        );
                        
                        broadcastToRoom(roomId, JSON.stringify(Packets.roomMessage(
                            roomId,
                            player.id,
                            currentPlayer.name,
                            msg.message
                        )));
                    } else {
                        ws.send(JSON.stringify(Packets.error("You're not in a room")));
                    }
                    break;

                case "ping":
                    ws.send(JSON.stringify(Packets.pong()));
                    break;

                case "create_room":
                    const createResult = roomManager.createRoom(
                        player.id,
                        packet.name || "New Room",
                        packet.maxPlayers || config.maxPlayersPerRoom,
                        packet.private || false,
                        packet.password || null
                    );
                    
                    if (createResult.success) {
                        roomManager.joinRoom(createResult.roomId, currentPlayer);
                        broadcastRooms();
                        ws.send(JSON.stringify(Packets.roomCreated(
                            createResult.roomId,
                            createResult.room
                        )));
                    } else {
                        ws.send(JSON.stringify(Packets.error(createResult.message)));
                    }
                    break;

                case "join_room":
                    const joinResult = roomManager.joinRoom(
                        packet.roomId,
                        currentPlayer,
                        packet.password || null
                    );
                    
                    if (joinResult.success) {
                        broadcastRooms();
                        ws.send(JSON.stringify(Packets.roomJoined(
                            packet.roomId,
                            roomManager.getRoom(packet.roomId)
                        )));
                        
                        ws.send(JSON.stringify(Packets.history(
                            chatManager.getRoomHistory(packet.roomId)
                        )));
                    } else {
                        ws.send(JSON.stringify(Packets.error(joinResult.message)));
                    }
                    break;

                case "leave_room":
                    const currentRoomId = roomManager.findPlayerRoom(player.id);
                    if (currentRoomId) {
                        roomManager.leaveRoom(currentRoomId, player.id);
                        broadcastRooms();
                        ws.send(JSON.stringify(Packets.roomLeft(currentRoomId)));
                    }
                    break;

                case "start_game":
                    const startRoomId = roomManager.findPlayerRoom(player.id);
                    if (startRoomId) {
                        const startResult = roomManager.startGame(startRoomId, player.id);
                        if (startResult.success) {
                            broadcastToRoom(startRoomId, JSON.stringify(
                                Packets.gameStarted(startRoomId)
                            ));
                        } else {
                            ws.send(JSON.stringify(Packets.error(startResult.message)));
                        }
                    } else {
                        ws.send(JSON.stringify(Packets.error("You're not in a room")));
                    }
                    break;

                case "list_rooms":
                    sendRoomList(ws);
                    break;

                case "request_history":
                    const historyType = packet.historyType || "public";
                    let history = [];
                    
                    if (historyType === "public") {
                        history = chatManager.getPublicHistory();
                    } else if (historyType === "private" && packet.withId) {
                        history = chatManager.getPrivateHistory(
                            player.id, 
                            packet.withId
                        );
                    } else if (historyType === "room") {
                        const playerRoomId = roomManager.findPlayerRoom(player.id);
                        if (playerRoomId) {
                            history = chatManager.getRoomHistory(playerRoomId);
                        }
                    }
                    
                    ws.send(JSON.stringify(Packets.history(history)));
                    break;

                default:
                    ws.send(JSON.stringify(Packets.error(`Unknown packet type: ${packet.type}`)));
            }
        } catch (err) {
            console.log("Error:", err.message);
            ws.send(JSON.stringify(Packets.error(err.message)));
        }
    });

    ws.on("close", () => {
        console.log(`❌ Player Left: ${player.id}`);
        
        const roomId = roomManager.findPlayerRoom(player.id);
        if (roomId) {
            roomManager.leaveRoom(roomId, player.id);
            broadcastRooms();
        }
        
        players.delete(player.id);
        broadcastPlayers();
    });
});

// --- توابع کمکی ---

function getPlayersList() {
    return Array.from(players.values()).map(({ player }) => player.toJSON());
}

function broadcastPlayers() {
    broadcast(JSON.stringify(Packets.players(getPlayersList())));
}

function broadcastRooms() {
    broadcast(JSON.stringify(Packets.rooms(roomManager.getRoomsList())));
}

function sendRoomList(ws) {
    ws.send(JSON.stringify(Packets.rooms(roomManager.getRoomsList())));
}

function broadcastToRoom(roomId, packetString) {
    const room = roomManager.rooms?.get(roomId);
    if (!room) return;

    room.players.forEach((player) => {
        const playerData = players.get(player.id);
        if (playerData && playerData.ws.readyState === 1) {
            playerData.ws.send(packetString);
        }
    });
}

function broadcast(packetString) {
    wss.clients.forEach((client) => {
        if (client.readyState === 1) {
            client.send(packetString);
        }
    });
}

// Health check برای Railway
setInterval(() => {
    console.log(`💚 Health check: ${players.size} players, ${roomManager.rooms.size} rooms`);
}, 30000);

// گوش دادن به درخواست‌های HTTP و WebSocket
server.listen(PORT, () => {
    console.log(`✅ HTTP & WebSocket server running on port ${PORT}`);
});
