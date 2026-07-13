import { WebSocketServer } from "ws";
import { randomUUID } from "crypto";

const PORT = process.env.PORT || 8080;

const wss = new WebSocketServer({
    port: PORT
});

const players = new Map();

console.log(`🚀 Server started on port ${PORT}`);

wss.on("connection", (ws) => {

    const id = randomUUID();

    players.set(id, {
        id,
        name: "Player",
        job: "None",
        x: 0,
        y: 0,
        z: 0,
        rot: 0,
        animation: "idle"
    });

    console.log(`Player Connected : ${id}`);

    ws.send(JSON.stringify({
        type: "welcome",
        id
    }));

    broadcastPlayers();

    ws.on("message", (message) => {

        try{

            const data = JSON.parse(message);

            const player = players.get(id);

            if(!player) return;

            switch(data.type){

                case "update":

                    player.x = data.x;
                    player.y = data.y;
                    player.z = data.z;
                    player.rot = data.rot;
                    player.animation = data.animation;

                    broadcastPlayers();

                    break;

                case "set_name":

                    player.name = data.name;

                    broadcastPlayers();

                    break;

                case "set_job":

                    player.job = data.job;

                    broadcastPlayers();

                    break;

                case "chat":

                    broadcast({
                        type:"chat",
                        id,
                        name:player.name,
                        message:data.message
                    });

                    break;

                case "ping":

                    ws.send(JSON.stringify({
                        type:"pong"
                    }));

                    break;

            }

        }catch(err){

            console.log(err);

        }

    });

    ws.on("close",()=>{

        console.log(`Player Left : ${id}`);

        players.delete(id);

        broadcastPlayers();

    });

});

function broadcastPlayers(){

    const packet = {

        type:"players",

        players:Array.from(players.values())

    };

    broadcast(packet);

}

function broadcast(packet){

    const json = JSON.stringify(packet);

    wss.clients.forEach(client=>{

        if(client.readyState===1){

            client.send(json);

        }

    });

}
