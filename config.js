export default {
  port: process.env.PORT || 8080,
  maxPlayers: 50,
  world: { width: 10000, height: 10000 },
  pingInterval: 5000,
  vehicle: { maxSeats: 4 },
  banFile: './data/bans.json'
};
