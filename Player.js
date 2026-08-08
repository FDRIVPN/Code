import { randomUUID } from 'crypto';

export default class Player {
  constructor(ws) {
    this.id = randomUUID();
    this.ws = ws;
    this.name = '';
    this.job = '';
    this.position = { x: 0, y: 0, z: 0 };
    this.rotation = 0;
    this.vehicleId = null;
    this.seatIndex = null;
    this.isBanned = false;
  }

  send(data) {
    if (this.ws.readyState === 1) {
      this.ws.send(JSON.stringify(data));
    }
  }

  close(reason) {
    if (this.ws.readyState === 1) {
      this.ws.close(1000, reason);
    }
  }
}
