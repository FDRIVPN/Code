import { randomUUID } from 'crypto';

export default class Vehicle {
  constructor(ownerId, name, job, position, rotation, steering, car_db_id) {
    this.id = randomUUID();          // ID یکتای ماشین
    this.ownerId = ownerId;          // ID مالک (پلیر)
    this.name = name;
    this.job = job;
    this.position = { ...position };
    this.rotation = rotation;
    this.steering = steering || 0;
    this.car_db_id = car_db_id || null;  // شناسه ماشین از دیتابیس (اختیاری)
    this.seats = [ownerId, null, null, null];
  }

  isSeatAvailable(seatIndex) {
    return seatIndex >= 0 && seatIndex < 4 && this.seats[seatIndex] === null;
  }

  addPassenger(playerId, seatIndex) {
    if (seatIndex === 0) return false;
    if (!this.isSeatAvailable(seatIndex)) return false;
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
    if (position) this.position = { ...position };
    if (rotation !== undefined) this.rotation = rotation;
    if (steering !== undefined) this.steering = steering;
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
      seats: this.seats,
      car_db_id: this.car_db_id
    };
  }
}
