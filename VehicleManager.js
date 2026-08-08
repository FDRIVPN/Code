import Vehicle from './Vehicle.js';

export default class VehicleManager {
  constructor() {
    this.vehicles = new Map();
  }

  createVehicle(ownerId, name, job, position, rotation, steering) {
    if (this.vehicles.has(ownerId)) return null;
    const vehicle = new Vehicle(ownerId, name, job, position, rotation, steering);
    this.vehicles.set(ownerId, vehicle);
    return vehicle;
  }

  getVehicle(vehicleId) {
    return this.vehicles.get(vehicleId) || null;
  }

  removeVehicle(vehicleId) {
    const vehicle = this.vehicles.get(vehicleId);
    if (vehicle) this.vehicles.delete(vehicleId);
    return vehicle;
  }

  findVehicleByPlayer(playerId) {
    for (const [id, vehicle] of this.vehicles) {
      if (vehicle.seats.includes(playerId)) {
        return vehicle;
      }
    }
    return null;
  }

  getAllVehicles() {
    return Array.from(this.vehicles.values()).map(v => v.getState());
  }
}
