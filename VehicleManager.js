import Vehicle from './Vehicle.js';

export default class VehicleManager {
  constructor() {
    this.vehicles = new Map(); // key: CAR_DB_ID, value: Vehicle
  }

  createVehicle(ownerId, name, job, position, rotation, steering) {
    const vehicle = new Vehicle(ownerId, name, job, position, rotation, steering);
    this.vehicles.set(vehicle.CAR_DB_ID, vehicle);
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

  findVehiclesByOwner(ownerId) {
    const result = [];
    for (const [id, vehicle] of this.vehicles) {
      if (vehicle.ownerId === ownerId) {
        result.push(vehicle);
      }
    }
    return result;
  }
}
