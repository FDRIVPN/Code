import fs from 'fs/promises';
import config from './config.js';

export default class BanManager {
  constructor() {
    this.bannedIds = new Set();
    this.banFile = config.banFile;
    this.loadBans();
  }

  async loadBans() {
    try {
      const data = await fs.readFile(this.banFile, 'utf-8');
      const list = JSON.parse(data);
      this.bannedIds = new Set(list);
      console.log(`✅ Loaded ${this.bannedIds.size} bans.`);
    } catch (err) {
      if (err.code === 'ENOENT') {
        await this.saveBans();
        console.log('📄 Created new ban file.');
      } else {
        console.error('❌ Failed to load ban file:', err);
      }
    }
  }

  async saveBans() {
    try {
      const list = Array.from(this.bannedIds);
      await fs.writeFile(this.banFile, JSON.stringify(list, null, 2));
    } catch (err) {
      console.error('❌ Failed to save ban file:', err);
    }
  }

  async ban(playerId) {
    if (this.bannedIds.has(playerId)) return false;
    this.bannedIds.add(playerId);
    await this.saveBans();
    return true;
  }

  async unban(playerId) {
    if (!this.bannedIds.has(playerId)) return false;
    this.bannedIds.delete(playerId);
    await this.saveBans();
    return true;
  }

  isBanned(playerId) {
    return this.bannedIds.has(playerId);
  }

  getBanList() {
    return Array.from(this.bannedIds);
  }
}
