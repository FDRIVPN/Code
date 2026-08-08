export default class Chat {
  constructor(banManager) {
    this.banManager = banManager;
    this.history = [];
    this.maxHistory = 100;
  }

  // پردازش پیام: اگر بازیکن بن باشد، null برمی‌گرداند
  processMessage(playerId, message) {
    if (this.banManager && this.banManager.isBanned(playerId)) {
      return null;
    }
    // فیلتر ساده (می‌توانید کلمات زشت را اینجا اضافه کنید)
    const filtered = message.replace(/badword/gi, '***');
    this.history.push({ playerId, message: filtered, timestamp: Date.now() });
    if (this.history.length > this.maxHistory) this.history.shift();
    return filtered;
  }

  getHistory() {
    return this.history;
  }
}
