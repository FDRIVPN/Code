import { randomUUID } from "crypto";

class Player {
    constructor(id = null) {
        this.id = id || randomUUID();
        this.name = "Player";
        this.job = "None";
        this.x = 0;
        this.y = 0;
        this.z = 0;
        this.rot = 0;
        this.animation = "idle";
        this.connected = true;
        this.joinTime = Date.now();
    }

    // به‌روزرسانی موقعیت
    updatePosition(x, y, z, rot, animation) {
        this.x = x;
        this.y = y;
        this.z = z;
        this.rot = rot;
        this.animation = animation || this.animation;
    }

    // تنظیم نام
    setName(name) {
        if (name && name.length > 0 && name.length <= 20) {
            this.name = name;
            return true;
        }
        return false;
    }

    // تنظیم شغل
    setJob(job) {
        const validJobs = ["None", "Warrior", "Mage", "Archer", "Healer", "Assassin"];
        if (validJobs.includes(job)) {
            this.job = job;
            return true;
        }
        return false;
    }

    // گرفتن اطلاعات بازیکن برای ارسال به کلاینت
    toJSON() {
        return {
            id: this.id,
            name: this.name,
            job: this.job,
            x: this.x,
            y: this.y,
            z: this.z,
            rot: this.rot,
            animation: this.animation
        };
    }

    // بررسی اینکه بازیکن فعال است
    isActive() {
        return this.connected && (Date.now() - this.joinTime < 3600000); // 1 ساعت
    }
}

export default Player;
