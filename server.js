#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import sys
import os
from websocket import create_connection, WebSocketException

DEFAULT_URL = "wss://gojo-server1.up.railway.app"
SERVER_URL = os.environ.get("SERVER_URL", DEFAULT_URL)
if len(sys.argv) > 1:
    SERVER_URL = sys.argv[1]

class GameClient:
    def __init__(self, url, name="Client"):
        self.url = url
        self.name = name
        self.ws = None
        self.player_id = None
        self.vehicle_id = None
        self.message_queue = []

    def connect(self):
        try:
            print(f"[{self.name}] Connecting to {self.url} ...")
            self.ws = create_connection(self.url, timeout=5)
            raw = self.ws.recv()
            data = json.loads(raw)
            if data.get("type") == "set_id":
                self.player_id = data.get("id")
                print(f"[{self.name}] Connected. Player ID: {self.player_id}")
                return True
            return False
        except Exception as e:
            print(f"[{self.name}] Connection failed: {e}")
            return False

    def send(self, payload):
        if self.ws:
            self.ws.send(json.dumps(payload))

    def wait_for_type(self, expected_types, timeout=5):
        """منتظر پیام با نوع مشخص، بقیه پیام‌ها رو در صف نگه می‌داره"""
        start = time.time()
        while time.time() - start < timeout:
            # اول صف رو چک کن
            for i, msg in enumerate(self.message_queue):
                if msg.get("type") in expected_types:
                    return self.message_queue.pop(i)
            # از سوکت بخوان
            try:
                self.ws.settimeout(0.5)
                raw = self.ws.recv()
                if raw:
                    data = json.loads(raw)
                    if data.get("type") in expected_types:
                        return data
                    else:
                        self.message_queue.append(data)
            except:
                pass
        return None

    def close(self):
        if self.ws:
            self.ws.close()

class GameTester:
    def __init__(self, url):
        self.url = url
        self.owner = None
        self.passenger = None
        self.pass_count = 0
        self.fail_count = 0

    def log(self, msg, level="INFO"):
        print(f"[{level}] {msg}")

    def assert_true(self, condition, msg):
        if condition:
            self.pass_count += 1
            self.log(f"✅ PASS: {msg}", "PASS")
            return True
        else:
            self.fail_count += 1
            self.log(f"❌ FAIL: {msg}", "FAIL")
            return False

    def connect_clients(self):
        self.owner = GameClient(self.url, "Owner")
        if not self.owner.connect():
            return False
        self.passenger = GameClient(self.url, "Passenger")
        if not self.passenger.connect():
            return False
        return True

    def run(self):
        self.log("=" * 60)
        self.log("🚗 Starting Game Server Tests (Two Clients)")
        self.log(f"🔗 Server: {self.url}")
        self.log("=" * 60)

        if not self.connect_clients():
            self.log("❌ Cannot run tests without connection", "ERROR")
            return

        # 1. Update Position
        self.log("\n▶️ Running: Update Position (Owner)")
        self.owner.send({"type": "update", "position": {"x": 100, "y": 200}, "rotation": 1.2})
        time.sleep(0.5)
        self.assert_true(self.owner.ws.connected, "Owner connection alive")

        # 2. Create Vehicle
        self.log("\n▶️ Running: Create Vehicle (Owner)")
        self.owner.send({
            "type": "create_vehicle",
            "name": "Ali",
            "job": "Driver",
            "position": {"x": 50, "y": 60},
            "rotation": 0.5,
            "steering": 0.1
        })
        resp = self.owner.wait_for_type(["vehicle_state"], timeout=5)
        if resp and resp.get("type") == "vehicle_state":
            vehicle = resp.get("vehicle")
            if vehicle and vehicle.get("ownerId") == self.owner.player_id:
                self.owner.vehicle_id = vehicle.get("id")
                self.log(f"[Owner] Vehicle created with ID: {self.owner.vehicle_id}")
                self.assert_true(True, "Vehicle creation succeeded")
                seats = vehicle.get("seats", [])
                if len(seats) >= 1 and seats[0] == self.owner.player_id:
                    self.assert_true(True, "Owner seat (0) is correct")
                else:
                    self.assert_true(False, f"Owner seat wrong: {seats}")
            else:
                self.assert_true(False, "Vehicle state invalid")
        else:
            self.assert_true(False, f"No vehicle_state: {resp}")

        # 3. Join Vehicle (Passenger)
        self.log("\n▶️ Running: Join Vehicle (Passenger)")
        if self.owner.vehicle_id:
            self.passenger.send({
                "type": "join_vehicle",
                "vehicleId": self.owner.vehicle_id,
                "seatIndex": 1
            })
            resp = self.passenger.wait_for_type(["seat_update"], timeout=5)
            if resp and resp.get("type") == "seat_update":
                seats = resp.get("seats", [])
                if len(seats) > 1 and seats[1] == self.passenger.player_id:
                    self.assert_true(True, "Passenger joined seat 1")
                    self.passenger.vehicle_id = self.owner.vehicle_id
                else:
                    self.assert_true(False, f"Seat 1 not occupied: {seats}")
            else:
                self.assert_true(False, f"No seat_update: {resp}")
        else:
            self.assert_true(False, "No vehicle to join")

        # 4. Update Vehicle
        self.log("\n▶️ Running: Update Vehicle (Owner)")
        self.owner.send({
            "type": "update_vehicle",
            "position": {"x": 200, "y": 300},
            "rotation": 1.0,
            "steering": 0.3
        })
        resp = self.owner.wait_for_type(["vehicle_state"], timeout=5)
        if resp and resp.get("type") == "vehicle_state":
            v = resp.get("vehicle")
            if v and v.get("id") == self.owner.vehicle_id:
                pos = v.get("position")
                if pos and pos.get("x") == 200 and pos.get("y") == 300:
                    self.assert_true(True, "Vehicle position updated")
                else:
                    self.assert_true(False, f"Position not updated: {pos}")
            else:
                self.assert_true(False, "Vehicle state mismatch")
        else:
            self.assert_true(False, f"No vehicle_state: {resp}")

        # 5. Chat
        self.log("\n▶️ Running: Chat (Owner)")
        msg_text = "Hello from owner!"
        self.owner.send({"type": "chat", "message": msg_text})
        resp = self.owner.wait_for_type(["chat"], timeout=5)
        if resp and resp.get("type") == "chat":
            received = resp.get("message")
            if received == msg_text:
                self.assert_true(True, "Chat message echoed")
            else:
                self.assert_true(False, f"Message mismatch: {received}")
        else:
            self.assert_true(False, f"No chat: {resp}")

        # 6. Ban
        self.log("\n▶️ Running: Ban (dummy)")
        dummy_id = "dummy-user-123"
        self.owner.send({"type": "ban_player", "targetId": dummy_id})
        resp = self.owner.wait_for_type(["ban_list"], timeout=5)
        if resp and resp.get("type") == "ban_list":
            bans = resp.get("bans", [])
            self.assert_true(dummy_id in bans, f"Ban list contains {dummy_id}")
        else:
            self.assert_true(False, f"No ban_list: {resp}")

        # 7. Unban
        self.log("\n▶️ Running: Unban (dummy)")
        self.owner.send({"type": "unban_player", "targetId": dummy_id})
        resp = self.owner.wait_for_type(["ban_list"], timeout=5)
        if resp and resp.get("type") == "ban_list":
            bans = resp.get("bans", [])
            self.assert_true(dummy_id not in bans, f"Unbanned {dummy_id}")
        else:
            self.assert_true(False, f"No ban_list: {resp}")

        # 8. Leave Vehicle (Passenger)
        self.log("\n▶️ Running: Leave Vehicle (Passenger)")
        self.passenger.send({"type": "leave_vehicle"})
        resp = self.passenger.wait_for_type(["seat_update"], timeout=5)
        if resp and resp.get("type") == "seat_update":
            seats = resp.get("seats", [])
            if len(seats) > 1 and seats[1] is None:
                self.assert_true(True, "Passenger left, seat 1 empty")
            else:
                self.assert_true(False, f"Seat 1 not empty: {seats}")
        else:
            self.assert_true(False, f"No seat_update: {resp}")

        # 9. Leave Vehicle (Owner) - ماشین باقی می‌مونه
        self.log("\n▶️ Running: Leave Vehicle (Owner)")
        self.owner.send({"type": "leave_vehicle"})
        resp = self.owner.wait_for_type(["seat_update"], timeout=5)
        if resp and resp.get("type") == "seat_update":
            seats = resp.get("seats", [])
            if len(seats) > 0 and seats[0] is None:
                self.assert_true(True, "Owner left, vehicle remains with empty seat 0")
            else:
                self.assert_true(False, f"Seat 0 not empty: {seats}")
        else:
            self.assert_true(False, f"No seat_update: {resp}")

        # بستن
        self.owner.close()
        self.passenger.close()
        self.log("Connections closed.")

        self.log("\n" + "=" * 60)
        self.log("📊 TEST SUMMARY")
        self.log(f"✅ Passed: {self.pass_count}")
        self.log(f"❌ Failed: {self.fail_count}")
        total = self.pass_count + self.fail_count
        if total > 0:
            self.log(f"📈 Success rate: {self.pass_count/total*100:.1f}%")
        self.log("=" * 60)

if __name__ == "__main__":
    tester = GameTester(SERVER_URL)
    tester.run()
