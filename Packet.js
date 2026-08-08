export const PacketType = {
  // عمومی
  SET_ID: 'set_id',
  UPDATE: 'update',
  CHAT: 'chat',
  PING: 'ping',
  FULL_STATE: 'full_state',
  PLAYER_LEFT: 'player_left',
  ERROR: 'error',

  // ماشین
  CREATE_VEHICLE: 'create_vehicle',
  JOIN_VEHICLE: 'join_vehicle',
  LEAVE_VEHICLE: 'leave_vehicle',
  UPDATE_VEHICLE: 'update_vehicle',
  VEHICLE_STATE: 'vehicle_state',
  SEAT_UPDATE: 'seat_update',
  VEHICLE_REMOVED: 'vehicle_removed',

  // بن
  BAN_PLAYER: 'ban_player',
  UNBAN_PLAYER: 'unban_player',
  BAN_LIST: 'ban_list',
  YOU_ARE_BANNED: 'you_are_banned'
};
