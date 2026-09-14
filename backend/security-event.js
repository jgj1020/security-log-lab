function createSecurityEvent({
  eventType,
  ip,
  path,
  method,
  status,
  userAgent = "unknown",
}) {
  return {
    eventId: `EVT-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    timestamp: new Date().toISOString(),
    eventType,
    ip,
    path,
    method,
    status,
    userAgent,
  };
}

module.exports = {
  createSecurityEvent,
};