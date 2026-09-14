const { Kafka } = require("kafkajs");

const kafka = new Kafka({
  clientId: "security-event-monitor",
  brokers: ["localhost:9092"],
});

const producer = kafka.producer();

async function connectProducer() {
  await producer.connect();
  console.log("✅ Kafka Producer 연결 성공");
}

async function sendSecurityEvent(event) {
  await producer.send({
    topic: "security-events",
    messages: [
      {
        key: event.eventType,
        value: JSON.stringify(event),
      },
    ],
  });

  console.log("📤 Kafka로 이벤트 전송:");
  console.log(event);
}

async function disconnectProducer() {
  await producer.disconnect();
}

module.exports = {
  connectProducer,
  sendSecurityEvent,
  disconnectProducer,
};