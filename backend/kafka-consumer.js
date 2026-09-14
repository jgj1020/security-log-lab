const { Kafka } = require("kafkajs");

const kafka = new Kafka({
  clientId: "security-event-monitor-consumer",
  brokers: ["localhost:9092"],
});

const consumer = kafka.consumer({
  groupId: "security-event-monitor-group",
});

async function startConsumer() {
  await consumer.connect();

  console.log("✅ Kafka Consumer 연결 성공");

  await consumer.subscribe({
    topic: "security-events",
    fromBeginning: true,
  });

  console.log("📥 security-events Topic 구독 완료");

  await consumer.run({
    eachMessage: async ({ topic, partition, message }) => {
      const value = message.value?.toString();

      console.log("\n==============================");
      console.log("📨 Kafka 메시지 수신");
      console.log("==============================");

      console.log("Topic:", topic);
      console.log("Partition:", partition);
      console.log("Offset:", message.offset);
      console.log("Key:", message.key?.toString());
      console.log("Value:", value);

      try {
        const event = JSON.parse(value);

        console.log("\n🔐 보안 이벤트");
        console.log("이벤트:", event.eventType);
        console.log("IP:", event.ip);
        console.log("경로:", event.path);
        console.log("Method:", event.method);
        console.log("Status:", event.status);
        console.log("시간:", event.timestamp);
      } catch (error) {
        console.log("⚠️ JSON 변환 실패:", error.message);
      }
    },
  });
}

async function shutdown() {
  try {
    await consumer.disconnect();
    console.log("🛑 Kafka Consumer 종료");
  } finally {
    process.exit(0);
  }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

startConsumer().catch((error) => {
  console.error("❌ Kafka Consumer 실행 실패");
  console.error(error.message);
  process.exit(1);
});