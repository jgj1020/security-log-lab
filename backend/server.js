const express = require("express");
const cors = require("cors");

const {
  createSecurityEvent,
} = require("./security-event");

const {
  connectProducer,
  sendSecurityEvent,
  disconnectProducer,
} = require("./kafka-producer");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const securityEvents = [];

// ----------------------------------------
// 서버 상태
// ----------------------------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Security Event Monitor API 서버가 실행 중입니다.",
    kafka: "Producer 준비 완료",
  });
});

// ----------------------------------------
// 보안 이벤트 생성
// ----------------------------------------

app.post("/events", async (req, res) => {
  try {
    const {
      eventType,
      ip,
      path,
      method,
      status,
      userAgent,
    } = req.body;

    if (
      !eventType ||
      !ip ||
      !path ||
      !method ||
      status === undefined
    ) {
      return res.status(400).json({
        success: false,
        message:
          "eventType, ip, path, method, status는 필수입니다.",
      });
    }

    const event = createSecurityEvent({
      eventType,
      ip,
      path,
      method,
      status,
      userAgent,
    });

    // 임시 저장
    securityEvents.push(event);

    // Kafka로 전송
    await sendSecurityEvent(event);

    console.log("🚨 보안 이벤트 생성");
    console.log(event);

    res.status(201).json({
      success: true,
      message: "보안 이벤트 생성 및 Kafka 전송 성공",
      data: event,
    });
  } catch (error) {
    console.error("❌ 이벤트 처리 실패");
    console.error(error.message);

    res.status(500).json({
      success: false,
      message: "보안 이벤트 처리 실패",
      error: error.message,
    });
  }
});

// ----------------------------------------
// 전체 이벤트 조회
// ----------------------------------------

app.get("/events", (req, res) => {
  const sortedEvents = [...securityEvents].sort(
    (a, b) =>
      new Date(b.timestamp) -
      new Date(a.timestamp)
  );

  res.json({
    success: true,
    count: sortedEvents.length,
    data: sortedEvents,
  });
});

// ----------------------------------------
// 이벤트 검색
// ----------------------------------------

app.get("/events/search", (req, res) => {
  const { eventType } = req.query;

  if (!eventType) {
    return res.status(400).json({
      success: false,
      message: "eventType을 입력해주세요.",
    });
  }

  const result = securityEvents.filter(
    (event) => event.eventType === eventType
  );

  res.json({
    success: true,
    count: result.length,
    data: result,
  });
});

// ----------------------------------------
// IP 검색
// ----------------------------------------

app.get("/events/search-ip", (req, res) => {
  const { ip } = req.query;

  if (!ip) {
    return res.status(400).json({
      success: false,
      message: "ip를 입력해주세요.",
    });
  }

  const result = securityEvents.filter(
    (event) => event.ip === ip
  );

  res.json({
    success: true,
    count: result.length,
    data: result,
  });
});

// ----------------------------------------
// 통계
// ----------------------------------------

app.get("/events/stats", (req, res) => {
  const stats = {};

  for (const event of securityEvents) {
    stats[event.eventType] =
      (stats[event.eventType] || 0) + 1;
  }

  res.json({
    success: true,
    data: stats,
  });
});

// ----------------------------------------
// 서버 시작
// ----------------------------------------

async function startServer() {
  try {
    await connectProducer();

    app.listen(PORT, () => {
      console.log(
        `🚀 Security Event Monitor: http://localhost:${PORT}`
      );

      console.log(
        "📦 저장 방식: 메모리 + Kafka Producer"
      );
    });
  } catch (error) {
    console.error("❌ Kafka 연결 실패");
    console.error(error.message);

    console.log(
      "⚠️ Kafka가 실행되지 않아 서버를 시작하지 않습니다."
    );

    process.exit(1);
  }
}

// ----------------------------------------
// 종료 처리
// ----------------------------------------

async function shutdown() {
  try {
    await disconnectProducer();
  } finally {
    process.exit(0);
  }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

startServer();