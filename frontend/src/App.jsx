import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import "./App.css";

const API_URL = "http://localhost:3000";

const ATTACK_TYPES = [
  "SUSPICIOUS_REQUEST",
  "LOGIN_FAILED",
  "RATE_LIMIT",
  "XSS",
  "SQL_INJECTION",
];

function App() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [activePage, setActivePage] = useState("overview");

  const fetchEvents = async () => {
    try {
      setLoading(true);

      const response = await axios.get(`${API_URL}/events`);

      setEvents(response.data.data || []);
    } catch (error) {
      console.error("이벤트 조회 실패:", error);
    } finally {
      setLoading(false);
    }
  };

  const createRandomEvent = async () => {
    const testEvents = [
      {
        eventType: "SUSPICIOUS_REQUEST",
        ip: "192.168.0.15",
        path: "/api/users",
        method: "GET",
        status: 403,
        userAgent: "Chrome",
      },
      {
        eventType: "LOGIN_FAILED",
        ip: "192.168.0.10",
        path: "/login",
        method: "POST",
        status: 401,
        userAgent: "Chrome",
      },
      {
        eventType: "RATE_LIMIT",
        ip: "192.168.0.20",
        path: "/api/search",
        method: "GET",
        status: 429,
        userAgent: "Chrome",
      },
      {
        eventType: "XSS",
        ip: "192.168.0.25",
        path: "/comment",
        method: "POST",
        status: 403,
        userAgent: "Firefox",
      },
      {
        eventType: "SQL_INJECTION",
        ip: "192.168.0.30",
        path: "/api/users",
        method: "GET",
        status: 403,
        userAgent: "Edge",
      },
      {
        eventType: "FILE_ACCESS",
        ip: "192.168.0.40",
        path: "/files/report.pdf",
        method: "GET",
        status: 200,
        userAgent: "Firefox",
      },
      {
        eventType: "ADMIN_ACTION",
        ip: "192.168.0.5",
        path: "/admin/users",
        method: "DELETE",
        status: 200,
        userAgent: "Chrome",
      },
    ];

    try {
      setCreating(true);

      const randomEvent =
        testEvents[
          Math.floor(Math.random() * testEvents.length)
        ];

      await axios.post(`${API_URL}/events`, randomEvent);

      await fetchEvents();
    } catch (error) {
      console.error("이벤트 생성 실패:", error);

      alert(
        "이벤트 생성에 실패했습니다.\nNode.js 서버가 실행 중인지 확인해주세요."
      );
    } finally {
      setCreating(false);
    }
  };

  useEffect(() => {
    fetchEvents();

    const interval = setInterval(() => {
      fetchEvents();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const stats = useMemo(() => {
    let suspicious = 0;
    let loginFailed = 0;
    let rateLimit = 0;

    events.forEach((event) => {
      if (event.eventType === "SUSPICIOUS_REQUEST") {
        suspicious += 1;
      }

      if (event.eventType === "LOGIN_FAILED") {
        loginFailed += 1;
      }

      if (event.eventType === "RATE_LIMIT") {
        rateLimit += 1;
      }
    });

    const attackCount = events.filter((event) =>
      ATTACK_TYPES.includes(event.eventType)
    ).length;

    return {
      total: events.length,
      suspicious,
      loginFailed,
      rateLimit,
      attackCount,
    };
  }, [events]);

  const eventTypeStats = useMemo(() => {
    const result = {};

    events.forEach((event) => {
      result[event.eventType] =
        (result[event.eventType] || 0) + 1;
    });

    return Object.entries(result).sort(
      (a, b) => b[1] - a[1]
    );
  }, [events]);

  const attackTypeStats = useMemo(() => {
    const result = {};

    events
      .filter((event) =>
        ATTACK_TYPES.includes(event.eventType)
      )
      .forEach((event) => {
        result[event.eventType] =
          (result[event.eventType] || 0) + 1;
      });

    return Object.entries(result).sort(
      (a, b) => b[1] - a[1]
    );
  }, [events]);

  const ipStats = useMemo(() => {
    const result = {};

    events
      .filter((event) =>
        ATTACK_TYPES.includes(event.eventType)
      )
      .forEach((event) => {
        if (!result[event.ip]) {
          result[event.ip] = {
            count: 0,
            lastSeen: event.timestamp,
            types: {},
          };
        }

        result[event.ip].count += 1;

        result[event.ip].types[event.eventType] =
          (result[event.ip].types[event.eventType] || 0) +
          1;

        if (
          new Date(event.timestamp) >
          new Date(result[event.ip].lastSeen)
        ) {
          result[event.ip].lastSeen = event.timestamp;
        }
      });

    return Object.entries(result)
      .map(([ip, data]) => ({
        ip,
        ...data,
      }))
      .sort((a, b) => b.count - a.count);
  }, [events]);

  const attackEvents = useMemo(() => {
    return events
      .filter((event) =>
        ATTACK_TYPES.includes(event.eventType)
      )
      .sort(
        (a, b) =>
          new Date(b.timestamp) -
          new Date(a.timestamp)
      );
  }, [events]);

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleString("ko-KR");
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <p className="eyebrow">
            SECURITY EVENT MONITOR
          </p>

          <h1>보안 이벤트 모니터</h1>

          <p className="subtitle">
            보안 이벤트를 수집하고 분석합니다.
          </p>
        </div>

        <div className="header-actions">
          <button
            className="refresh-button"
            onClick={fetchEvents}
            disabled={loading}
          >
            {loading ? "조회 중..." : "새로고침"}
          </button>

          <button
            className="event-button"
            onClick={createRandomEvent}
            disabled={creating}
          >
            {creating
              ? "생성 중..."
              : "⚡ 보안 이벤트 발생"}
          </button>
        </div>
      </header>

      <nav className="navigation">
        <div className="navigation-inner">
          <button
            className={
              activePage === "overview"
                ? "nav-button active"
                : "nav-button"
            }
            onClick={() => setActivePage("overview")}
          >
            Overview
            <span>전체 현황</span>
          </button>

          <button
            className={
              activePage === "attack"
                ? "nav-button active"
                : "nav-button"
            }
            onClick={() => setActivePage("attack")}
          >
            Attack Analysis
            <span>공격 분석</span>
          </button>
        </div>
      </nav>

      <main className="container">
        {activePage === "overview" ? (
          <OverviewPage
            events={events}
            stats={stats}
            eventTypeStats={eventTypeStats}
            formatTime={formatTime}
          />
        ) : (
          <AttackAnalysisPage
            attackTypeStats={attackTypeStats}
            ipStats={ipStats}
            attackEvents={attackEvents}
            formatTime={formatTime}
          />
        )}
      </main>
    </div>
  );
}

function OverviewPage({
  events,
  stats,
  eventTypeStats,
  formatTime,
}) {
  return (
    <>
      <div className="page-title">
        <div>
          <p className="page-label">OVERVIEW</p>

          <h2>전체 보안 현황</h2>

          <p>
            현재 수집된 보안 이벤트의 전체 상태를 확인합니다.
          </p>
        </div>
      </div>

      <section className="stat-grid">
        <StatCard
          title="전체 이벤트"
          value={stats.total}
          description="현재 수집된 전체 이벤트"
        />

        <StatCard
          title="공격 이벤트"
          value={stats.attackCount}
          description="공격으로 분류된 이벤트"
          danger
        />

        <StatCard
          title="로그인 실패"
          value={stats.loginFailed}
          description="LOGIN_FAILED"
        />

        <StatCard
          title="의심 요청"
          value={stats.suspicious}
          description="SUSPICIOUS_REQUEST"
        />
      </section>

      <section className="overview-grid">
        <section className="panel">
          <PanelHeader
            title="이벤트 유형별 현황"
            description="전체 이벤트를 유형별로 확인합니다."
          />

          {eventTypeStats.length === 0 ? (
            <Empty />
          ) : (
            <div className="chart-list">
              {eventTypeStats.map(([type, count]) => {
                const max = eventTypeStats[0][1];
                const width =
                  max === 0 ? 0 : (count / max) * 100;

                return (
                  <div
                    className="chart-row"
                    key={type}
                  >
                    <div className="chart-label">
                      <span>{type}</span>
                      <strong>{count}</strong>
                    </div>

                    <div className="bar-background">
                      <div
                        className={`bar ${getBarClass(
                          type
                        )}`}
                        style={{
                          width: `${width}%`,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="panel">
          <PanelHeader
            title="보안 상태 요약"
            description="현재 시스템의 주요 지표입니다."
          />

          <div className="summary-list">
            <SummaryRow
              label="전체 이벤트"
              value={`${stats.total}건`}
            />

            <SummaryRow
              label="공격 이벤트"
              value={`${stats.attackCount}건`}
              danger={stats.attackCount > 0}
            />

            <SummaryRow
              label="로그인 실패"
              value={`${stats.loginFailed}건`}
            />

            <SummaryRow
              label="Rate Limit"
              value={`${stats.rateLimit}건`}
            />
          </div>
        </section>
      </section>

      <section className="panel">
        <PanelHeader
          title="최근 보안 이벤트"
          description="최근 발생한 이벤트를 시간순으로 보여줍니다."
        />

        <EventTable
          events={events}
          formatTime={formatTime}
        />
      </section>
    </>
  );
}

function AttackAnalysisPage({
  attackTypeStats,
  ipStats,
  attackEvents,
  formatTime,
}) {
  const totalAttacks = attackEvents.length;

  const topAttackType =
    attackTypeStats.length > 0
      ? attackTypeStats[0][0]
      : "-";

  const topAttackIp =
    ipStats.length > 0
      ? ipStats[0].ip
      : "-";

  const maxAttackCount =
    attackTypeStats.length > 0
      ? attackTypeStats[0][1]
      : 0;

  return (
    <>
      <div className="page-title">
        <div>
          <p className="page-label">ATTACK ANALYSIS</p>

          <h2>공격 분석</h2>

          <p>
            어떤 공격이 많이 발생하고 어떤 IP에서 공격이
            집중되는지 분석합니다.
          </p>
        </div>
      </div>

      <section className="stat-grid">
        <StatCard
          title="공격 이벤트"
          value={totalAttacks}
          description="공격으로 분류된 이벤트"
          danger
        />

        <StatCard
          title="공격 유형"
          value={attackTypeStats.length}
          description="탐지된 공격 유형 수"
        />

        <StatCard
          title="공격 IP"
          value={ipStats.length}
          description="공격을 발생시킨 IP"
        />

        <StatCard
          title="최다 공격 유형"
          value={topAttackType}
          description={
            maxAttackCount > 0
              ? `${maxAttackCount}회 발생`
              : "데이터 없음"
          }
        />
      </section>

      <section className="analysis-grid">
        <section className="panel">
          <PanelHeader
            title="공격 유형 분석"
            description="공격 종류별 발생량을 비교합니다."
          />

          {attackTypeStats.length === 0 ? (
            <Empty />
          ) : (
            <div className="chart-list">
              {attackTypeStats.map(
                ([type, count]) => {
                  const width =
                    maxAttackCount === 0
                      ? 0
                      : (count /
                          maxAttackCount) *
                        100;

                  return (
                    <div
                      className="chart-row"
                      key={type}
                    >
                      <div className="chart-label">
                        <span>{type}</span>
                        <strong>{count}</strong>
                      </div>

                      <div className="bar-background">
                        <div
                          className="bar attack"
                          style={{
                            width: `${width}%`,
                          }}
                        />
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          )}
        </section>

        <section className="panel">
          <PanelHeader
            title="최다 공격 IP"
            description="공격 횟수가 많은 IP입니다."
          />

          <div className="top-ip-box">
            <span>TOP ATTACK IP</span>

            <strong>{topAttackIp}</strong>

            <small>
              {ipStats.length > 0
                ? `${ipStats[0].count}개의 공격 이벤트`
                : "데이터 없음"}
            </small>
          </div>
        </section>
      </section>

      <section className="panel">
        <PanelHeader
          title="공격 IP 분석"
          description="공격 IP별 발생 횟수와 주요 공격 유형을 확인합니다."
        />

        {ipStats.length === 0 ? (
          <Empty />
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>순위</th>
                  <th>IP</th>
                  <th>공격 횟수</th>
                  <th>주요 공격 유형</th>
                  <th>최근 발생</th>
                </tr>
              </thead>

              <tbody>
                {ipStats.map((item, index) => {
                  const topType =
                    Object.entries(item.types).sort(
                      (a, b) => b[1] - a[1]
                    )[0]?.[0] || "-";

                  return (
                    <tr key={item.ip}>
                      <td>
                        <strong>{index + 1}</strong>
                      </td>

                      <td>{item.ip}</td>

                      <td>
                        <span className="attack-count">
                          {item.count}
                        </span>
                      </td>

                      <td>
                        <span className="badge danger">
                          {topType}
                        </span>
                      </td>

                      <td>
                        {formatTime(item.lastSeen)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <PanelHeader
          title="공격 이벤트 목록"
          description="공격으로 분류된 이벤트만 표시합니다."
        />

        <EventTable
          events={attackEvents}
          formatTime={formatTime}
        />
      </section>
    </>
  );
}

function StatCard({
  title,
  value,
  description,
  danger = false,
}) {
  return (
    <div
      className={`stat-card ${
        danger ? "stat-danger" : ""
      }`}
    >
      <span>{title}</span>

      <strong>{value}</strong>

      <small>{description}</small>
    </div>
  );
}

function PanelHeader({
  title,
  description,
}) {
  return (
    <div className="panel-header">
      <div>
        <h3>{title}</h3>

        <p>{description}</p>
      </div>
    </div>
  );
}

function SummaryRow({
  label,
  value,
  danger = false,
}) {
  return (
    <div className="summary-row">
      <span>{label}</span>

      <strong
        className={danger ? "danger-text" : ""}
      >
        {value}
      </strong>
    </div>
  );
}

function EventTable({
  events,
  formatTime,
}) {
  if (events.length === 0) {
    return <Empty />;
  }

  return (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>시간</th>
            <th>IP</th>
            <th>이벤트</th>
            <th>요청 경로</th>
            <th>Method</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {events.map((event) => (
            <tr key={event.eventId}>
              <td>
                {formatTime(event.timestamp)}
              </td>

              <td>{event.ip}</td>

              <td>
                <span
                  className={`badge ${getBadgeClass(
                    event.eventType
                  )}`}
                >
                  {event.eventType}
                </span>
              </td>

              <td>{event.path}</td>

              <td>{event.method}</td>

              <td>
                <span
                  className={`status ${
                    event.status >= 400
                      ? "danger"
                      : "success"
                  }`}
                >
                  {event.status}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Empty() {
  return (
    <div className="empty">
      표시할 데이터가 없습니다.
    </div>
  );
}

function getBadgeClass(type) {
  switch (type) {
    case "SUSPICIOUS_REQUEST":
      return "warning";

    case "LOGIN_FAILED":
      return "danger";

    case "RATE_LIMIT":
      return "limit";

    case "XSS":
      return "xss";

    case "SQL_INJECTION":
      return "sql";

    case "ADMIN_ACTION":
      return "admin";

    case "FILE_ACCESS":
      return "file";

    default:
      return "normal";
  }
}

function getBarClass(type) {
  switch (type) {
    case "SUSPICIOUS_REQUEST":
      return "suspicious";

    case "LOGIN_FAILED":
      return "login";

    case "RATE_LIMIT":
      return "rate";

    case "XSS":
      return "xss";

    case "SQL_INJECTION":
      return "sql";

    default:
      return "normal";
  }
}

export default App;