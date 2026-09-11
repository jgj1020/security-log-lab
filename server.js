const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

const PORT = 3000;

/*
|--------------------------------------------------------------------------
| 기본 설정
|--------------------------------------------------------------------------
*/

app.set('trust proxy', true);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/*
|--------------------------------------------------------------------------
| 로그 파일
|--------------------------------------------------------------------------
*/

const LOG_FILE = path.join(__dirname, 'security.log');

function ensureLogFile() {
  if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '', 'utf8');
  }
}

ensureLogFile();

/*
|--------------------------------------------------------------------------
| Rate Limiting
|--------------------------------------------------------------------------
| 같은 IP에서 로그인 요청을 너무 많이 보내면 차단
|--------------------------------------------------------------------------
*/

const loginAttempts = new Map();

const RATE_LIMIT_WINDOW = 60 * 1000; // 1분
const MAX_LOGIN_ATTEMPTS = 5; // 1분에 5회까지 허용

/*
|--------------------------------------------------------------------------
| WAF 차단 패턴
|--------------------------------------------------------------------------
*/

const BLOCK_PATTERNS = [
  // SQL Injection

  {
    name: 'SQL_INJECTION_OR',
    regex: /(\bor\b|\band\b)\s+[^&]*?(=|')/i,
  },

  {
    name: 'SQL_INJECTION_UNION',
    regex: /union\s+select/i,
  },

  {
    name: 'SQL_INJECTION_SELECT_FROM',
    regex: /select\s+.+\s+from/i,
  },

  {
    name: 'SQL_INJECTION_DROP',
    regex: /drop\s+table/i,
  },

  {
    name: 'SQL_INJECTION_INSERT',
    regex: /insert\s+into/i,
  },

  {
    name: 'SQL_INJECTION_DELETE',
    regex: /delete\s+from/i,
  },

  {
    name: 'SQL_INJECTION_UPDATE',
    regex: /update\s+.+\s+set/i,
  },

  // XSS

  {
    name: 'XSS_SCRIPT',
    regex: /<script[\s>]/i,
  },

  {
    name: 'XSS_JAVASCRIPT',
    regex: /javascript\s*:/i,
  },

  {
    name: 'XSS_ONERROR',
    regex: /onerror\s*=/i,
  },

  {
    name: 'XSS_ONLOAD',
    regex: /onload\s*=/i,
  },

  // Path Traversal

  {
    name: 'PATH_TRAVERSAL_UNIX',
    regex: /\.\.\//,
  },

  {
    name: 'PATH_TRAVERSAL_WINDOWS',
    regex: /\.\.\\/,
  },
];

/*
|--------------------------------------------------------------------------
| 로그 값 정리
|--------------------------------------------------------------------------
*/

function sanitizeLogValue(value) {
  return String(value ?? '')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

/*
|--------------------------------------------------------------------------
| 로그 저장 함수
|--------------------------------------------------------------------------
*/

function writeLog(type, message, req, extra = {}) {
  const log = {
    time: new Date().toISOString(),
    type,
    method: req.method,
    path: sanitizeLogValue(req.originalUrl),
    ip: req.ip,
    message,
    ...extra,
  };

  const line = JSON.stringify(log);

  // 터미널 출력
  console.log(line);

  // security.log 저장
  fs.appendFile(LOG_FILE, `${line}\n`, 'utf8', (error) => {
    if (error) {
      console.error('로그 파일 저장 실패:', error);
    }
  });
}

/*
|--------------------------------------------------------------------------
| 요청 데이터 가져오기
|--------------------------------------------------------------------------
*/

function getRequestText(req) {
  return JSON.stringify({
    url: req.originalUrl,
    query: req.query,
    body: req.body,
    params: req.params,
    userAgent: req.get('user-agent') || '',
  });
}

/*
|--------------------------------------------------------------------------
| WAF Middleware
|--------------------------------------------------------------------------
*/

function wafMiddleware(req, res, next) {
  const requestText = getRequestText(req);

  const matchedPattern = BLOCK_PATTERNS.find(({ regex }) =>
    regex.test(requestText)
  );

  /*
  |--------------------------------------------------------------------------
  | 공격 패턴 발견
  |--------------------------------------------------------------------------
  */

  if (matchedPattern) {
    writeLog(
      'WAF_BLOCK',
      '의심스러운 요청이 감지되어 차단했습니다.',
      req,
      {
        reason: matchedPattern.name,
      }
    );

    return res.status(403).json({
      success: false,
      message: 'WAF에 의해 요청이 차단되었습니다.',
      reason: matchedPattern.name,
    });
  }

  /*
  |--------------------------------------------------------------------------
  | 정상 요청
  |--------------------------------------------------------------------------
  */

  writeLog(
    'WAF_ALLOW',
    '정상 요청으로 판단했습니다.',
    req
  );

  next();
}

/*
|--------------------------------------------------------------------------
| Rate Limiting Middleware
|--------------------------------------------------------------------------
*/

function loginRateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();

  let record = loginAttempts.get(ip);

  /*
  |--------------------------------------------------------------------------
  | 처음 요청한 IP
  |--------------------------------------------------------------------------
  */

  if (!record) {
    record = {
      count: 0,
      firstRequest: now,
    };

    loginAttempts.set(ip, record);
  }

  /*
  |--------------------------------------------------------------------------
  | 1분이 지나면 기록 초기화
  |--------------------------------------------------------------------------
  */

  if (now - record.firstRequest >= RATE_LIMIT_WINDOW) {
    record.count = 0;
    record.firstRequest = now;
  }

  /*
  |--------------------------------------------------------------------------
  | 요청 횟수 증가
  |--------------------------------------------------------------------------
  */

  record.count++;

  /*
  |--------------------------------------------------------------------------
  | 요청 횟수 초과
  |--------------------------------------------------------------------------
  */

  if (record.count > MAX_LOGIN_ATTEMPTS) {
    writeLog(
      'RATE_LIMIT_BLOCK',
      '로그인 요청 횟수가 너무 많아 요청을 차단했습니다.',
      req,
      {
        reason: 'TOO_MANY_LOGIN_REQUESTS',
        attempts: record.count,
      }
    );

    return res.status(429).json({
      success: false,
      message:
        '로그인 요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
    });
  }

  next();
}

/*
|--------------------------------------------------------------------------
| WAF 적용
|--------------------------------------------------------------------------
*/

app.use(wafMiddleware);

/*
|--------------------------------------------------------------------------
| 메인 페이지
|--------------------------------------------------------------------------
*/

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

/*
|--------------------------------------------------------------------------
| 로그인 페이지
|--------------------------------------------------------------------------
*/

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

/*
|--------------------------------------------------------------------------
| 대시보드
|--------------------------------------------------------------------------
*/

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

/*
|--------------------------------------------------------------------------
| 설정 페이지
|--------------------------------------------------------------------------
*/

app.get('/settings', (req, res) => {
  res.sendFile(path.join(__dirname, 'settings.html'));
});

/*
|--------------------------------------------------------------------------
| Hello API
|--------------------------------------------------------------------------
*/

app.get('/hello', (req, res) => {
  res.json({
    success: true,
    message: 'Hello Node.js!',
  });
});

/*
|--------------------------------------------------------------------------
| 검색 API
|--------------------------------------------------------------------------
*/

app.get('/search', (req, res) => {
  const keyword = req.query.keyword || '';

  res.json({
    success: true,
    keyword,
    message: '검색 요청이 정상적으로 처리되었습니다.',
  });
});

/*
|--------------------------------------------------------------------------
| 로그인 처리
|--------------------------------------------------------------------------
*/

function loginHandler(req, res) {
  const { username } = req.body;

  writeLog(
    'LOGIN_REQUEST',
    '로그인 요청이 서버에 도착했습니다.',
    req,
    {
      username: username || '',
    }
  );

  res.json({
    success: true,
    username: username || null,
    message: '로그인 요청이 서버에 도착했습니다.',
  });
}

/*
|--------------------------------------------------------------------------
| 로그인 API
|--------------------------------------------------------------------------
*/

app.post('/login', loginRateLimit, loginHandler);

app.post('/api/login', loginRateLimit, loginHandler);

/*
|--------------------------------------------------------------------------
| 로그 조회 API
|--------------------------------------------------------------------------
|
| 전체
| /logs
|
| 타입 검색
| /logs?type=WAF_BLOCK
|
| 로그인 검색
| /logs?type=LOGIN_REQUEST
|
| Rate Limit 검색
| /logs?type=RATE_LIMIT_BLOCK
|
| IP 검색
| /logs?ip=::1
|
|--------------------------------------------------------------------------
*/

app.get('/logs', (req, res) => {
  fs.readFile(LOG_FILE, 'utf8', (error, data) => {
    if (error) {
      console.error('로그 읽기 실패:', error);

      return res.status(500).json({
        success: false,
        message: '로그 파일을 읽을 수 없습니다.',
      });
    }

    const type = req.query.type;
    const ip = req.query.ip;

    let logs = data
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return {
            raw: line,
          };
        }
      });

    /*
    |--------------------------------------------------------------------------
    | 로그 종류 필터
    |--------------------------------------------------------------------------
    */

    if (type) {
      logs = logs.filter((log) => log.type === type);
    }

    /*
    |--------------------------------------------------------------------------
    | IP 필터
    |--------------------------------------------------------------------------
    */

    if (ip) {
      logs = logs.filter((log) => log.ip === ip);
    }

    /*
    |--------------------------------------------------------------------------
    | 최근 100개
    |--------------------------------------------------------------------------
    */

    logs = logs.slice(-100);

    res.json({
      success: true,
      count: logs.length,

      filter: {
        type: type || null,
        ip: ip || null,
      },

      logs,
    });
  });
});

/*
|--------------------------------------------------------------------------
| 로그 통계 함수
|--------------------------------------------------------------------------
*/

function getLogStats(req, res) {
  fs.readFile(LOG_FILE, 'utf8', (error, data) => {
    if (error) {
      console.error('로그 읽기 실패:', error);

      return res.status(500).json({
        success: false,
        message: '로그 파일을 읽을 수 없습니다.',
      });
    }

    const logs = data
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    const stats = {
      total: logs.length,
      wafAllow: 0,
      wafBlock: 0,
      loginRequest: 0,
      loginFail: 0,
      loginSuccess: 0,
      rateLimitBlock: 0,
    };

    /*
    |--------------------------------------------------------------------------
    | 로그 종류별 통계
    |--------------------------------------------------------------------------
    */

    logs.forEach((log) => {
      switch (log.type) {
        case 'WAF_ALLOW':
          stats.wafAllow++;
          break;

        case 'WAF_BLOCK':
          stats.wafBlock++;
          break;

        case 'LOGIN_REQUEST':
          stats.loginRequest++;
          break;

        case 'LOGIN_FAIL':
          stats.loginFail++;
          break;

        case 'LOGIN_SUCCESS':
          stats.loginSuccess++;
          break;

        case 'RATE_LIMIT_BLOCK':
          stats.rateLimitBlock++;
          break;
      }
    });

    res.json({
      success: true,
      stats,
    });
  });
}

/*
|--------------------------------------------------------------------------
| 통계 API
|--------------------------------------------------------------------------
*/

app.get('/logs/stats', getLogStats);

app.get('/stats', getLogStats);

/*
|--------------------------------------------------------------------------
| 404 처리
|--------------------------------------------------------------------------
*/

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: '존재하지 않는 API입니다.',
  });
});

/*
|--------------------------------------------------------------------------
| 서버 실행
|--------------------------------------------------------------------------
*/

app.listen(PORT, () => {
  console.log('====================================');
  console.log(' Security Log Lab');
  console.log(' Node.js + WAF + Rate Limiting');
  console.log('====================================');
  console.log(`Server: http://localhost:${PORT}`);
});