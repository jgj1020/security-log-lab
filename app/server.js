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
| WAF 차단 패턴
|--------------------------------------------------------------------------
| 학습용 간단 WAF
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

  // 터미널에 출력
  console.log(line);

  // security.log에 저장
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
| WAF 적용
|--------------------------------------------------------------------------
*/

app.use(wafMiddleware);

/*
|--------------------------------------------------------------------------
| 기본 API
|--------------------------------------------------------------------------
*/

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Security Log Lab 서버가 정상적으로 실행 중입니다.',
  });
});

/*
|--------------------------------------------------------------------------
| Hello
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
| 로그인 API
|--------------------------------------------------------------------------
*/

app.post('/login', (req, res) => {
  const { username } = req.body;

  res.json({
    success: true,
    username: username || null,
    message: '로그인 요청이 서버에 도착했습니다.',
  });
});

/*
|--------------------------------------------------------------------------
| 로그 조회 API
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

    const logs = data
      .split('\n')
      .filter(Boolean)
      .slice(-100)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return {
            raw: line,
          };
        }
      });

    res.json({
      success: true,
      count: logs.length,
      logs,
    });
  });
});

/*
|--------------------------------------------------------------------------
| 보안 대시보드
|--------------------------------------------------------------------------
|
| 반드시 404 처리보다 위에 있어야 합니다.
|
*/

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

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
  console.log(' Node.js + WAF');
  console.log(' Log File: security.log');
  console.log('====================================');
  console.log(`Server: http://localhost:${PORT}`);
});