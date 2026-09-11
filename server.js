const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3001;

// ============================================================
// 기본 설정
// ============================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
// 파일 경로
// ============================================================

const USERS_FILE = path.join(__dirname, 'users.json');
const SECURITY_LOG_FILE = path.join(__dirname, 'security.log');

// ============================================================
// 보안 정책
// ============================================================

// 한 계정에서 비밀번호를 5번 틀리면 계정 잠금
const MAX_LOGIN_FAILURES = 5;

// 계정 잠금 시간
const ACCOUNT_LOCK_MINUTES = 5;

// 한 IP에서 로그인 실패가 10번 발생하면 IP 차단
const MAX_IP_FAILURES = 10;

// IP 차단 시간
const IP_BLOCK_MINUTES = 10;

// ============================================================
// 메모리 저장소
// ============================================================

// 로그인 세션
const sessions = new Map();

// IP별 로그인 실패 횟수
const ipLoginFailures = new Map();

// IP별 차단 종료 시간
const blockedIps = new Map();

// ============================================================
// 필요한 파일 생성
// ============================================================

function ensureFile(filePath, initialValue) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, initialValue, 'utf8');
  }
}

ensureFile(
  USERS_FILE,
  JSON.stringify(
    {
      users: [],
    },
    null,
    2
  )
);

ensureFile(
  SECURITY_LOG_FILE,
  ''
);

// ============================================================
// 사용자 데이터 읽기
// ============================================================

function readUsers() {
  try {
    const raw = fs.readFileSync(
      USERS_FILE,
      'utf8'
    );

    const data = JSON.parse(raw);

    if (!Array.isArray(data.users)) {
      return {
        users: [],
      };
    }

    return data;
  } catch (error) {
    console.error(
      'users.json 읽기 실패:',
      error
    );

    return {
      users: [],
    };
  }
}

// ============================================================
// 사용자 데이터 저장
// ============================================================

function saveUsers(data) {
  fs.writeFileSync(
    USERS_FILE,
    JSON.stringify(
      data,
      null,
      2
    ),
    'utf8'
  );
}

// ============================================================
// IP 가져오기
// ============================================================

function getClientIp(req) {
  return (
    req.ip ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

// ============================================================
// 보안 로그 기록
// ============================================================

function writeSecurityLog(
  type,
  req,
  extra = {}
) {
  const log = {
    time: new Date().toISOString(),

    type,

    method: req.method,

    path: req.originalUrl,

    ip: getClientIp(req),

    ...extra,
  };

  const line =
    JSON.stringify(log);

  // 터미널 출력
  console.log(line);

  // 파일 저장
  fs.appendFileSync(
    SECURITY_LOG_FILE,
    `${line}\n`,
    'utf8'
  );
}

// ============================================================
// 아이디 검사
// ============================================================

function isValidUsername(username) {
  return /^[a-zA-Z0-9_]{4,20}$/.test(
    username
  );
}

// ============================================================
// 비밀번호 검사
// ============================================================

function isValidPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 8
  );
}

// ============================================================
// 비밀번호 해시
// ============================================================
// Node.js 내장 crypto.scrypt 사용
//
// 비밀번호를 그대로 저장하지 않고
// salt + hash 형태로 저장합니다.
// ============================================================

function hashPassword(password) {
  return new Promise(
    (resolve, reject) => {
      const salt =
        crypto.randomBytes(16)
          .toString('hex');

      crypto.scrypt(
        password,
        salt,
        64,
        (error, derivedKey) => {
          if (error) {
            reject(error);
            return;
          }

          resolve({
            algorithm: 'scrypt',

            salt,

            hash:
              derivedKey.toString(
                'hex'
              ),
          });
        }
      );
    }
  );
}

// ============================================================
// 비밀번호 검증
// ============================================================

function verifyPassword(
  password,
  storedPassword
) {
  return new Promise(
    (resolve, reject) => {
      if (
        !storedPassword ||
        storedPassword.algorithm !==
          'scrypt' ||
        !storedPassword.salt ||
        !storedPassword.hash
      ) {
        resolve(false);
        return;
      }

      crypto.scrypt(
        password,
        storedPassword.salt,
        64,
        (error, derivedKey) => {
          if (error) {
            reject(error);
            return;
          }

          const storedHash =
            Buffer.from(
              storedPassword.hash,
              'hex'
            );

          if (
            storedHash.length !==
            derivedKey.length
          ) {
            resolve(false);
            return;
          }

          const matched =
            crypto.timingSafeEqual(
              storedHash,
              derivedKey
            );

          resolve(matched);
        }
      );
    }
  );
}

// ============================================================
// IP 차단 여부 확인
// ============================================================

function isIpBlocked(ip) {
  const blockedUntil =
    blockedIps.get(ip);

  // 차단 기록 없음
  if (!blockedUntil) {
    return false;
  }

  // 아직 차단 시간 안 끝남
  if (
    blockedUntil > Date.now()
  ) {
    return true;
  }

  // 차단 시간이 끝났다면 초기화
  blockedIps.delete(ip);

  ipLoginFailures.delete(ip);

  return false;
}

// ============================================================
// IP 로그인 실패 횟수 증가
// ============================================================

function registerIpFailure(ip) {
  const currentCount =
    ipLoginFailures.get(ip) ||
    0;

  const newCount =
    currentCount + 1;

  ipLoginFailures.set(
    ip,
    newCount
  );

  return newCount;
}

// ============================================================
// IP 실패 횟수 가져오기
// ============================================================

function getIpFailureCount(ip) {
  return (
    ipLoginFailures.get(ip) ||
    0
  );
}

// ============================================================
// IP 차단
// ============================================================

function blockIp(ip) {
  const blockedUntil =
    Date.now() +
    IP_BLOCK_MINUTES *
      60 *
      1000;

  blockedIps.set(
    ip,
    blockedUntil
  );

  return blockedUntil;
}

// ============================================================
// 세션 생성
// ============================================================

function createSession(username) {
  const token =
    crypto.randomBytes(32)
      .toString('hex');

  sessions.set(token, {
    username,

    createdAt: Date.now(),
  });

  return token;
}

// ============================================================
// 세션 토큰 가져오기
// ============================================================

function getSessionToken(req) {
  const cookie =
    req.headers.cookie || '';

  const sessionCookie =
    cookie
      .split(';')
      .map((item) =>
        item.trim()
      )
      .find((item) =>
        item.startsWith(
          'session='
        )
      );

  if (!sessionCookie) {
    return null;
  }

  return sessionCookie.slice(
    'session='.length
  );
}

// ============================================================
// 로그인 사용자 확인
// ============================================================

function requireLogin(
  req,
  res,
  next
) {
  const token =
    getSessionToken(req);

  if (!token) {
    return res.status(401).json({
      success: false,

      message:
        '로그인이 필요합니다.',
    });
  }

  const session =
    sessions.get(token);

  if (!session) {
    return res.status(401).json({
      success: false,

      message:
        '세션이 만료되었거나 존재하지 않습니다.',
    });
  }

  req.username =
    session.username;

  req.sessionToken =
    token;

  next();
}

// ============================================================
// 회원가입 API
// ============================================================

app.post(
  '/api/signup',
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ''
        ).trim();

      const password =
        String(
          req.body.password || ''
        );

      // ------------------------------------------------------
      // 아이디 검사
      // ------------------------------------------------------

      if (
        !isValidUsername(
          username
        )
      ) {
        writeSecurityLog(
          'SIGNUP_REJECT',
          req,
          {
            username,

            reason:
              'INVALID_USERNAME',
          }
        );

        return res.status(400).json({
          success: false,

          message:
            '아이디는 영문, 숫자, _만 사용할 수 있으며 4~20자여야 합니다.',
        });
      }

      // ------------------------------------------------------
      // 비밀번호 검사
      // ------------------------------------------------------

      if (
        !isValidPassword(
          password
        )
      ) {
        writeSecurityLog(
          'SIGNUP_REJECT',
          req,
          {
            username,

            reason:
              'WEAK_PASSWORD',
          }
        );

        return res.status(400).json({
          success: false,

          message:
            '비밀번호는 8자 이상이어야 합니다.',
        });
      }

      const data =
        readUsers();

      // ------------------------------------------------------
      // 아이디 중복 확인
      // ------------------------------------------------------

      const exists =
        data.users.some(
          (user) =>
            user.username.toLowerCase() ===
            username.toLowerCase()
        );

      if (exists) {
        writeSecurityLog(
          'SIGNUP_REJECT',
          req,
          {
            username,

            reason:
              'USERNAME_EXISTS',
          }
        );

        return res.status(409).json({
          success: false,

          message:
            '이미 존재하는 아이디입니다.',
        });
      }

      // ------------------------------------------------------
      // 비밀번호 해시
      // ------------------------------------------------------

      const passwordData =
        await hashPassword(
          password
        );

      // ------------------------------------------------------
      // 사용자 생성
      // ------------------------------------------------------

      const newUser = {
        username,

        password:
          passwordData,

        loginFailures: 0,

        lockedUntil: null,

        createdAt:
          new Date().toISOString(),

        lastLoginAt: null,
      };

      data.users.push(
        newUser
      );

      saveUsers(data);

      // ------------------------------------------------------
      // 회원가입 성공 로그
      // ------------------------------------------------------

      writeSecurityLog(
        'SIGNUP_SUCCESS',
        req,
        {
          username,
        }
      );

      return res.status(201).json({
        success: true,

        message:
          '회원가입이 완료되었습니다.',
      });
    } catch (error) {
      console.error(
        '회원가입 오류:',
        error
      );

      return res.status(500).json({
        success: false,

        message:
          '회원가입 처리 중 오류가 발생했습니다.',
      });
    }
  }
);

// ============================================================
// 로그인 API
// ============================================================

app.post(
  '/api/login',
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ''
        ).trim();

      const password =
        String(
          req.body.password || ''
        );

      const clientIp =
        getClientIp(req);

      // ------------------------------------------------------
      // 1. IP 차단 확인
      // ------------------------------------------------------

      if (
        isIpBlocked(
          clientIp
        )
      ) {
        const blockedUntil =
          blockedIps.get(
            clientIp
          );

        writeSecurityLog(
          'IP_BLOCKED',
          req,
          {
            username,

            reason:
              'TOO_MANY_LOGIN_ATTEMPTS',

            ipFailures:
              getIpFailureCount(
                clientIp
              ),

            blockedUntil:
              blockedUntil
                ? new Date(
                    blockedUntil
                  ).toISOString()
                : null,
          }
        );

        return res
          .status(429)
          .json({
            success: false,

            message:
              '비정상적인 로그인 시도가 감지되어 현재 IP의 접근이 일시적으로 제한되었습니다.',
          });
      }

      const data =
        readUsers();

      // ------------------------------------------------------
      // 2. 사용자 찾기
      // ------------------------------------------------------

      const user =
        data.users.find(
          (item) =>
            item.username.toLowerCase() ===
            username.toLowerCase()
        );

      // ------------------------------------------------------
      // 3. 존재하지 않는 계정
      // ------------------------------------------------------

      if (!user) {
        const ipFailures =
          registerIpFailure(
            clientIp
          );

        writeSecurityLog(
          'LOGIN_FAIL',
          req,
          {
            username,

            reason:
              'INVALID_CREDENTIALS',

            ipFailures,
          }
        );

        // IP 실패 횟수 확인
        if (
          ipFailures >=
          MAX_IP_FAILURES
        ) {
          const blockedUntil =
            blockIp(
              clientIp
            );

          writeSecurityLog(
            'IP_BLOCKED',
            req,
            {
              username,

              reason:
                'TOO_MANY_LOGIN_ATTEMPTS',

              ipFailures,

              blockedUntil:
                new Date(
                  blockedUntil
                ).toISOString(),
            }
          );

          return res
            .status(429)
            .json({
              success: false,

              message:
                `로그인 시도가 너무 많아 이 IP를 ${IP_BLOCK_MINUTES}분간 제한했습니다.`,
            });
        }

        return res
          .status(401)
          .json({
            success: false,

            message:
              '아이디 또는 비밀번호가 올바르지 않습니다.',
          });
      }

      // ------------------------------------------------------
      // 4. 계정 잠금 확인
      // ------------------------------------------------------

      if (
        user.lockedUntil
      ) {
        const lockedUntil =
          new Date(
            user.lockedUntil
          ).getTime();

        // 아직 잠겨 있음
        if (
          lockedUntil >
          Date.now()
        ) {
          const remainingSeconds =
            Math.ceil(
              (lockedUntil -
                Date.now()) /
                1000
            );

          writeSecurityLog(
            'LOGIN_BLOCKED',
            req,
            {
              username:
                user.username,

              reason:
                'ACCOUNT_LOCKED',

              lockedUntil:
                user.lockedUntil,
            }
          );

          return res
            .status(423)
            .json({
              success: false,

              message:
                `계정이 잠겨 있습니다. 약 ${remainingSeconds}초 후 다시 시도하세요.`,
            });
        }

        // 잠금 시간이 끝난 경우
        user.lockedUntil =
          null;

        user.loginFailures =
          0;

        saveUsers(data);
      }

      // ------------------------------------------------------
      // 5. 비밀번호 확인
      // ------------------------------------------------------

      const passwordCorrect =
        await verifyPassword(
          password,
          user.password
        );

      // ------------------------------------------------------
      // 6. 비밀번호 실패
      // ------------------------------------------------------

      if (
        !passwordCorrect
      ) {
        user.loginFailures +=
          1;

        const ipFailures =
          registerIpFailure(
            clientIp
          );

        // ====================================================
        // 계정 잠금
        // ====================================================

        if (
          user.loginFailures >=
          MAX_LOGIN_FAILURES
        ) {
          const lockedUntil =
            new Date(
              Date.now() +
                ACCOUNT_LOCK_MINUTES *
                  60 *
                  1000
            );

          user.lockedUntil =
            lockedUntil.toISOString();

          saveUsers(data);

          writeSecurityLog(
            'ACCOUNT_LOCKED',
            req,
            {
              username:
                user.username,

              reason:
                'TOO_MANY_LOGIN_FAILURES',

              failures:
                user.loginFailures,

              ipFailures,

              lockedUntil:
                user.lockedUntil,
            }
          );

          // IP도 기준에 도달했다면 차단
          if (
            ipFailures >=
            MAX_IP_FAILURES
          ) {
            const blockedUntil =
              blockIp(
                clientIp
              );

            writeSecurityLog(
              'IP_BLOCKED',
              req,
              {
                username:
                  user.username,

                reason:
                  'TOO_MANY_LOGIN_ATTEMPTS',

                ipFailures,

                blockedUntil:
                  new Date(
                    blockedUntil
                  ).toISOString(),
              }
            );
          }

          return res
            .status(423)
            .json({
              success: false,

              message:
                `로그인 실패가 ${MAX_LOGIN_FAILURES}회 발생하여 계정을 ${ACCOUNT_LOCK_MINUTES}분간 잠갔습니다.`,
            });
        }

        saveUsers(data);

        writeSecurityLog(
          'LOGIN_FAIL',
          req,
          {
            username:
              user.username,

            reason:
              'INVALID_PASSWORD',

            failures:
              user.loginFailures,

            ipFailures,
          }
        );

        // ====================================================
        // IP 차단
        // ====================================================

        if (
          ipFailures >=
          MAX_IP_FAILURES
        ) {
          const blockedUntil =
            blockIp(
              clientIp
            );

          writeSecurityLog(
            'IP_BLOCKED',
            req,
            {
              username:
                user.username,

              reason:
                'TOO_MANY_LOGIN_ATTEMPTS',

              ipFailures,

              blockedUntil:
                new Date(
                  blockedUntil
                ).toISOString(),
            }
          );

          return res
            .status(429)
            .json({
              success: false,

              message:
                `로그인 시도가 너무 많아 이 IP를 ${IP_BLOCK_MINUTES}분간 제한했습니다.`,
            });
        }

        const accountRemaining =
          MAX_LOGIN_FAILURES -
          user.loginFailures;

        return res
          .status(401)
          .json({
            success: false,

            message:
              `비밀번호가 올바르지 않습니다. 계정 남은 시도: ${accountRemaining}회`,
          });
      }

      // ------------------------------------------------------
      // 7. 로그인 성공
      // ------------------------------------------------------

      user.loginFailures =
        0;

      user.lockedUntil =
        null;

      user.lastLoginAt =
        new Date().toISOString();

      saveUsers(data);

      // 정상 로그인했으므로 해당 IP 실패 기록 초기화
      ipLoginFailures.delete(
        clientIp
      );

      // ------------------------------------------------------
      // 세션 생성
      // ------------------------------------------------------

      const sessionToken =
        createSession(
          user.username
        );

      // ------------------------------------------------------
      // HttpOnly 쿠키
      // ------------------------------------------------------

      res.setHeader(
        'Set-Cookie',
        `session=${sessionToken}; HttpOnly; Path=/; SameSite=Lax`
      );

      // ------------------------------------------------------
      // 성공 로그
      // ------------------------------------------------------

      writeSecurityLog(
        'LOGIN_SUCCESS',
        req,
        {
          username:
            user.username,
        }
      );

      return res.json({
        success: true,

        message:
          '로그인에 성공했습니다.',

        username:
          user.username,
      });
    } catch (error) {
      console.error(
        '로그인 오류:',
        error
      );

      return res.status(500).json({
        success: false,

        message:
          '로그인 처리 중 오류가 발생했습니다.',
      });
    }
  }
);

// ============================================================
// 로그아웃
// ============================================================

app.post(
  '/api/logout',
  (req, res) => {
    const token =
      getSessionToken(req);

    if (token) {
      const session =
        sessions.get(token);

      sessions.delete(token);

      writeSecurityLog(
        'LOGOUT',
        req,
        {
          username:
            session?.username ||
            null,
        }
      );
    } else {
      writeSecurityLog(
        'LOGOUT',
        req
      );
    }

    res.setHeader(
      'Set-Cookie',
      'session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'
    );

    return res.json({
      success: true,

      message:
        '로그아웃되었습니다.',
    });
  }
);

// ============================================================
// 현재 로그인 사용자
// ============================================================

app.get(
  '/api/me',
  requireLogin,
  (req, res) => {
    return res.json({
      success: true,

      username:
        req.username,
    });
  }
);

// ============================================================
// 보호된 API
// ============================================================

app.get(
  '/api/protected',
  requireLogin,
  (req, res) => {
    return res.json({
      success: true,

      message:
        `${req.username}님, 보호된 API에 접근했습니다.`,
    });
  }
);

// ============================================================
// 보안 로그 조회
// ============================================================

app.get(
  '/api/security-logs',
  (req, res) => {
    try {
      const raw =
        fs.readFileSync(
          SECURITY_LOG_FILE,
          'utf8'
        );

      const logs =
        raw
          .split('\n')
          .filter(Boolean)
          .slice(-100)
          .map((line) => {
            try {
              return JSON.parse(
                line
              );
            } catch {
              return {
                raw: line,
              };
            }
          });

      return res.json({
        success: true,

        count:
          logs.length,

        logs,
      });
    } catch (error) {
      console.error(
        '보안 로그 읽기 오류:',
        error
      );

      return res.status(500).json({
        success: false,

        message:
          '보안 로그를 읽을 수 없습니다.',
      });
    }
  }
);

// ============================================================
// IP 상태 확인 API
// ============================================================

app.get(
  '/api/security-status',
  (req, res) => {
    const ip =
      getClientIp(req);

    const blocked =
      isIpBlocked(ip);

    const failureCount =
      getIpFailureCount(ip);

    const blockedUntil =
      blockedIps.get(ip);

    return res.json({
      success: true,

      ip,

      blocked,

      failureCount,

      blockedUntil:
        blockedUntil
          ? new Date(
              blockedUntil
            ).toISOString()
          : null,

      policy: {
        maxIpFailures:
          MAX_IP_FAILURES,

        blockMinutes:
          IP_BLOCK_MINUTES,
      },
    });
  }
);

// ============================================================
// 메인 화면
// ============================================================

app.get(
  '/',
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );
  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,

      message:
        '존재하지 않는 경로입니다.',
    });
  }
);

// ============================================================
// 서버 실행
// ============================================================

app.listen(
  PORT,
  () => {
    console.log(
      '========================================'
    );

    console.log(
      ' Secure Login Lab'
    );

    console.log(
      ' Node.js + Express + scrypt'
    );

    console.log(
      ' Account + IP Protection'
    );

    console.log(
      '========================================'
    );

    console.log(
      `http://localhost:${PORT}`
    );
  }
);