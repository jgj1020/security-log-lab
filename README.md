## 🏗 서비스 실행 구조

![Secure Login Lab 서비스 실행 구조](./docs/architecture.png)

### 동작 흐름

사용자
→ Node.js + Express
→ 로그인 인증 및 보안 검사
→ users.json 데이터 조회/저장
→ security.log 보안 이벤트 기록

### 주요 보안 기능

- 비밀번호 `scrypt` 해시
- 로그인 실패 횟수 관리
- 계정 5회 실패 시 잠금
- IP 로그인 실패 횟수 추적
- IP 10회 실패 시 임시 차단
- HttpOnly 쿠키 기반 세션 관리
- 로그인 및 보안 이벤트 로그 기록
