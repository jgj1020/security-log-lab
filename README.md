# Security Log Lab

Node.js와 Express를 이용해 웹 요청을 검사하고,
WAF를 직접 구현하면서 보안 로그가 어떻게 생성되고 관리되는지
학습하기 위한 프로젝트입니다.

## 📌 프로젝트 소개

웹 서비스에 들어오는 요청을 WAF에서 검사하고,
정상 요청과 의심스러운 요청을 구분하여 로그로 기록합니다.

기록된 로그는 간단한 보안 관제 Dashboard에서 확인할 수 있도록
구성했습니다.

현재는 로컬 환경에서 보안 로그의 생성과 확인 과정을
직접 구현하며 학습하고 있습니다.

---

## 🏗 현재 구조

```text
Browser
   ↓
Node.js + Express
   ↓
WAF
   ├── 정상 요청 → WAF_ALLOW
   │
   └── 의심 요청 → WAF_BLOCK
                     ↓
                security.log
                     ↓
                 Dashboard

🛡 WAF

WAF는 Web Application Firewall의 약자로,
웹 애플리케이션으로 들어오는 요청을 검사하고
의심스러운 요청을 차단하는 보안 시스템입니다.

이번 프로젝트에서는 학습 목적으로
Node.js와 JavaScript를 이용해 간단한 WAF 기능을 직접 구현했습니다.

현재 검사하는 패턴
SQL Injection
XSS
Path Traversal

의심스러운 요청이 발견되면 요청을 차단하고
보안 로그를 기록합니다.
