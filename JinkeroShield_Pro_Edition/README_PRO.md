# 🛡️ JWAF — Jinkero Shield Pro AI (Full Defense Suite V2.0.0 PRO AI)

**JWAF (Jinkero Shield Pro AI V2.0)** 는 기존 경량 포터블 방화벽과 별도로 구축된 **Windows 정식 설치형 엔터프라이즈급 개인용 AI 방화벽 · 로컬 WAF · EDR 통합 보안 스위트**입니다.
AI가 디자인한 전용 **JWAF 사이버 쉴드 커스텀 아이콘(`jwaf_icon.ico`)**, 다중 앙상블 머신러닝 연산(Isolation Forest + Markov Chain + Shannon Entropy + N-gram), **자가 발전(Self-Evolving) AI 방어 시스템**, 그리고 **패키지 해킹·변조를 원천 차단하는 HMAC-SHA256 전자서명 및 SHA-256 자가 무결성 보호(Self-Protection) 엔진**을 탑재했습니다.

---

## 🔒 1. 패키지 위변조 방지(Anti-Tampering) 및 시큐어 코딩 아키텍처

1. **머신 귀속 HMAC-SHA256 전자서명 ([`PackageSelfProtectionEngine`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/core/self_protection.py#L14-L52))**:
   - PC 고유 하드웨어 노드 식별자와 보안 솔트를 결합한 머신 귀속 비밀키로 설정 파일(`shield_pro_config.json`) 및 위협 인텔리전스 DB(`ai_threat_intel_db.json`)에 `_hmac_seal` 전자서명을 부여합니다.
   - 해커나 악성코드가 외부에서 설정 파일을 열어 방화벽을 강제로 끄거나 화이트리스트를 변조하면, 로드 즉시 `hmac.compare_digest` 검증이 실패를 감지하여 **변조된 설정을 폐기하고 방화벽 및 AI 엔진을 강제 활성화 상태로 자동 복원**합니다.
2. **실행 패키지 및 코어 모듈 SHA-256 무결성 봉인 (`package_integrity.seal`)**:
   - `JinkeroShieldPro.exe`, `setup.exe`, 코어/UI 모듈 전체의 SHA-256 해시 매니페스트를 생성하고 HMAC-SHA256으로 이중 봉인하여 단 1바이트의 파일 패치나 코드 변조도 즉시 탐지합니다.
   - 런타임 디버거 어태치(`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`) 상시 감시를 통해 메모리 해킹 및 리버스 엔지니어링 시도를 탐지합니다.
3. **전 모듈 시큐어 코딩(Secure Coding) 감사 및 방어 적용**:
   - **OS Command Injection 및 로컬 자가 격리(Self-Lockout) 원천 차단**: [`_sanitize_firewall_ips()`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/core/firewall_manager.py#L24-L40)에서 `ipaddress.ip_network` 검증으로 루프백(`127.0.0.1`), 사설망(`192.168.*`, `10.*`), 멀티캐스트 및 비정상 문자열을 완벽히 필터링하고 `shell=False` 배열 호출만 허용합니다.
   - **WAF Reflected XSS · 대용량 DoS · Open-Proxy/SSRF 방어**: [`LocalWAFProxy`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/core/waf_proxy.py#L11-L185)에서 차단 사유 `html.escape()` 이스케이프, 보안 응답 헤더(`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`), 1MB 페이로드 상한(`413 Payload Too Large`), 5초 소켓 타임아웃(Slowloris 방어), URI 경로 정규화 검증을 적용했습니다.

---

## 🧬 2. 자율 진화 · 자가 발전(Self-Evolving) AI 시스템

1. **신종 변종 공격 시그니처 자율 합성 (`AUTO-EVO-*`)**:
   - 미지의 폴리모픽(Polymorphic) 변종 공격이나 난독화 쉘코드가 앙상블 AI에 의해 포착·차단되면, [`synthesize_rule_from_attack()`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/core/ai_full_engine.py#L260-L306)이 공격 페이로드에서 핵심 위험 토큰을 추출하여 **새로운 방어 규칙(`AUTO-EVO-01`, `AUTO-EVO-02`...)을 즉석에서 자동 생성**하고 위협 DB에 영구 등록합니다.
2. **온라인 Isolation Forest 25-Tree 자가 재학습 ([`retrain_with_online_samples()`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/core/ai_full_engine.py#L60-L71))**:
   - 사용자 PC의 안전한 트래픽 특징 벡터와 안전 문자 전이(Markov Bigram)를 온라인으로 학습하여 25개 Isolation Forest 결정 트리의 분할 경계를 스스로 재보정함으로써 정상 프로그램 오탐을 방지합니다.
3. **악성 C2 서브넷(`/24`) 자율 군집 학습 및 2중 진화 루프**:
   - 백그라운드에서 **매 10분마다 내부 온라인 자가 발전**, **매 6시간마다 글로벌 클라우드 위협 인텔리전스(Abuse.ch Feodo C2 피드 + Adversarial AI 시그니처)**를 자율 동기화하며 진화 세대(`Gen 1.0` → `Gen 2.0`...)를 업그레이드합니다.

---

## 📦 3. 정식 설치(`setup.exe`), 실행(`JinkeroShieldPro.exe`) 및 완전 제거 방법

### ① 설치 파일 실행 (`setup.exe`)
- [`JinkeroShield_Pro_Edition\setup.exe`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/setup.exe) 를 실행하면 **JWAF (Jinkero Shield Pro AI V2.0) Windows 정식 설치 마법사**가 구동됩니다.
- 네이티브 Win32 COM(`IShellLinkW`) 인프로세스 방식으로 **JWAF 커스텀 아이콘**이 적용된 바탕화면/시작메뉴 바로가기를 생성하여 V3 등 백신 오진을 원천 방지합니다.

### ② 본 프로그램 실행 (`JinkeroShieldPro.exe`) 및 완전 제거 (`--uninstall`)
- 바탕화면의 **`JWAF - Jinkero Shield Pro AI`** 바로가기 또는 [`JinkeroShield_Pro_Edition\JinkeroShieldPro.exe`](file:///e:/soamai/localwaf/JinkeroShield_Pro_Edition/JinkeroShieldPro.exe) 를 실행하면 7-탭 엔터프라이즈 방화벽 대시보드가 구동됩니다.
- Windows **제어판(프로그램 추가/제거 / 설치된 앱)** 또는 설치 마법사의 **[🗑️ 기존 설치본 완전 제거]** 버튼을 클릭하면 실행 중인 프로세스 종료, 방화벽 규칙(`Jinkero_Block_Ips`, `Jinkero_Outbound_Block`, `Jinkero_Block_Ports`) 정리, 바로가기/레지스트리 삭제, 설치 폴더(`C:\Program Files\JinkeroShieldPro`)까지 100% 남김없이 완전 삭제됩니다.

---
*All Copyright Reserved by JINKERO 2026*
