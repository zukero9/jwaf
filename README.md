# Jinkero Shield - AI 자율형 개인용 방화벽 & 로컬 WAF (V1.0.2 AI)

Windows 11 환경에 최적화된 온디바이스 AI 기반 고성능 개인용 방화벽 및 인라인 WAF 솔루션입니다.
중국발 금융권 지능형 지속 위협(APT), 제로데이 난독화 웹셸, 랜섬웨어 및 C2 비콘 통신을 로컬 커널(`Jinkero_Block_Ips`)과 애플리케이션 AI 계층에서 다중 방어합니다.

---

## 🌟 핵심 아키텍처 및 주요 기능

### 1. 🤖 온디바이스 AI 자율 방어 엔진 (`core/ai_engine.py`)
- **샤넌 정보 엔트로피($H(X)$) & 문자 N-gram 변종 탐지**: 정적 정규식(Signature)을 우회하기 위해 Base64, Hex, 유니코드 등으로 난독화된 제로데이 웹셸, 변종 SQLi, RCE 페이로드의 엔트로피와 특수기호 밀도를 계산하여 실시간 차단합니다.
- **슬라이딩 윈도우(60초) Z-Score 이상 징후 탐지**: 출발지 IP별 분당 요청 속도, 접근 경로 다양성, 다중 로컬 포트 접근(Port Sweep)을 실시간 프로파일링하여 통계적 이상치(Outlier)를 색출합니다.
- **C2 비콘(Command & Control) 주기성 Jitter 분석**: 악성코드/봇넷이 외부 C2 서버와 일정한 주기로 폴링 통신할 때 나타나는 도착 시간 간격($\Delta t$)의 변동계수($CV = \sigma / \mu$)를 추적하여 기계적 비콘 통신을 탐지합니다.
- **XAI (설명 가능한 AI) 한국어 판정 리포트**: 모든 패킷과 연결에 대해 `0 ~ 100점`의 AI 위협 점수를 부여하고, 왜 차단/경고되었는지 구체적인 한글 사유(예: `고엔트로피 난독화 페이로드(H=5.42 bits), 변종 쉘코드/인젝션 N-gram 패턴`)를 제공합니다.
- **3단계 AI 민감도 모드 지원 (오탐 방지 정밀 튜닝)**:
  - 일반 웹 브라우저, 메신저, 클라우드/CDN 에페메럴(임시, `>=10000`) 포트 통신은 안전하게 통과시키며, 확실한 고위험 공격만 선별 차단합니다.
  - `BALANCED (균형 권장 - 확실한 위협 90점 이상만 차단)`
  - `CONSERVATIVE (보수적 - 초고위험 95점 이상만 차단)`
  - `AGGRESSIVE (공격적 금융보안 - 82점 이상 차단)`

### 2. 🛡️ Windows 방화벽 단일 통합 규칙(`Jinkero_Block_Ips`) 누적 연동
- **커널 레벨 고속 차단**: 수백 개의 개별 규칙이 생성되어 PC가 느려지는 현상을 막기 위해, 모든 차단 IP(BlackIP, 국가 차단 IP, APT/AI 탐지 IP)를 **`Jinkero_Block_Ips`** 단일 마스터 규칙 1개에 쉼표(`,`)로 누적 동기화합니다. (위험 포트는 **`Jinkero_Block_Ports`** 규칙으로 통합 관리)
- **영구 보존 및 재실행 시 자동 복원**: 한 번 탐지·차단된 지능형 침해 시도 및 AI 차단 내역은 `shield_config.json`에 영구 기록되어 프로그램을 재실행해도 그대로 유지되며 Windows 방화벽에 자동 동기화됩니다.
- **비동기 스레드 백그라운드 처리**: 방화벽 명령(`netsh`, PowerShell)을 비동기 워커 스레드로 실행하여 UI 조작 시 렉이나 멈춤 현상이 발생하지 않습니다.
- **규칙 세부 조회 / IP 직접 편집 / 삭제**: `⚙️ 방화벽 설정` 탭에서 `Jinkero_Block_Ips` 규칙에 등록된 IP 목록을 직접 편집하거나 삭제할 수 있습니다.

### 3. 📊 고시인성 실시간 네트워크 모니터링 & 과부하 점멸 경고 (`LiveTrafficChart`)
- **대형 디지털 HUD 수치 전광판**: 차트 상단에 고대비 네온 시안(`⬇ 수신(RX)`), 네온 에메랄드(`⬆ 송신(TX)`), 골드(`⚡ 총 대역폭`) 대형 디지털 수치 배지와 최고 속도(Peak) 기록을 배치하여 한눈에 송수신 속도를 확인할 수 있습니다.
- **우측 끝 실시간 콜아웃 태그**: 그래프 곡선 우측 끝점에 발광 마커와 실시간 수치 태그(`RX ...`, `TX ...`)가 함께 움직이며 직관적인 가시성을 제공합니다.
- **과부하(Heavy Load) 긴급 점멸 알림**: 대규모 트래픽 유입이나 디도스/패킷 인젝션 등으로 12MB/s 이상 급증할 경우 차트 테두리와 경고 배지가 적색/황색으로 긴급 점멸합니다.
- **프로세스별 트래픽 순위 (Top 15)**: PC 내에서 네트워크 연결이 가장 활발한 상위 15개 프로세스를 실시간으로 집계합니다.

### 4. 🌏 국가별 다중 차단 (12개 주요국 프리셋 + 사용자 국가 코드 직접 추가)
- **12개 주요 공격 다발 국가 체크박스 그리드**: 중국(`CN`), 러시아(`RU`), 북한(`KP`), 이란(`IR`), 베트남(`VN`), 인도(`IN`), 브라질(`BR`), 루마니아(`RO`), 우크라이나(`UA`), 벨라루스(`BY`), 나이지리아(`NG`), 파키스탄(`PK`)을 손쉽게 다중 선택할 수 있습니다.
- **사용자 정의 국가 코드(ISO 2자리) 직접 입력 추가**: `US`, `HK`, `NL`, `SG`, `TR` 등 전 세계 모든 2자리 영문 ISO 국가 코드를 사용자가 직접 입력하여 즉시 차단 목록에 추가하거나 해제할 수 있습니다.
- **정밀 GeoIP 판별 (한국 ISP 화이트리스트 + 실시간 API 캐싱)**: 카카오(KakaoTalk `121.53.0.0/16`), KT, SKB, LGU+, 네이버 등 국내 주요 통신사 대역을 사전 보호하고 `ip-api.com` 실시간 조회 및 로컬 캐시(`geoip_cache.json`)를 결합하여 국가 오탐을 원천 방지합니다.

### 5. 🏦 지능형 금융권 특화 방어 및 파일 무결성 감시 (FIM)
- **Log4j JNDI RCE 방어**: `${jndi:ldap...}`, `${jndi:rmi...}` 페이로드 탐지 및 드롭
- **Fastjson 역직렬화 공격 차단**: `@type`을 악용한 원격 코드 실행 차단
- **Spring4Shell & WebShell 방어**: `class.module.classLoader`, `.jsp`, `.asp`, `.php` 등 웹셸 업로드 및 실행 원천 차단
- **외부 조작 및 침투 방어**: Directory Traversal (`../`, `win.ini`), SQL Injection, XSS 및 LoLBin(`certutil`, `bitsadmin`, `powershell`) 악성 명령 실행 차단
- **Windows Hosts 파일 파밍 방어 (FIM)**: 은행/금융 사이트 피싱 유도를 위한 `C:\Windows\System32\drivers\etc\hosts` 파일의 무단 수정을 실시간 감시합니다.

### 6. 🖥️ 모던 UI, 로그 행 클릭 상세 분석 뷰어 & 윈도우 시작 시 자동 트레이 실행
- **로그 행 클릭/더블클릭 상세 분석 기능**:
  - `📋 접근 로그` 표에서 원하는 행을 **단일 클릭**하면 하단 **상세 분석 인스펙터 패널**에 발생 일시, 출발지 IP 및 국가, 대상 프로세스 실행 경로(`exe`), 로컬/원격 포트, AI 위협 점수 및 XAI 판정 사유 전문이 즉시 표시됩니다.
  - 행을 **더블클릭**하거나 `🔎 팝업 창으로 크게 보기` 버튼을 누르면 상세 보안 분석 리포트 팝업 창이 열리며, `✅ 이 IP 차단 해제 & 신뢰(WhiteIP) 등록` 또는 `🚫 이 IP 즉시 차단(BlackIP) 등록`을 원클릭으로 수행할 수 있습니다.
- **클린 모던 KPI 카드**: 대시보드 상단 KPI 카드 클릭 시 전체 트래픽, 차단된 침해 내역 필터, 차단 IP 관리, 방화벽 설정 탭으로 즉시 이동합니다.
- **윈도우 시작 시 자동 실행 (트레이 모드)**: 상단 헤더의 `윈도우 시작 시 자동 실행 (트레이)` 체크박스를 켜면 Windows 레지스트리(`HKCU\...\Run`)에 `--minimized` 옵션으로 등록되어 부팅 시 시스템 트레이에서 조용히 상시 보호를 시작합니다.

---

## 📦 실행 파일 및 매뉴얼 안내

- **공식 릴리즈 실행 파일**: `E:\soamai\localwaf\release\JinkeroShield\JinkeroShield.exe`
- **버전**: `V1.0.2 AI`
- **Windows 방화벽 규칙명**:
  - IP 통합 차단 규칙: **`Jinkero_Block_Ips`**
  - 포트 통합 차단 규칙: **`Jinkero_Block_Ports`**
- **관리자 권한**: Windows 방화벽 커널 규칙을 제어하기 위해 실행 시 자동으로 Windows UAC 승인 창이 표시됩니다.

---

## 🛠️ 소스 코드 구성

- [`main.py`](file:///e:/soamai/localwaf/main.py): 프로그램 진입점, UAC 권한 확인, 트레이 시작(`--minimized`) 및 예외 로깅 처리
- [`core/ai_engine.py`](file:///e:/soamai/localwaf/core/ai_engine.py): 온디바이스 AI 자율 방어 엔진 (샤넌 엔트로피, N-gram, Z-Score, C2 비콘 Jitter 분석, XAI 리포트)
- [`core/config.py`](file:///e:/soamai/localwaf/core/config.py): 영구 설정(`shield_config.json`), Black/White IP, 국가별/침해시도/AI 이상징후 기록 보존
- [`core/firewall_manager.py`](file:///e:/soamai/localwaf/core/firewall_manager.py): Windows 고급 방화벽 단일 규칙(`Jinkero_Block_Ips`, `Jinkero_Block_Ports`) 연동 및 편집
- [`core/geoip.py`](file:///e:/soamai/localwaf/core/geoip.py): 국내 ISP 보호 대역 및 실시간 API + 로컬 캐시 기반 정밀 국가 판별기
- [`core/rules.py`](file:///e:/soamai/localwaf/core/rules.py): 지능형 금융권 APT, 웹셸, RCE 및 인젝션 정규식 탐지 엔진
- [`core/waf_proxy.py`](file:///e:/soamai/localwaf/core/waf_proxy.py): 로컬 HTTP 인라인 WAF 프록시 게이트웨이 (시그니처 + AI 이중 검사)
- [`core/net_monitor.py`](file:///e:/soamai/localwaf/core/net_monitor.py): 활성 네트워크 소켓 감시, AI 소켓 이상 징후 분석, RX/TX 대역폭 및 프로세스 순위 집계
- [`core/file_guard.py`](file:///e:/soamai/localwaf/core/file_guard.py): Windows `hosts` 파일 무단 변조 실시간 감시 (FIM)
- [`core/startup_manager.py`](file:///e:/soamai/localwaf/core/startup_manager.py): Windows 부팅 시 트레이 자동 실행 레지스트리 관리
- [`ui/components.py`](file:///e:/soamai/localwaf/ui/components.py): 실시간 RX/TX 차트(과부하 점멸), 모던 미니멀 KPI 카드, 토글 스위치
- [`ui/main_window.py`](file:///e:/soamai/localwaf/ui/main_window.py): 메인 대시보드, `🤖 AI 자율 방어` 탭, 로그 필터링, 시스템 트레이 제어
- [`ui/material_theme.py`](file:///e:/soamai/localwaf/ui/material_theme.py): Windows 11 Fluent Dark 스타일시트

---
**All Copyright Reserved by JINKERO 2026**
