# 🛡️ JWAF (Jinkero Shield & Local WAF Suite)

[![Platform](https://img.shields.io/badge/Platform-Windows%2011%20%7C%20Android%205.0%2B-blue?style=flat-square&logo=windows)](https://github.com/zukero9/jwaf)
[![Python](https://img.shields.io/badge/Python-3.13%2B-brightgreen?style=flat-square&logo=python)](https://github.com/zukero9/jwaf)
[![License](https://img.shields.io/badge/Security-Enterprise%20AI%20EDR-orange?style=flat-square)](https://github.com/zukero9/jwaf)

Windows 11 및 Android 전 세대 기기에 최적화된 **온디바이스 AI 자율형 개인용 방화벽, 로컬 WAF 및 EDR 스위트**입니다.  
중국발 금융권 지능형 지속 위협(APT), 제로데이 난독화 웹셸, 랜섬웨어 및 C2 비콘 통신을 로컬 커널 단일 마스터 규칙(`Jinkero_Block_Ips`)과 다중 계층 앙상블 AI 엔진으로 차단합니다.

---

## 📥 다운로드 (Official Releases)

깃허브 저장소에서 빌드 완료된 공식 바이너리를 즉시 다운로드하여 실행할 수 있습니다.

| 구분 | 플랫폼 / 에디션 | 파일명 | 다운로드 링크 | 설명 |
| :--- | :--- | :--- | :---: | :--- |
| **단독 실행 (포터블)** | Windows 10/11 (64-bit) | `JinkeroShield.exe` | [⬇️ 다운로드 (EXE)](https://raw.githubusercontent.com/zukero9/jwaf/main/release/JinkeroShield.exe) | 설치 없이 즉시 실행 가능한 **One-file 단독 실행 파일** (Python/PyQt6 DLL 내장) |
| **포터블 압축본** | Windows 10/11 (64-bit) | `JinkeroShield_Single_v1.0.2.zip` | [⬇️ 다운로드 (ZIP)](https://raw.githubusercontent.com/zukero9/jwaf/main/release/JinkeroShield_Single_v1.0.2.zip) | 방화벽 단독 실행 파일 배포용 ZIP 압축본 |
| **설치형 마법사 (Pro)** | Windows 10/11 (64-bit) | `setup.exe` | [⬇️ 다운로드 (EXE)](https://raw.githubusercontent.com/zukero9/jwaf/main/JinkeroShield_Pro_Edition/setup.exe) | 자가 발전 AI, EDR 킬스위치, 바로가기/자동실행을 지원하는 **Windows 정식 설치 마법사** |
| **프로 에디션 실행 파일** | Windows 10/11 (64-bit) | `JinkeroShieldPro.exe` | [⬇️ 다운로드 (EXE)](https://raw.githubusercontent.com/zukero9/jwaf/main/JinkeroShield_Pro_Edition/JinkeroShieldPro.exe) | JWAF Pro 엔터프라이즈 AI 방화벽 & EDR 실행 바이너리 |
| **안드로이드 모바일** | Android 5.0 Lollipop ~ 16+ | `JinkeroShieldPro_Android_V2.0.apk` | [⬇️ 다운로드 (APK)](https://raw.githubusercontent.com/zukero9/jwaf/main/JinkeroShield_Android_Edition/JinkeroShieldPro_Android_V2.0.apk) | **v1+v2+v3 다중 공인 서명** 적용, 무루팅 로컬 VPN 패킷 방화벽 모바일 앱 |

> 💡 **참고**:
> - Windows 방화벽 커널 규칙 조작을 위해 최초 실행 시 Windows UAC 관리자 권한 승인 창이 표시됩니다.
> - 모바일 APK는 구형 기기(API 21+)부터 최신 Android 14/15/16까지 100% 호환 설치를 지원합니다.

---

## 🌟 주요 핵심 기능

### 1. 🤖 온디바이스 AI 자율 방어 엔진
- **샤넌 정보 엔트로피($H(X)$) & N-gram 변종 탐지**: Base64, Hex 등으로 난독화된 제로데이 웹셸, SQLi, RCE 페이로드를 실시간 수학적 엔트로피 계산으로 차단
- **슬라이딩 윈도우(60초) Z-Score 이상 징후 감지**: 비정상 패킷 급증, 다중 포트 스윕(Port Sweep) 통계적 이상치 색출
- **C2 비콘 Jitter 주기성 추적**: 악성코드의 외부 C2 통신 주기 간격($\Delta t$) 변동계수($CV = \sigma / \mu$)를 분석하여 봇넷 비콘 차단
- **XAI (설명 가능한 AI) 한국어 리포트**: 패킷별 0~100점의 위협 점수와 명확한 한글 판정 사유 제시

### 2. 🛡️ Windows 방화벽 커널 단일 규칙(`Jinkero_Block_Ips`) 누적 연동
- 수백 개의 개별 규칙 생성을 방지하여 PC 성능 저하 없이 **`Jinkero_Block_Ips`** 단일 마스터 규칙에 차단 IP를 쉼표(`,`)로 실시간 누적
- 재부팅 시에도 영구 보존 및 자동 동기화
- 비동기 백그라운드 워커 스레드로 GUI 멈춤(Freezing) 제로

### 3. 📊 고시인성 반응형 실시간 트래픽 HUD & 점멸 경고
- 창 크기 변경에 따라 상단 RX/TX HUD 배지 및 테이블 컬럼이 유동적으로 자동 재배치
- 12MB/s 이상 과부하 발생 시 긴급 적색/황색 점멸 알림

### 4. 🌏 국가별 다중 차단 (12개국 프리셋 + ISO 코드 직접 추가)
- 중국(`CN`), 러시아(`RU`), 북한(`KP`), 이란(`IR`) 등 12개 주요 공격 다발국가 원클릭 차단
- 사용자 정의 ISO 국가 코드(HK, US, NL 등) 자유 추가
- 국내 주요 통신사(KT, SKB, LGU+, 카카오) 화이트리스트 및 실시간 GeoIP 캐싱으로 오탐 방지

### 5. 📱 모바일 안드로이드 에디션 (`JinkeroShield_Android_Edition`)
- 무루팅 Android `VpnService` 기반 양방향 TUN 패킷 필터링
- Android 5.0 (API 21) ~ Android 16+ 전 세대 하위 호환
- v1 (JAR SHA256withRSA) + v2 (APK Signature Scheme v2) + v3 3중 공인 서명 완료

---

## 🛠️ 프로젝트 디렉터리 구성

```text
├── core/                           # WAF 프록시, AI 엔진, GeoIP, 방화벽 관리 코어 모듈
├── ui/                             # 반응형 모던 Fluent Dark UI 및 고시인성 HUD 컴포넌트
├── main.py                         # Windows 포터블 방화벽 진입점
├── JinkeroShield.spec              # One-file 단독 실행 바이너리 PyInstaller 스펙
├── release/                        # 단독 포터블 실행 파일 및 배포 ZIP 아카이브
│   ├── JinkeroShield.exe           # 단독 실행 바이너리 (36.2 MB)
│   └── JinkeroShield_Single_v1.0.2.zip
├── JinkeroShield_Pro_Edition/      # 엔터프라이즈 AI 방화벽, EDR 킬스위치 및 설치 마법사
│   ├── JinkeroShieldPro.exe        # Pro 실행 파일
│   ├── setup.exe                   # Windows 정식 설치 마법사
│   └── setup_wizard.py
├── JinkeroShield_Android_Edition/  # 안드로이드 모바일 AI 방화벽 (API 21~35+)
│   ├── JinkeroShieldPro_Android_V2.0.apk  # 설치용 APK
│   └── build_apk.py                # AOSP 표준 aapt + D8 빌드 파이프라인
├── admin_manifest.xml              # Windows UAC 관리자 권한 매니페스트
└── jwaf_icon.ico                   # 고화질 방화벽 쉴드 아이콘
```

---

## 📄 라이선스 및 저작권
**All Copyright Reserved by JINKERO 2026**
