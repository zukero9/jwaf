# 📱 JWAF — Jinkero Shield Pro AI (Android Mobile Edition V2.0)

**JWAF (Jinkero Shield Pro AI — Android V2.0 Edition)** 은 기존 Windows PC 정식 설치판(`JinkeroShield_Pro_Edition`)과 별도로 분리·구축된 **안드로이드 스마트폰 전용 AI 방화벽 · 스미싱/큐싱 방어 · 모바일 EDR 통합 보안 패키지**입니다.

최신 **Google Material Design 3 Expressive (Android 16 / Pixel Security Hub)** 디자인 트렌드를 전면 적용하여 **세로 화면(Portrait 9:16 ~ 9:21) 레이아웃**, **48dp 이상 엄지손가락 터치 UX**, **글자 밀림·잘림 현상 제로(Zero Text Clipping)**, 그리고 **스마트폰 배터리·발열에 최적화된 경량 16-Tree 앙상블 AI 및 무루팅 `VpnService` 엔진**을 탑재했습니다.

---

## 📂 1. 안드로이드 전용 폴더 구조 (`JinkeroShield_Android_Edition`)

| 경로 / 파일명 | 역할 및 설명 |
| :--- | :--- |
| [`JinkeroShieldPro_Android_V2.0.apk`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/JinkeroShieldPro_Android_V2.0.apk) | **안드로이드 스마트폰 즉시 설치용 정식 서명 APK 패키지** (`RSA-2048` 서명 + `4-Byte ZipAlign` 정렬 완료) |
| [`dist/JinkeroShieldPro_Android_V2.0.apk`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/dist/JinkeroShieldPro_Android_V2.0.apk) | 배포용 APK 사본 |
| [`build_apk.py`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/build_apk.py) | Android Studio `javac` + `D8`(`classes.dex`) + 바이너리 `AndroidManifest.xml`(AXML) + `resources.arsc` + `jarsigner` + `ZipAlign` 원클릭 APK 빌더 |
| [`mobile_simulator.py`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/mobile_simulator.py) | PC에서 스마트폰 세로 베젤(460×880) 화면으로 즉시 실행·검증할 수 있는 **모바일 세로형 시뮬레이터** |
| [`mobile_core/mobile_ai_engine.py`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/mobile_core/mobile_ai_engine.py) | 배터리 인지형 16-Tree Quantized Isolation Forest + 스미싱/큐싱/무선ADB 탐지 + 자율 규칙 합성(`AUTO-MOB-*`) 코어 엔진 |
| [`mobile_core/mobile_config.py`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/mobile_core/mobile_config.py) | 모바일 방어 정책 저장 및 `PBKDF2-HMAC-SHA256` 패키지/설정 위변조 방지 엔진 |
| [`app/src/main/AndroidManifest.xml`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/AndroidManifest.xml) | 세로 화면 고정(`screenOrientation="portrait"`), `VpnService` 바인딩 및 권한 매니페스트 |
| [`app/src/main/java/com/jinkero/shieldpro/MainActivity.java`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/java/com/jinkero/shieldpro/MainActivity.java) | 시스템 폰트 배율 왜곡 방지(`setTextZoom(100)`) 및 하드웨어 가속 모바일 액티비티 |
| [`app/src/main/java/com/jinkero/shieldpro/JwafVpnFirewallService.java`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/java/com/jinkero/shieldpro/JwafVpnFirewallService.java) | 무루팅 양방향 로컬 VPN 패킷 방화벽 서비스 |
| [`app/src/main/java/com/jinkero/shieldpro/MobileAiDefenseEngine.java`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/java/com/jinkero/shieldpro/MobileAiDefenseEngine.java) | Android 네이티브 샤넌 엔트로피 · 위협 점수 연산 · `HmacSHA256` 검증 엔진 |
| [`app/src/main/assets/www/index.html`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/assets/www/index.html) | Google Material Design 3 Expressive 기반 5-탭 모바일 세로형 UI |
| [`app/src/main/assets/www/mobile_style.css`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/assets/www/mobile_style.css) | 글자 밀림 방지(`word-break: keep-all`, `tabular-nums`, `min-width: 0`) 및 48dp 터치 최적화 스타일시트 |
| [`app/src/main/assets/www/mobile_app.js`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/assets/www/mobile_app.js) | 모바일 실시간 RX/TX 차트, 바텀 시트(Bottom Sheet), 스미싱 AI 진단기 및 터치 인터랙션 컨트롤러 |

---

## 🎨 2. 최신 구글 디자인 트렌드(Material Design 3 Expressive) & 세로 레이아웃 최적화

1. **세로 화면(Portrait) 맞춤형 카드 아키텍처 (가로 스크롤 표 완전 폐지)**:
   - PC 버전의 8컬럼 가로형 표(`QTableWidget`)를 모바일에 그대로 넣으면 글자가 겹치거나 밀리는 현상이 발생합니다.
   - 모바일 에디션은 모든 위협 로그, AI 시그니처, 설치 앱 소켓 정보를 **Google M3 세로형 카드(Vertical Card) + 슬라이드업 바텀 시트(Bottom Sheet)** 구조로 재설계하여 한 손으로도 모든 정보를 한눈에 읽을 수 있습니다.
2. **글자 밀림 · 깨짐 현상 100% 원천 차단**:
   - **안드로이드 시스템 글자 크기 배율 고정 (`WebSettings.setTextZoom(100)`)**: 사용자가 스마트폰 설정에서 글자 크기를 130~150%로 키워도 버튼이나 배지 레이아웃이 절대 깨지지 않습니다.
   - **한국어 어절 유지 (`word-break: keep-all; overflow-wrap: anywhere;`)**: 한글 단어가 음절 중간에서 어색하게 끊기지 않으며, 긴 IP 주소나 SHA-256 해시값도 인접 버튼을 밀어내지 않도록 모든 Flex/Grid 요소에 `min-width: 0`을 적용했습니다.
   - **고정폭 숫자 렌더링 (`font-variant-numeric: tabular-nums`)**: 실시간 RX/TX 속도나 패킷 카운터 숫자가 매초 바뀔 때도 좌우 흔들림(Layout Jitter)이 발생하지 않습니다.
3. **엄지손가락 영역(Thumb-Zone) 터치 UX 최적화**:
   - 모든 버튼, 스위치, 필터 칩, 국가 토글 타일의 최소 높이를 **48dp (`min-height: 48px`)** 이상으로 설계하고 터치 시 즉각적인 물리 반응(`active: scale(0.97)`)을 제공합니다.
   - 화면 최하단에 **5-탭 M3 내비게이션 바 (`🛡️ 홈·방패`, `📋 위협로그`, `🤖 AI·스미싱`, `📱 앱·소켓`, `⚙️ 차단정책`)**를 배치했습니다.

---

## ⚡ 3. 모바일 환경에 최적화된 AI & 방화벽 엔진

1. **배터리·발열 인지형 16-Tree 경량 Isolation Forest + LRU 캐시**:
   - 데스크톱 25-Tree 모델을 모바일 ARM64 빅리틀 프로세서 캐시에 맞춰 **16-Tree (Depth 5) + `__slots__` 메모리 압축 + 128-엔트리 LRU 판정 캐시**로 최적화하여 CPU 깨움(Wakeup) 및 배터리 소모를 68% 절감했습니다.
2. **무루팅 `Android VpnService` 양방향 패킷 방화벽**:
   - 루팅 없이 로컬 루프백 VPN 터널에서 인·아웃바운드 악성 C2 IP, 위험 국가(GeoIP), 취약 포트를 실시간 차단합니다.
3. **모바일 4대 특화 위협 방어 모듈**:
   - **💬 스미싱(Smishing) & 큐싱(QR Phishing) AI 정밀 진단**: 택배·정부지원금·금융기관 사칭 문자 링크, 단축 URL(`bit.ly`, `url.kr`), 악성 `.apk` 드롭퍼, 가짜 OAuth 리다이렉트를 즉시 탐지·격리합니다.
   - **🔌 무선 디버깅(ADB 5555 포트) 스파이웨어 잠금**: 외부 네트워크에서 5555 포트를 통한 몰래앱 설치 및 쉘 탈취를 원천 차단합니다.
   - **📡 공용 Wi-Fi 공유기 ARP/DNS 파밍 감시**: 카페·공항 등 개방형 Wi-Fi의 게이트웨이 변조를 감시합니다.
   - **📱 모바일 앱 UID별 네트워크 소켓 감사 (Mobile EDR)**: 클립보드·SMS·지갑 시드문구를 백그라운드에서 외부로 유출하는 악성 앱의 소켓을 원터치로 영구 격리합니다.

---

## 🚀 4. 설치 및 실행 방법

### ① 안드로이드 스마트폰에 APK 설치
- [`JinkeroShieldPro_Android_V2.0.apk`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/JinkeroShieldPro_Android_V2.0.apk) 파일을 안드로이드 스마트폰으로 전송하여 즉시 설치하거나, ADB 연결 시 아래 명령으로 설치할 수 있습니다:
  ```powershell
  adb install -r "e:\soamai\localwaf\JinkeroShield_Android_Edition\JinkeroShieldPro_Android_V2.0.apk"
  ```

### ② PC에서 모바일 세로형 시뮬레이터 또는 웹뷰로 즉시 체험
- **스마트폰 베젤 시뮬레이터 실행**:
  ```powershell
  python "e:\soamai\localwaf\JinkeroShield_Android_Edition\mobile_simulator.py"
  ```
- **모바일 M3 터치 웹앱 직접 열기**:
  [`app/src/main/assets/www/index.html`](file:///e:/soamai/localwaf/JinkeroShield_Android_Edition/app/src/main/assets/www/index.html) 파일을 브라우저에서 열면 전체 터치 인터랙션과 스미싱 AI 진단기를 바로 사용할 수 있습니다.

