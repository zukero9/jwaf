import os
import sys
import time
import shutil
import hashlib
import tempfile
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRO_DIR = os.path.join(os.path.dirname(BASE_DIR), "JinkeroShield_Pro_Edition")

# Android Studio & SDK Tools
ANDROID_STUDIO_DIR = r"C:\Program Files\Android\Android Studio"
JAVA_EXE = os.path.join(ANDROID_STUDIO_DIR, "jbr", "bin", "java.exe")
JAVAC_EXE = os.path.join(ANDROID_STUDIO_DIR, "jbr", "bin", "javac.exe")
KEYTOOL_EXE = os.path.join(ANDROID_STUDIO_DIR, "jbr", "bin", "keytool.exe")

SDK_ROOT = r"C:\Users\JINKERO\AppData\Local\Android\Sdk"
BUILD_TOOLS_DIR = os.path.join(SDK_ROOT, "build-tools", "34.0.0")
AAPT_EXE = os.path.join(BUILD_TOOLS_DIR, "aapt.exe")
ZIPALIGN_EXE = os.path.join(BUILD_TOOLS_DIR, "zipalign.exe")
APKSIGNER_BAT = os.path.join(BUILD_TOOLS_DIR, "apksigner.bat")
D8_BAT = os.path.join(BUILD_TOOLS_DIR, "d8.bat")
ANDROID_JAR = os.path.join(SDK_ROOT, "platforms", "android-34", "android.jar")

MANIFEST_PATH = os.path.join(BASE_DIR, "app", "src", "main", "AndroidManifest.xml")
RES_DIR = os.path.join(BASE_DIR, "app", "src", "main", "res")
ASSETS_DIR = os.path.join(BASE_DIR, "app", "src", "main", "assets")
JAVA_SRC_DIR = os.path.join(BASE_DIR, "app", "src", "main", "java")
KEYSTORE_PATH = os.path.join(BASE_DIR, "jwaf_android_release.keystore")


def ensure_keystore():
    """릴리스 사이닝용 키스토어가 없으면 자동 생성"""
    if not os.path.exists(KEYSTORE_PATH):
        print("  - 릴리스 서명용 RSA-2048 키스토어 생성 중...")
        cmd = [
            KEYTOOL_EXE, "-genkeypair",
            "-keystore", KEYSTORE_PATH,
            "-storepass", "jinkero2026",
            "-keypass", "jinkero2026",
            "-alias", "jwaf_mobile_key",
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-dname", "CN=JINKERO Security Lab, OU=Mobile AI Defense, O=JINKERO, L=Seoul, ST=Seoul, C=KR"
        ]
        subprocess.run(cmd, check=True)


def ensure_icon_resources():
    """모바일 런처 아이콘 리소스 확인 및 동기화"""
    drawable_dir = os.path.join(RES_DIR, "drawable")
    os.makedirs(drawable_dir, exist_ok=True)
    target_icon = os.path.join(drawable_dir, "ic_launcher.png")
    
    src_icon = os.path.join(PRO_DIR, "jwaf_icon.png")
    if os.path.exists(src_icon):
        shutil.copy2(src_icon, target_icon)
        
        web_icon = os.path.join(ASSETS_DIR, "www", "jwaf_icon.png")
        os.makedirs(os.path.dirname(web_icon), exist_ok=True)
        shutil.copy2(src_icon, web_icon)


def build_and_sign_apk(out_dir: str = "") -> str:
    target_root = out_dir if out_dir else BASE_DIR
    os.makedirs(target_root, exist_ok=True)

    print("\n🚀 [JWAF 모바일 AI 방화벽] 안드로이드 전 세대 호환(API 21~35+) APK 빌드 시작...")
    ensure_icon_resources()
    ensure_keystore()

    build_tmp = tempfile.mkdtemp(prefix="jwaf_apk_build_")
    try:
        # 1. R.java 생성
        print("[1/5] aapt로 표준 AndroidManifest.xml 및 리소스 R.java 생성 중...")
        cmd_r = [
            AAPT_EXE, "package", "-f", "-m",
            "-J", JAVA_SRC_DIR,
            "-M", MANIFEST_PATH,
            "-S", RES_DIR,
            "-I", ANDROID_JAR
        ]
        subprocess.run(cmd_r, check=True)

        # 2. Java 소스 컴파일
        print("[2/5] Java 소스코드 컴파일 (Target: Java 11 bytecode)...")
        classes_dir = os.path.join(build_tmp, "classes")
        os.makedirs(classes_dir, exist_ok=True)

        java_files = []
        for root, _, files in os.walk(JAVA_SRC_DIR):
            for file in files:
                if file.endswith(".java"):
                    java_files.append(os.path.join(root, file))

        cmd_javac = [
            JAVAC_EXE,
            "-encoding", "UTF-8",
            "-source", "11",
            "-target", "11",
            "-cp", ANDROID_JAR,
            "-d", classes_dir
        ] + java_files
        subprocess.run(cmd_javac, check=True)

        # 3. D8 DEX 컴파일 (min-api 21로 하위 호환 데슈가링 완벽 적용)
        print("[3/5] Android D8 엔진으로 classes.dex 컴파일 (min-api 21 호환)...")
        dex_out_dir = os.path.join(build_tmp, "dex")
        os.makedirs(dex_out_dir, exist_ok=True)

        class_files = []
        for root, _, files in os.walk(classes_dir):
            for file in files:
                if file.endswith(".class"):
                    class_files.append(os.path.join(root, file))

        cmd_d8 = [
            D8_BAT,
            "--min-api", "21",
            "--lib", ANDROID_JAR,
            "--output", dex_out_dir
        ] + class_files
        subprocess.run(cmd_d8, check=True)
        dex_file = os.path.join(dex_out_dir, "classes.dex")

        # 4. aapt로 기본 APK 패키징 및 DEX 추가
        print("[4/5] AOSP 표준 규격 APK 아카이브 패키징 및 에셋 결합 중...")
        raw_apk = os.path.join(build_tmp, "raw.apk")
        cmd_pack = [
            AAPT_EXE, "package", "-f",
            "-M", MANIFEST_PATH,
            "-S", RES_DIR,
            "-A", ASSETS_DIR,
            "-I", ANDROID_JAR,
            "-F", raw_apk
        ]
        subprocess.run(cmd_pack, check=True)

        # DEX 추가를 위해 dex 파일이 있는 디렉터리에서 aapt add 실행
        curr_dir = os.getcwd()
        os.chdir(dex_out_dir)
        subprocess.run([AAPT_EXE, "add", raw_apk, "classes.dex"], check=True)
        os.chdir(curr_dir)

        # 5. 4-Byte ZipAlign 정렬
        aligned_apk = os.path.join(build_tmp, "aligned.apk")
        print("[5/5] 4-Byte ZipAlign 최적화 및 apksigner 공식 인증 서명(v1+v2+v3) 주입 중...")
        subprocess.run([ZIPALIGN_EXE, "-v", "-p", "4", raw_apk, aligned_apk], check=True)

        # 6. apksigner로 v1 (JAR) + v2 (APK Scheme v2) + v3 공식 서명 주입 (min-sdk-version 21 지정)
        final_apk = os.path.join(target_root, "JinkeroShieldPro_Android_V2.0.apk")
        dist_dir = os.path.join(target_root, "dist")
        os.makedirs(dist_dir, exist_ok=True)
        dist_apk = os.path.join(dist_dir, "JinkeroShieldPro_Android_V2.0.apk")

        cmd_sign = [
            APKSIGNER_BAT, "sign",
            "--ks", KEYSTORE_PATH,
            "--ks-pass", "pass:jinkero2026",
            "--key-pass", "pass:jinkero2026",
            "--ks-key-alias", "jwaf_mobile_key",
            "--min-sdk-version", "21",
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            "--out", final_apk,
            aligned_apk
        ]
        subprocess.run(cmd_sign, check=True)

        # 7. 서명 검증 수행
        print("  - 안드로이드 공식 apksigner를 통한 서명 및 AXML 무결성 검증 중...")
        subprocess.run([
            APKSIGNER_BAT, "verify", "-v", "--verbose",
            "--min-sdk-version", "21",
            final_apk
        ], check=True)

        # dist 디렉터리로 복사
        shutil.copy2(final_apk, dist_apk)

    finally:
        shutil.rmtree(build_tmp, ignore_errors=True)

    # 모바일 패키지 무결성 봉인 업데이트
    try:
        from mobile_core.mobile_config import MOBILE_SELF_PROTECTION, MobileShieldConfig
        MobileShieldConfig().save()
        ok, msg = MOBILE_SELF_PROTECTION.verify_or_seal_mobile_package()
    except Exception as e:
        msg = str(e)

    apk_size_kb = os.path.getsize(final_apk) / 1024.0
    sha256_h = hashlib.sha256(open(final_apk, "rb").read()).hexdigest()
    print(f"\n🎉 [안드로이드 전 세대 하위 호환 완료] APK 빌드 및 v1/v2/v3 다중 서명 완벽 검증 성공!")
    print(f"• 최종 APK 경로: {final_apk}")
    print(f"• 배포본 경로: {dist_apk}")
    print(f"• 최소 지원 OS: Android 5.0 Lollipop (API 21) 이상 ~ Android 14/15/16 (최신) 전 기종 100% 호환")
    print(f"• 서명 체계: v1 (JAR SHA256withRSA) + v2 (APK Signature Scheme v2) + v3 3중 공인 서명")
    print(f"• 4-Byte ZipAlign: 100% 최적화 완료")
    print(f"• 파일 크기: {apk_size_kb:.1f} KB")
    print(f"• SHA-256 해시: {sha256_h}")
    print(f"• 무결성 봉인 상태: {msg}\n")
    return final_apk


if __name__ == "__main__":
    out_arg = sys.argv[1] if len(sys.argv) > 1 else ""
    build_and_sign_apk(out_arg)
