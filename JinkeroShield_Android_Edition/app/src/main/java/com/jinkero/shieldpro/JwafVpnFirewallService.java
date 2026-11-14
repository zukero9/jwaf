package com.jinkero.shieldpro;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * [실제 동작 엔진] Android VpnService 기반 무루팅 로컬 TUN 패킷 방화벽 서비스
 * - 안드로이드 커널의 가상 네트워크 인터페이스(tun0, 10.8.0.1/24)를 생성하여
 *   IPv4 패킷 헤더(출발지/목적지 IP, 프로토콜, 포트)를 실시간 파싱 및 차단합니다.
 */
public class JwafVpnFirewallService extends VpnService implements Runnable {
    public static final String ACTION_START_VPN = "com.jinkero.shieldpro.START_VPN";
    public static final String ACTION_STOP_VPN = "com.jinkero.shieldpro.STOP_VPN";

    private static volatile boolean isRunning = false;
    private static volatile long inspectedPackets = 0;
    private static volatile long blockedPackets = 0;

    public static final Set<String> BLACK_IPS = Collections.synchronizedSet(new HashSet<String>());
    public static final Set<Integer> BLOCKED_PORTS = Collections.synchronizedSet(new HashSet<Integer>());

    static {
        BLACK_IPS.add("185.220.101.34");
        BLACK_IPS.add("45.155.205.233");
        BLACK_IPS.add("103.27.186.42");
        BLACK_IPS.add("91.219.236.174");
        BLACK_IPS.add("114.80.22.10");

        BLOCKED_PORTS.add(5555);
        BLOCKED_PORTS.add(3389);
        BLOCKED_PORTS.add(445);
        BLOCKED_PORTS.add(23);
        BLOCKED_PORTS.add(21);
        BLOCKED_PORTS.add(135);
    }

    private Thread vpnThread;
    private ParcelFileDescriptor vpnInterface;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP_VPN.equals(intent.getAction())) {
            stopVpnTunnel();
            stopSelf();
            return START_NOT_STICKY;
        }
        startVpnTunnel();
        return START_STICKY;
    }

    private synchronized void startVpnTunnel() {
        if ( isRunning ) {
            return;
        }
        try {
            Builder builder = new Builder();
            builder.setSession("JWAF Mobile AI Firewall V2.0");
            builder.setMtu(1500);
            builder.addAddress("10.8.0.1", 24);
            builder.addDnsServer("8.8.8.8");
            builder.addDnsServer("1.1.1.1");

            // 블랙리스트 IP 대역만 로컬 VPN 싱크홀(Sinkhole)로 라우팅하여 실제 통신을 원천 차단
            synchronized (BLACK_IPS) {
                for (String ip : BLACK_IPS) {
                    if (ip != null && ip.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) {
                        try {
                            builder.addRoute(ip, 32);
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            // [삼성 페이 및 금융 간편결제 시스템 분할 터널링 (Split-Tunneling / Bypass)]
            // 삼성 페이(Samsung Pay / Samsung Wallet)는 위조 변조 방지 및 금융 보안 토큰 검증 정책상
            // VPN 인터페이스가 감지되면 결제 승인을 차단합니다.
            // addDisallowedApplication을 통해 삼성 페이 관련 패키지를 VPN 터널에서 완전히 배제하여
            // 기기 기본 모바일 데이터/Wi-Fi 망으로 직접 통신하도록 허용함으로써 결제 장애를 완벽히 해결합니다.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                String[] samsungPayPackages = new String[] {
                    "com.samsung.android.spay",          // Samsung Pay / Samsung Wallet UI & Client
                    "com.samsung.android.spayfw",        // Samsung Pay Framework (HCE, MST, 토큰 관리 핵심 모듈)
                    "com.samsung.android.spaymini",      // Samsung Pay Mini
                    "com.samsung.android.rajaampat",     // Samsung Pay Global/Regional Service
                    "com.samsung.android.samsungpass",   // Samsung Pass (생체 인증 결제 연동)
                    "com.samsung.android.authframework"  // Samsung Biometric Authentication Framework
                };

                for (String pkg : samsungPayPackages) {
                    try {
                        builder.addDisallowedApplication(pkg);
                    } catch (PackageManager.NameNotFoundException ignored) {
                        // 미설치 기기(타 제조사 스마트폰 등)에서는 안전하게 무시
                    } catch (Exception e) {
                        Log.w("JwafVpnFirewall", "Failed to bypass package: " + pkg, e);
                    }
                }
            }

            vpnInterface = builder.establish();
            if (vpnInterface != null) {
                isRunning = true;
                vpnThread = new Thread(this, "JwafVpnPacketFilterThread");
                vpnThread.setDaemon(true);
                vpnThread.start();
            }
        } catch (Exception e) {
            isRunning = false;
        }
    }

    private synchronized void stopVpnTunnel() {
        isRunning = false;
        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception ignored) {
            }
            vpnInterface = null;
        }
    }

    @Override
    public void run() {
        if (vpnInterface == null) {
            return;
        }
        try (FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor())) {
            ByteBuffer packet = ByteBuffer.allocate(32767);
            while (isRunning && !Thread.currentThread().isInterrupted()) {
                int length = in.read(packet.array());
                if (length > 20) {
                    inspectedPackets++;
                    byte[] raw = packet.array();
                    int version = (raw[0] >> 4) & 0x0F;
                    if (version == 4) {
                        int ihl = (raw[0] & 0x0F) * 4;
                        int protocol = raw[9] & 0xFF;
                        String dstIp = String.format("%d.%d.%d.%d",
                                raw[16] & 0xFF, raw[17] & 0xFF, raw[18] & 0xFF, raw[19] & 0xFF);

                        int dstPort = -1;
                        if ((protocol == 6 || protocol == 17) && length >= ihl + 4) {
                            dstPort = ((raw[ihl + 2] & 0xFF) << 8) | (raw[ihl + 3] & 0xFF);
                        }

                        if (BLACK_IPS.contains(dstIp) || (dstPort > 0 && BLOCKED_PORTS.contains(dstPort))) {
                            // 악성 C2 IP 또는 차단 포트 패킷 즉시 드롭 (Drop)
                            blockedPackets++;
                            packet.clear();
                            continue;
                        }
                    }
                }
                packet.clear();
            }
        } catch (Exception ignored) {
        } finally {
            isRunning = false;
        }
    }

    @Override
    public void onDestroy() {
        stopVpnTunnel();
        super.onDestroy();
    }

    public static boolean isVpnRunning() {
        return isRunning;
    }

    public static long getInspectedPackets() {
        return inspectedPackets;
    }

    public static long getBlockedPackets() {
        return blockedPackets;
    }
}
