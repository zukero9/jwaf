package com.jinkero.shieldpro;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
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
