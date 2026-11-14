package com.jinkero.shieldpro;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * JWAF (Jinkero Shield Pro AI V2.0) — Android Mobile Edition
 * - 앱 시작 시 실제 Android VpnService 터널 권한 확인 및 백그라운드 패킷 필터 가동
 * - 세로 화면(Portrait) 고정 및 시스템 폰트 배율에 의한 글자 밀림 원천 차단(setTextZoom(100))
 */
public class MainActivity extends Activity {
    private static final int VPN_REQUEST_CODE = 2026;
    private WebView mobileWebView;
    private MobileAiDefenseEngine aiEngine;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_NO_TITLE);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);

        Window window = getWindow();
        if (window != null) {
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.setStatusBarColor(Color.parseColor("#090D16"));
            window.setNavigationBarColor(Color.parseColor("#090D16"));
        }

        aiEngine = new MobileAiDefenseEngine();

        mobileWebView = new WebView(this);
        mobileWebView.setBackgroundColor(Color.parseColor("#090D16"));
        mobileWebView.setOverScrollMode(View.OVER_SCROLL_NEVER);

        WebSettings settings = mobileWebView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setUseWideViewPort(true);
        settings.setLoadWithOverviewMode(true);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);
        settings.setTextZoom(100);

        mobileWebView.setWebViewClient(new WebViewClient());
        mobileWebView.setWebChromeClient(new WebChromeClient());
        mobileWebView.addJavascriptInterface(new JwafMobileBridge(this, aiEngine), "AndroidJwafBridge");

        setContentView(mobileWebView);
        mobileWebView.loadUrl("file:///android_asset/www/index.html");

        // 앱 시작 시 실제 로컬 VPN 방화벽 서비스 준비 및 시작
        requestAndStartVpnService();
    }

    private void requestAndStartVpnService() {
        try {
            Intent intent = VpnService.prepare(this);
            if (intent != null) {
                startActivityForResult(intent, VPN_REQUEST_CODE);
            } else {
                onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
            }
        } catch (Throwable ignored) {
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            Intent svc = new Intent(this, JwafVpnFirewallService.class);
            svc.setAction(JwafVpnFirewallService.ACTION_START_VPN);
            startService(svc);
        }
    }

    @Override
    public void onBackPressed() {
        if (mobileWebView != null && mobileWebView.canGoBack()) {
            mobileWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
