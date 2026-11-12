package io.umbral;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;

/**
 * 打开模块自带的界面（webroot/index.html）。
 *
 * ══════════════════════════════════════════════════════
 *  为什么需要（M3）
 * ══════════════════════════════════════════════════════
 *
 *  KernelSU 里点模块的「执行」时，很多模块（Zygisk Next、各种配置模块）
 *  会弹出一个自己的界面 —— 那是模块自带的 WebUI：
 *
 *      /data/adb/modules/<id>/webroot/index.html
 *
 *  KSU 的做法是：ksud 起一个本地 http 服务指向 webroot，再用 WebView 打开。
 *  我们没有常驻 ksud，所以用更直接的方式：直接用 WebView 加载
 *  file:// 路径 —— 对大多数只做「读配置 / 写开关」的模块够用。
 *
 *  需要 http 起步的模块（要 fetch 后端）我们暂不支持，会在标题上标出来。
 */
public class ModuleWebUiActivity extends Activity {

    private static final String EXTRA_ID = "module_id";

    /** 关界面即停服务：省电、少暴露端口 */
    private WebUiServer server;

    /** 异步 exec 回调要用它 evaluateJavascript */
    private WebView webView;

    @Override
    protected void onDestroy() {
        try {
            if (server != null) {
                server.stop();
            }
        } catch (Throwable ignored) {
        }
        super.onDestroy();
    }

    public static void start(Context ctx, String moduleId) {
        Intent i = new Intent(ctx, ModuleWebUiActivity.class);
        i.putExtra(EXTRA_ID, moduleId);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        ctx.startActivity(i);
    }

    /** webroot 里有没有可打开的页面 */
    public static File indexOf(String moduleId) {
        File idx = new File(new File(new File("/data/adb/modules", moduleId), "webroot"),
                "index.html");
        return idx.exists() ? idx : null;
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        String id = getIntent() == null ? null : getIntent().getStringExtra(EXTRA_ID);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText(id == null ? "模块界面" : (id + " · 模块自带界面"));
        title.setTextSize(14);
        title.setTextColor(Color.parseColor("#1A1A1A"));
        int pad = (int) (getResources().getDisplayMetrics().density * 12);
        title.setPadding(pad, pad, pad, pad);
        root.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        File idx = id == null ? null : indexOf(id);
        if (idx == null) {
            TextView tv = new TextView(this);
            tv.setText("这个模块没有自带界面（webroot/index.html 不存在）。\n\n"
                    + "它的 action.sh 输出已经在上一步的日志里了。");
            tv.setTextSize(13);
            tv.setPadding(pad, pad, pad, pad);
            root.addView(tv, new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            setContentView(root);
            return;
        }

        /*
         * 起本地 http 服务（零3）：file:// 没有 origin，页面里 fetch 会失败；
         * 起了 http 之后 origin = http://127.0.0.1:<port>，模块页才能正常工作。
         */
        WebUiServer srv = new WebUiServer(idx.getParentFile());
        int port = srv.start();
        this.server = srv;
        final String url = port > 0
                ? ("http://127.0.0.1:" + port + "/index.html")
                : ("file://" + idx.getAbsolutePath());
        if (port <= 0) {
            title.setText(id + " · 模块界面（本地服务启动失败，退回 file://）");
        }

        WebView wv = new WebView(this);
        this.webView = wv;
        WebSettings ws = wv.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setAllowFileAccessFromFileURLs(true);
        ws.setAllowUniversalAccessFromFileURLs(true);
        wv.setWebViewClient(new WebViewClient());

        /*
         * ★ 页面调用的桥 —— 名字就叫 umbral ★
         *
         * 这里刻意**不**定义 window.ksu。
         * 模块页属于我们的生态，就该调我们自己的名字；
         * 把 ksu 映射进来等于冒充别人的接口，一旦对方改签名我们就会静默崩。
         *
         * 对外暴露的 API（模块页里这样用）：
         *   umbral.exec("id -u", function(code, out){ ... })
         *   umbral.execSync("id -u")            → 直接返回字符串
         *   umbral.toast("已保存")
         *   umbral.moduleId()                   → 当前模块 id
         */
        wv.addJavascriptInterface(new WebUiBridge(id), "umbral");
        wv.loadUrl(url);
        root.addView(wv, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    /** 模块页 JS 桥。方法名会被 WebView 暴露成 window.umbral.<方法名> */
    public class WebUiBridge {

        private final String moduleId;

        WebUiBridge(String moduleId) {
            this.moduleId = moduleId;
        }

        /** 同步执行，直接返回输出（页面里用起来最省事） */
        @android.webkit.JavascriptInterface
        public String execSync(String cmd) {
            try {
                io.umbral.sk.SuBridge.R r =
                        io.umbral.sk.SuBridge.root(cmd, 120000);
                return r.out == null ? "" : r.out;
            } catch (Throwable t) {
                return "ERROR: " + t;
            }
        }

        /**
         * 异步执行：umbral.exec(cmd, function(code, stdout, stderr){})
         *
         * 回调要在 UI 线程执行，所以这里起线程跑完再 evaluateJavascript 回去。
         */
        @android.webkit.JavascriptInterface
        public void exec(final String cmd, final String callbackName) {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    int code = -1;
                    String out = "";
                    String err = "";
                    try {
                        io.umbral.sk.SuBridge.R r =
                                io.umbral.sk.SuBridge.root(cmd, 120000);
                        out = r.out == null ? "" : r.out;
                        code = r.code;
                    } catch (Throwable t) {
                        err = String.valueOf(t);
                    }
                    final String js = "try{(" + callbackName + ")(" + code + ","
                            + jsStr(out) + "," + jsStr(err) + ")}catch(e){}";
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (webView != null) {
                                webView.evaluateJavascript(js, null);
                            }
                        }
                    });
                }
            }).start();
        }

        @android.webkit.JavascriptInterface
        public void toast(final String msg) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    android.widget.Toast.makeText(ModuleWebUiActivity.this,
                            msg, android.widget.Toast.LENGTH_SHORT).show();
                }
            });
        }

        @android.webkit.JavascriptInterface
        public String moduleId() {
            return moduleId == null ? "" : moduleId;
        }

        @android.webkit.JavascriptInterface
        public String version() {
            return io.umbral.module.ModuleRunner.KSU_VER;
        }
    }

    /** 把字符串安全地嵌进 JS 字面量 */
    private static String jsStr(String s) {
        if (s == null) {
            return "''";
        }
        StringBuilder sb = new StringBuilder("'");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '\'': sb.append("\\'"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('\'').toString();
    }
}
