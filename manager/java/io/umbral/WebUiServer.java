package io.umbral;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 极简本地 HTTP 服务 —— 给模块的 webroot 用（对齐 KSU 的 WebUI）。
 *
 * ══════════════════════════════════════════════════════
 *  为什么需要
 * ══════════════════════════════════════════════════════
 *
 *  模块的 WebUI 放在 /data/adb/modules/<id>/webroot/ 下。
 *  KSU 的 App 会起一个本地 http 服务指向它，再用 WebView 打开。
 *
 *  直接 file:// 加载只能跑纯静态页 —— 页面里 fetch('/api') 会因为
 *  file:// 没有 origin 而失败。起了 http 之后 origin 是
 *  http://127.0.0.1:<port>，绝大多数模块页就能正常工作。
 *
 *  ══════════════════════════════════════════════════════
 *   设计
 *  ══════════════════════════════════════════════════════
 *   · 绑 127.0.0.1（不对外监听，避免暴露）
 *   · 端口 0 → 系统随机分配，用完即关
 *   · GET / HEAD：读文件返回，目录默认 index.html
 *   · POST：把 body 写进 webroot 下同名 .post 文件并把长度回给页面
 *           （模块页常见的「保存配置」就是这个套路）
 *   · 只允许访问 rootDir 下的文件（路径穿越检查）
 */
public final class WebUiServer implements Runnable {

    private final File rootDir;
    private ServerSocket server;
    private Thread thread;
    private volatile boolean running;

    public WebUiServer(File rootDir) {
        this.rootDir = rootDir;
    }

    /** 启动，返回端口；失败返回 -1 */
    public int start() {
        try {
            server = new ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
            running = true;
            thread = new Thread(this, "webui");
            thread.setDaemon(true);
            thread.start();
            return server.getLocalPort();
        } catch (Throwable t) {
            return -1;
        }
    }

    public void stop() {
        running = false;
        try {
            if (server != null) {
                server.close();
            }
        } catch (Throwable ignored) {
        }
        server = null;
    }

    @Override
    public void run() {
        while (running) {
            Socket s = null;
            try {
                s = server.accept();
                handle(s);
            } catch (Throwable ignored) {
            } finally {
                try {
                    if (s != null) {
                        s.close();
                    }
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void handle(Socket s) {
        InputStream in = null;
        OutputStream out = null;
        try {
            in = new BufferedInputStream(s.getInputStream());
            out = s.getOutputStream();

            /* 解析请求行 + 头 */
            String requestLine = readLine(in);
            if (requestLine == null) {
                return;
            }
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                return;
            }
            String method = parts[0];
            String path = parts[1];

            int contentLength = 0;
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c > 0) {
                    String k = line.substring(0, c).trim().toLowerCase(Locale.US);
                    if ("content-length".equals(k)) {
                        try {
                            contentLength = Integer.parseInt(line.substring(c + 1).trim());
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }

            /* 去掉 query */
            int q = path.indexOf('?');
            String pure = q >= 0 ? path.substring(0, q) : path;
            if (pure.equals("/")) {
                pure = "/index.html";
            }

            if ("POST".equals(method)) {
                byte[] body = readN(in, contentLength);
                File target = resolve(pure);
                if (target != null) {
                    /* 写进 <目标>.post，并回 200 */
                    File dst = new File(target.getParentFile(), target.getName() + ".post");
                    java.io.FileOutputStream fo = new java.io.FileOutputStream(dst, false);
                    fo.write(body == null ? new byte[0] : body);
                    fo.close();
                }
                respond(out, 200, "text/plain", "ok".getBytes("UTF-8"));
                return;
            }

            if (!"GET".equals(method) && !"HEAD".equals(method)) {
                respond(out, 405, "text/plain", "method not allowed".getBytes("UTF-8"));
                return;
            }

            File f = resolve(pure);
            if (f == null || !f.exists() || f.isDirectory()) {
                respond(out, 404, "text/plain", "not found".getBytes("UTF-8"));
                return;
            }
            byte[] data = readAll(f);
            respond(out, 200, mimeOf(f.getName()), "HEAD".equals(method) ? new byte[0] : data);
        } catch (Throwable ignored) {
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Throwable ignored) {
            }
            try {
                if (out != null) {
                    out.close();
                }
            } catch (Throwable ignored) {
            }
        }
    }

    /** 只允许 rootDir 下的文件（防 ../ 穿越） */
    private File resolve(String uriPath) {
        try {
            String p = java.net.URLDecoder.decode(uriPath, "UTF-8");
            if (p.startsWith("/")) {
                p = p.substring(1);
            }
            if (p.contains("..")) {
                return null;
            }
            File f = new File(rootDir, p);
            String root = rootDir.getCanonicalPath();
            String target = f.getCanonicalPath();
            if (!target.startsWith(root)) {
                return null;
            }
            return f;
        } catch (Throwable t) {
            return null;
        }
    }

    private static void respond(OutputStream out, int code, String mime, byte[] body)
            throws IOException {
        String status = code == 200 ? "OK" : (code == 404 ? "Not Found" : "Error");
        StringBuilder h = new StringBuilder();
        h.append("HTTP/1.1 ").append(code).append(' ').append(status).append("\r\n");
        h.append("Content-Type: ").append(mime).append("\r\n");
        h.append("Content-Length: ").append(body.length).append("\r\n");
        h.append("Cache-Control: no-store\r\n");
        h.append("Connection: close\r\n\r\n");
        out.write(h.toString().getBytes("UTF-8"));
        if (body.length > 0) {
            out.write(body);
        }
        out.flush();
    }

    private static String mimeOf(String name) {
        String n = name.toLowerCase(Locale.US);
        if (n.endsWith(".html") || n.endsWith(".htm")) {
            return "text/html; charset=utf-8";
        }
        if (n.endsWith(".js")) {
            return "application/javascript; charset=utf-8";
        }
        if (n.endsWith(".css")) {
            return "text/css; charset=utf-8";
        }
        if (n.endsWith(".json")) {
            return "application/json; charset=utf-8";
        }
        if (n.endsWith(".png")) {
            return "image/png";
        }
        if (n.endsWith(".jpg") || n.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        if (n.endsWith(".svg")) {
            return "image/svg+xml";
        }
        return "application/octet-stream";
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') {
                break;
            }
            if (c != '\r') {
                bo.write(c);
            }
            if (bo.size() > 8192) {
                break;
            }
        }
        if (bo.size() == 0 && c == -1) {
            return null;
        }
        return new String(bo.toByteArray(), "UTF-8");
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        if (n <= 0) {
            return new byte[0];
        }
        byte[] b = new byte[n];
        int got = 0;
        while (got < n) {
            int r = in.read(b, got, n - got);
            if (r <= 0) {
                break;
            }
            got += r;
        }
        return b;
    }

    private static byte[] readAll(File f) throws IOException {
        FileInputStream fi = new FileInputStream(f);
        ByteArrayOutputStream bo = new ByteArrayOutputStream((int) Math.min(f.length(), 4 << 20));
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = fi.read(buf)) > 0) {
            bo.write(buf, 0, n);
        }
        fi.close();
        return bo.toByteArray();
    }

    /** 给界面用：MIME 表对外暴露一份（调试时看） */
    public static Map<String, String> mimeTable() {
        Map<String, String> m = new HashMap<>();
        m.put("html", "text/html");
        m.put("js", "application/javascript");
        m.put("css", "text/css");
        return m;
    }
}
