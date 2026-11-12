package io.umbral.um;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * UM 仓库 —— 导入、加密、列出、应用。
 *
 * ══════════════════════════════════════════════════════
 *  目录约定
 * ══════════════════════════════════════════════════════
 *
 *   /data/adb/umbral/um/<id>.umb     加密后的 UM 模块
 *
 *   放在 /data/adb 下而不是 App 私有目录，因为：
 *     ① 模块开机解密加载时要能读到（App 私有目录开机时可能还没解密完）
 *     ② 卸载 App 不会把用户的 UM 规则一起删掉
 *
 * ══════════════════════════════════════════════════════
 *  导入规则（按用户要求）
 * ══════════════════════════════════════════════════════
 *
 *   收到 UMM1 头的加密文件  → 原样保存（我们已经能解，不需要再加密一次）
 *   收到未加密的纯规则文本  → 用固定第 0 把钥匙加密后再保存
 *   两者都不是              → 拒绝，并说明为什么
 *
 * ══════════════════════════════════════════════════════
 *  持久化
 * ══════════════════════════════════════════════════════
 *
 *   规则以加密形式落盘，开机时由内核模块（或管理器）解密后写入 /proc/umbral/um。
 *   这是目标项 15(g)：重启后仍生效。
 */
public final class UmRepository {

    public static final String DIR = "/data/adb/umbral/um";

    /*
     * ★ 为什么需要 sidecar ★
     *
     * .umb 下发给内核时会做 xorMask 变成字节码（用户要求：初始是加密形态），
     * 于是文件里读不到那条 "# 应用： ..." 明文头部
     * → countApps/appsOf 解析失败 → 界面显示「已对 0 个应用生效」。
     *
     * 所以把「这个模块对哪些 uid 生效」单独存一份明文清单，
     * 结果照样能显示、能用来预选「修改生效应用」。
     */
    public static final String APPS_DIR = DIR + "/.apps";

    /** 写 uid 清单（apply 成功后自动调用） */
    public static void writeAppsMeta(String id, java.util.List<Integer> uids) {
        if (id == null) {
            return;
        }
        try {
            java.io.File d = new java.io.File(APPS_DIR);
            if (!d.exists()) {
                //noinspection ResultOfMethodCallIgnored
                d.mkdirs();
            }
            StringBuilder sb = new StringBuilder();
            for (Integer u : uids) {
                if (sb.length() > 0) {
                    sb.append(',');
                }
                sb.append(u);
            }
            java.io.File f = new java.io.File(d, id + ".txt");
            java.io.FileOutputStream fo = new java.io.FileOutputStream(f, false);
            fo.write(sb.toString().getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();
        } catch (Throwable ignored) {
        }
    }

    /** 读 uid 清单；没有就返回 null */
    public static int[] readAppsMeta(String id) {
        if (id == null) {
            return null;
        }
        try {
            java.io.File f = new java.io.File(new java.io.File(APPS_DIR), id + ".txt");
            if (!f.exists()) {
                return null;
            }
            byte[] b = new byte[(int) f.length()];
            java.io.FileInputStream in = new java.io.FileInputStream(f);
            int n = in.read(b);
            in.close();
            String s = new String(b, 0, Math.max(0, n), "UTF-8").trim();
            if (s.isEmpty()) {
                return new int[0];
            }
            String[] ps = s.split(",");
            int[] out = new int[ps.length];
            int k = 0;
            for (String p : ps) {
                try {
                    out[k++] = Integer.parseInt(p.trim());
                } catch (Exception ignored) {
                    k--;
                }
            }
            int[] t = new int[k];
            System.arraycopy(out, 0, t, 0, k);
            return t;
        } catch (Throwable t) {
            return null;
        }
    }
    /** 默认加密用的钥匙下标 */
    public static final int DEFAULT_KEY = 0;

    private UmRepository() {
    }

    /** 一个已安装的 UM 模块 */
    public static final class Item {
        public String id;
        public String path;
        public int type;
        public int keyId;
        public int ruleCount;
        public String error;
        public UmModule module;

        public String meta() {
            String t = (type == UmModule.TYPE_BYTECODE) ? "字节码" : "规则";
            if (error != null) {
                return t + " · " + error;
            }
            return t + " · " + ruleCount + " 条 · 密钥#" + keyId;
        }
    }

    // ══════════════════ 导入 ══════════════════

    /**
     * 导入一份 UM 内容。
     *
     * @param raw  文件原始字节
     * @param name 建议的模块 id（不含扩展名）
     * @return 导入后的 id；失败抛异常
     */
    public static String importBytes(Context ctx, byte[] raw, String name)
            throws UmModule.UmException {
        if (raw == null || raw.length == 0) {
            throw new UmModule.UmException("文件是空的");
        }
        String id = sanitize(name);

        byte[] out;
        UmModule m;

        if (UmModule.looksLikePlainRules(raw)) {
            /*
             * 未加密的纯规则 → 解析校验一遍再用固定密钥加密。
             * 先校验是为了「导入失败要立刻报错」，而不是存进去之后
             * 开机加载时才发现有问题 —— 那时候用户根本不知道去哪查。
             */
            m = UmModule.fromPlainRules(raw, id);
            m.rules();
            out = m.seal(DEFAULT_KEY);
        } else {
            m = UmModule.open(raw);
            if (m == null) {
                throw new UmModule.UmException("不认识的文件格式（既不是 UMM1 也不是纯规则文本）");
            }
            if (m.type == UmModule.TYPE_RULE) {
                m.rules();          /* 同样先校验 */
            }
            /* 已经是我们能解开的加密文件 —— 原样保存，不重复加密 */
            out = raw;
        }
        m.id = id;

        save(ctx, id, out);
        return id;
    }

    /**
     * 把一段规则文本存成一个真正的 UM 模块（落盘 + 加密）。
     *
     * 模板库下发时用它：用户要的是「在 UM 列表里看到一个模块、能卸载」，
     * 而不是往内核里塞一堆看不见的规则。
     *
     * @return 模块 id；失败抛异常
     */
    public static String saveNewModule(Context ctx, String id, String ruleText)
            throws UmModule.UmException {
        UmModule m = UmModule.fromPlainRules(ruleText.getBytes(java.nio.charset.StandardCharsets.UTF_8), id);
        m.rules();                       /* 先校验格式，错了立刻报 */
        byte[] sealed = m.seal(DEFAULT_KEY);
        save(ctx, id, sealed);
        return id;
    }

    // ══════════════════ 读取 ══════════════════

    /** 列出全部已安装 UM。会读磁盘（root 目录，失败返回空）。 */
    /**
     * ★ 脏标记 ★
     *
     * 下发 / 删除 UM 模块之后置位，UM 列表每次显示时检查一次，
     * 为真就重新扫描目录 —— 这样用户不用手动下拉刷新。
     */
    private static volatile boolean DIRTY = true;

    public static void markDirty() {
        DIRTY = true;
    }

    public static boolean consumeDirty() {
        boolean d = DIRTY;
        DIRTY = false;
        return d;
    }

    /**
     * ★ 这个 UM 模块对几个应用生效 ★
     *
     * 从 .umb 头部那行「# 应用： 10563,10564」数出来。
     * 读不到就返回 0 —— 列表只是不显示副标题，不影响任何功能。
     */
    public static int countApps(Item it) {
        if (it == null || it.id == null) {
            return 0;
        }
        int[] meta = readAppsMeta(it.id);
        if (meta == null) {
            /*
             * ★ sidecar 缺失时，直接从模块规则里数，并顺手补写 sidecar ★
             *
             * 为什么会缺：sidecar 是 apply() 成功时写的，
             * 但模块可能是「apply 失败但文件已生成」或「旧版本创建的」，
             * 这时界面就会显示「已对 0 个应用生效」，而实际上规则里有 uid。
             * 这里用规则本身兜底，并且把 sidecar 补上，下次就不用再算。
             */
            meta = uidsFromRules(it);
            if (meta != null && meta.length > 0) {
                java.util.ArrayList<Integer> us = new java.util.ArrayList<>();
                for (int u : meta) {
                    us.add(u);
                }
                writeAppsMeta(it.id, us);
            }
        }
        if (meta != null) {
            return meta.length;
        }
        java.io.File dir = new java.io.File(DIR);
        java.io.File[] fs = dir.listFiles();
        if (fs == null) {
            return 0;
        }
        for (java.io.File f : fs) {
            if (!f.getName().startsWith(it.id)) {
                continue;
            }
            java.io.BufferedReader r = null;
            try {
                r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(new java.io.FileInputStream(f), "UTF-8"));
                String line;
                int n = 0;
                while ((line = r.readLine()) != null && n < 8) {
                    n++;
                    int k = line.indexOf("# 应用");
                    if (k < 0) {
                        continue;
                    }
                    int c = line.indexOf(':');
                    if (c < 0) {
                        c = line.indexOf('：');
                    }
                    if (c < 0 || c + 1 >= line.length()) {
                        continue;
                    }
                    String tail = line.substring(c + 1).trim();
                    if (tail.isEmpty()) {
                        return 0;
                    }
                    return tail.split(",").length;
                }
            } catch (Throwable ignored) {
            } finally {
                try { if (r != null) r.close(); } catch (Exception ignored) { }
            }
        }
        return 0;
    }

    /**
     * ★ 读这个 UM 模块「对哪些应用生效」★
     *
     * 来源于 .umb 头部的「# 应用： 10563,10564」那一行。
     * 「修改生效应用」时用它预选；读不到返回空数组。
     */
    public static int[] appsOf(Item it) {
        if (it == null || it.id == null) {
            return new int[0];
        }
        int[] meta = readAppsMeta(it.id);
        if (meta == null) {
            meta = uidsFromRules(it);
        }
        if (meta != null) {
            return meta;
        }
        java.io.File[] fs = new java.io.File(DIR).listFiles();
        if (fs == null) {
            return new int[0];
        }
        for (java.io.File f : fs) {
            if (!f.getName().startsWith(it.id)) {
                continue;
            }
            java.io.BufferedReader r = null;
            try {
                r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(new java.io.FileInputStream(f), "UTF-8"));
                String line;
                int seen = 0;
                while ((line = r.readLine()) != null && seen < 8) {
                    seen++;
                    int k = line.indexOf("# 应用");
                    if (k < 0) {
                        continue;
                    }
                    int c = line.indexOf(':');
                    if (c < 0) {
                        c = line.indexOf('：');
                    }
                    if (c < 0) {
                        continue;
                    }
                    String tail = line.substring(c + 1).trim();
                    if (tail.isEmpty()) {
                        return new int[0];
                    }
                    String[] parts = tail.split(",");
                    int[] out = new int[parts.length];
                    int n = 0;
                    for (String ps : parts) {
                        try {
                            out[n++] = Integer.parseInt(ps.trim());
                        } catch (Exception ignored) {
                            n--;
                        }
                    }
                    int[] trimmed = new int[n];
                    System.arraycopy(out, 0, trimmed, 0, n);
                    return trimmed;
                }
            } catch (Throwable ignored) {
            } finally {
                try { if (r != null) r.close(); } catch (Exception ignored) { }
            }
        }
        return new int[0];
    }

    /** 删掉某个模块对应的 .umb 文件（修改生效应用时先删旧的） */
    public static boolean deleteFilesOf(Item it) {
        if (it == null || it.id == null) {
            return false;
        }
        java.io.File[] fs = new java.io.File(DIR).listFiles();
        if (fs == null) {
            return false;
        }
        boolean any = false;
        for (java.io.File f : fs) {
            if (f.getName().startsWith(it.id)) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
                any = true;
            }
        }
        return any;
    }

    public static List<Item> listAll(Context ctx) {
        List<Item> out = new ArrayList<>();
        File[] fs = new File(DIR).listFiles();
        if (fs == null) {
            return out;
        }
        for (File f : fs) {
            String n = f.getName();
            if (!n.endsWith(".umb")) {
                continue;
            }
            byte[] raw = readFile(f);
            if (raw == null) {
                continue;
            }
            Item it = new Item();
            it.id = n.substring(0, n.length() - 4);
            it.path = f.getAbsolutePath();
            try {
                UmModule m = UmModule.open(raw);
                if (m == null) {
                    it.error = "格式不对";
                } else {
                    it.module = m;
                    it.type = m.type;
                    it.keyId = m.keyId;
                    it.ruleCount = (m.type == UmModule.TYPE_RULE) ? m.rules().size() : 0;
                }
            } catch (UmModule.UmException e) {
                it.error = e.getMessage();
            }
            out.add(it);
        }
        Collections.sort(out, new Comparator<Item>() {
            @Override
            public int compare(Item a, Item b) {
                return String.valueOf(a.id).compareToIgnoreCase(String.valueOf(b.id));
            }
        });
        return out;
    }

    // ══════════════════ 应用 ══════════════════

    /**
     * 把一个 UM 模块的规则下发到内核。
     *
     * 内核接口：/proc/umbral/um 写 "uid <u> dev <d> ino <i>"
     * 先写 clear 再逐条写入，保证是「整份替换」而不是叠加。
     *
     * @return null = 成功，否则是错误描述
     */
    /**
     * 把一个 UM 模块下发到内核。
     *
     * 两条路径：
     *   纯规则载荷 → 汇编成字节码 → 下发字节码
     *   字节码载荷 → 解混淆       → 下发字节码
     *
     * ★ 下发前先用参考 VM 自检 ★
     *   同样的 VM 逻辑在内核里也有一份。先在用户态跑一遍确认「能跑、结论对」，
     *   再下发 —— 内核侧跑一个坏程序最坏是放行，但能提前发现就别浪费那次机会。
     */
    public static String apply(Item it) {
        if (it == null || it.module == null) {
            return "模块没打开";
        }

        byte[] code;
        int expectEnrty = -1;
        int sampleUid = -1;
        int sampleDev = 0;
        long sampleIno = 0;

        try {
            if (it.module.type == UmModule.TYPE_RULE) {
                java.util.List<UmModule.Rule> rs = it.module.rules();
                if (rs.isEmpty()) {
                    return "规则是空的";
                }
                code = UmBytecode.assembleRules(rs);
                /* 拿第一条 hide 规则当自检样本 */
                for (UmModule.Rule r : rs) {
                    if (r.prop == null) {
                        sampleUid = r.uid;
                        sampleDev = r.dev;
                        sampleIno = r.ino;
                        expectEnrty = UmBytecode.RET_ENOENT;
                        break;
                    }
                }
            } else {
                /* 字节码载荷：解混淆（sail 存在头部，这里用固定 16 字节 0 兼容旧包） */
                code = UmBytecode.xorMask(it.module.plain, defaultSalt(it));
            }
        } catch (UmModule.UmException e) {
            return e.getMessage();
        } catch (Exception e) {
            return "编译失败: " + e.getMessage();
        }

        if (code == null || code.length == 0) {
            return "编译出空程序";
        }

        /* ── 自检 ── */
        if (expectEnrty >= 0 && sampleUid > 0) {
            int got = UmBytecode.run(code, sampleUid, sampleDev, sampleIno);
            if (got != expectEnrty) {
                return "自检失败：样本 " + sampleUid + "/" + sampleDev + "/" + sampleIno
                        + " 期望 " + expectEnrty + " 实际 " + got;
            }
            /* 不匹配的上下文必须放行 */
            int got2 = UmBytecode.run(code, sampleUid, sampleDev, sampleIno ^ 1L);
            if (got2 != UmBytecode.RET_ALLOW) {
                return "自检失败：不匹配上下文应放行，实际 " + got2;
            }
        }

        /* ── 下发 ── */
        if (!writeProc("/proc/umbral/um", "clear")) {
            return "写 /proc/umbral/um 失败（模块没加载或没有权限）";
        }
        /*
         * ★ 同时写开机加载文件 ★
         *
         * 只写 /proc/umbral/um 是「这一秒生效」，重启就没了。
         * 开机加载文件才是持久化的来源 —— 模块 init 时会解密并加载它。
         * 用自研流密码（与内核 sk_um_crypt 逐字节一致），
         * 磁盘上看到的是乱码。
         */
        StringBuilder boot = new StringBuilder("# umbral boot rules\n");
        try {
            if (it.module.type == UmModule.TYPE_RULE) {
                for (UmModule.Rule r : it.module.rules()) {
                    if (r.prop != null) {
                        continue;
                    }
                    boot.append("uid ").append(r.uid)
                        .append(" dev ").append(r.dev)
                        .append(" ino ").append(r.ino).append('\n');
                }
            } else {
                /* 字节码载荷：靴文件里写成 bc 行，内核 init 会用 VM 载入 */
                byte[] masked = UmBytecode.xorMask(it.module.plain, defaultSalt(it));
                String hx = hex(masked);
                boot.setLength(0);
                boot.append("# umbral boot rules\nbc ").append(hx).append('\n');
            }
        } catch (UmModule.UmException e) {
            return e.getMessage();
        }
        byte[] bootPlain = boot.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bootEnc = UmStreamCipher.crypt(bootPlain);
        String err = writeBootFile(bootEnc);
        if (err != null) {
            return err;
        }

        /* 实时生效 */
        if (!writeProc("/proc/umbral/um", "clear")) {
            return "写 /proc/umbral/um 失败（模块没加载或没有权限）";
        }
        if (it.module.type == UmModule.TYPE_BYTECODE) {
            /* 内核 VM 已实现：整段下发 bc 协议 */
            if (!writeProc("/proc/umbral/um", "bc " + hex(code))) {
                return "下发字节码失败";
            }
            /* 成功：把「对哪些 uid 生效」记进 sidecar，界面才不会显示 0 */
        try {
            if (it.module.type == UmModule.TYPE_RULE) {
                java.util.ArrayList<Integer> us = new java.util.ArrayList<>();
                for (UmModule.Rule rr : it.module.rules()) {
                    if (!us.contains(rr.uid)) {
                        us.add(rr.uid);
                    }
                }
                writeAppsMeta(it.id, us);
            }
        } catch (Throwable ignored) {
        }

        return null;
        }
        try {
            for (UmModule.Rule r : it.module.rules()) {
                if (r.prop != null) {
                    continue;
                }
                if (!writeProc("/proc/umbral/um", r.uid + " " + r.dev + " " + r.ino)) {
                    return "写规则失败: " + r.uid + "/" + r.dev + "/" + r.ino;
                }
            }
        } catch (UmModule.UmException e) {
            return e.getMessage();
        }
        return null;
    }

    /**
     * 把加密后的开机规则写到 /data/adb/umbral/um/boot.umbc。
     * 先存到 App 私有目录再 cp，因为 /data/adb 只有 root 能写。
     */
    private static String writeBootFile(byte[] enc) {
        java.io.File tmp = null;
        try {
            java.io.File dir = new java.io.File(DIR);
            if (!dir.exists()) {
                if (!mkdirViaSu()) {
                    return "建不了目录 " + DIR;
                }
            }
            /* 私有一份临时副本，交给 root 拷过去 */
            tmp = new java.io.File(System.getProperty("java.io.tmpdir", "/tmp"),
                    "umboot_" + System.nanoTime());
            java.io.FileOutputStream o = new java.io.FileOutputStream(tmp);
            try {
                o.write(enc);
                o.flush();
            } finally {
                o.close();
            }
            /*
             * ★ 直接在本进程写，不再起 su 子进程 ★
             *
             * 原来这里是 execOk({"su","-c","cp ..."})：
             *   设备上没有 su 二进制（或 su 链还没通）→ 失败
             *   → 报「写开机规则文件失败（没有 root）」
             *
             * 而 App 进程自己有 /data/adb 的写权限
             * （影子权限按 uid 放行，已经实测能改 /data/adb）
             * 所以直接 FileOutputStream 写目标文件，一步到位。
             */
            java.io.File out = new java.io.File(UmStreamCipher.BOOT_FILE);
            java.io.File parent = out.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                return "建不了目录 " + parent.getAbsolutePath();
            }
            java.io.FileOutputStream fo = new java.io.FileOutputStream(out);
            try {
                fo.write(enc);
                fo.flush();
                fo.getFD().sync();          /* 必须 fsync，否则重启后可能读到 0 字节 */
            } finally {
                fo.close();
            }
            return null;
        } catch (Exception e) {
            return "写开机规则失败: " + e.getMessage();
        } finally {
            if (tmp != null) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }
    }

    /** 字节码载荷的默认混淆 salt（16 字节 0）。后续版本会把 salt 写进文件头。 */
    private static byte[] defaultSalt(Item it) {
        byte[] z = new byte[16];
        return z;
    }


    public static boolean clearAll() {
        return writeProc("/proc/umbral/um", "clear");
    }

    // ══════════════════ 内部 ══════════════════

    /**
     * 保存一份 UM 模块到 /data/adb/umbral/um/<id>.umb。
     *
     * 依次尝试三种身份，每一步的输出都记下来，失败时一并报给用户
     * —— 否则只知道"保存失败"，不知道卡在哪一步。
     */
    private static void save(Context ctx, String id, byte[] data) throws UmModule.UmException {
        java.io.File tmp = null;
        StringBuilder trace = new StringBuilder();
        /* 追踪同时落盘到外部目录，方便用 adb 直接读，不用靠 toast */
        try {
            java.io.File lg = new java.io.File(ctx.getExternalFilesDir(null), "um_save.log");
            StringBuilder env = new StringBuilder();
            env.append("=== ").append(new java.util.Date()).append(" ===\n");
            env.append("缓存目录=").append(ctx.getCacheDir()).append('\n');
            env.append("目标=").append(DIR).append('\n');
            env.append("写 /proc/umbral/grant 测试: ");
            io.umbral.sk.Shell.R g = io.umbral.sk.Shell.suFirst(
                    "printf %s \"$$ 1\" | dd of=/proc/umbral/grant conv=notrunc 2>&1 && echo GRANT_OK || echo GRANT_FAIL");
            env.append(g.out).append('\n');
            env.append("id -u 测试: ").append(io.umbral.sk.Shell.suFirst("id -u").out).append('\n');
            env.append("读 /proc/umbral/version: ")
               .append(io.umbral.sk.Shell.suFirst("cat /proc/umbral/version 2>&1").out).append('\n');
            java.io.FileOutputStream lo = new java.io.FileOutputStream(lg, true);
            lo.write(env.toString().getBytes("UTF-8"));
            lo.close();
        } catch (Throwable ignored) {
        }
        try {
            tmp = new java.io.File(ctx.getCacheDir(), id + ".umb");
            java.io.FileOutputStream o = new java.io.FileOutputStream(tmp);
            try {
                o.write(data);
                o.flush();
            } finally {
                o.close();
            }
            trace.append("临时文件 ").append(tmp.length()).append(" 字节; ");

            String path = DIR + "/" + id + ".umb";
            String cmd = "mkdir -p " + DIR
                    + " && cp '" + tmp.getAbsolutePath() + "' '" + path + "'"
                    + " && chmod 644 '" + path + "'"
                    + " && echo UMBRAL_OK";

            /* ① 真 root 子进程 */
            io.umbral.sk.Shell.R r1 = io.umbral.sk.Shell.root(cmd);
            if (r1.out != null && r1.out.contains("UMBRAL_OK")) {
                return;
            }
            trace.append("root子进程 rc=").append(r1.code)
                 .append(" out=[").append(clip(r1.out)).append("]; ");

            /* ② 当前身份（万一目录可写） */
            io.umbral.sk.Shell.R r2 = io.umbral.sk.Shell.suFirst(cmd);
            if (r2.out != null && r2.out.contains("UMBRAL_OK")) {
                return;
            }
            trace.append("普通身份 rc=").append(r2.code)
                 .append(" out=[").append(clip(r2.out)).append("]; ");

            /* ③ 直接写（不走 shell） */
            try {
                java.io.FileOutputStream fo = new java.io.FileOutputStream(path);
                try {
                    fo.write(data);
                    fo.flush();
                } finally {
                    fo.close();
                }
                return;
            } catch (Exception e3) {
                trace.append("直写失败[").append(e3.getClass().getSimpleName())
                     .append(": ").append(e3.getMessage()).append("]");
            }

            logTrace(ctx, trace.toString());
            throw new UmModule.UmException("写不进 " + DIR + " → " + trace);
        } catch (UmModule.UmException e) {
            throw e;
        } catch (Exception e) {
            throw new UmModule.UmException("保存失败：" + e.getMessage() + " → " + trace);
        } finally {
            if (tmp != null) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
        }
    }

    private static void logTrace(Context ctx, String msg) {
        try {
            java.io.File lg = new java.io.File(ctx.getExternalFilesDir(null), "um_save.log");
            java.io.FileOutputStream lo = new java.io.FileOutputStream(lg, true);
            lo.write(("结果: " + msg + "\n\n").getBytes("UTF-8"));
            lo.close();
        } catch (Throwable ignored) {
        }
    }

    private static String clip(String s) {
        if (s == null) {
            return "null";
        }
        String t = s.trim().replace('\n', ' ');
        return t.length() > 120 ? t.substring(0, 120) + "…" : t;
    }


    private static boolean mkdirViaSu() {
        return execOk(new String[]{"su", "-c", "mkdir -p " + DIR + " && chmod 700 " + DIR});
    }

    private static boolean writeProc(String path, String content) {
        /* 先直接写（模块授权后可行），失败再走 su */
        FileOutputStream fo = null;
        try {
            fo = new FileOutputStream(path, false);
            fo.write(content.getBytes("UTF-8"));
            fo.flush();
            return true;
        } catch (Exception ignored) {
        } finally {
            if (fo != null) {
                try {
                    fo.close();
                } catch (Exception ignored) {
                }
            }
        }
        return execOk(new String[]{"su", "-c",
                "echo '" + content.replace("'", "'\\''") + "' > " + path});
    }

    private static boolean execOk(String[] argv) {
        Process p = null;
        try {
            p = Runtime.getRuntime().exec(argv);
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }

    private static byte[] readFile(File f) {
        java.io.FileInputStream in = null;
        try {
            in = new java.io.FileInputStream(f);
            byte[] buf = new byte[(int) Math.min(f.length(), 512 * 1024)];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n <= 0) {
                    break;
                }
                off += n;
            }
            return buf;
        } catch (Exception e) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xFF));
        }
        return sb.toString();
    }

    private static String sanitize(String name) {
        if (name == null || name.trim().isEmpty()) {
            return "um_" + System.currentTimeMillis();
        }
        String n = name.trim();
        int dot = n.lastIndexOf('.');
        if (dot > 0) {
            n = n.substring(0, dot);
        }
        return n.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    /** 从输入流读全部（给文件选择器用） */
    public static byte[] readAll(InputStream in) {
        try {
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) > 0) {
                o.write(b, 0, n);
            }
            return o.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 从模块规则里提取去重后的 uid 列表。
     *
     * 这是 sidecar 缺失时的唯一可靠来源 —— .umb 是加密形态读不到明文头部，
     * 但规则对象本身在内存里是解析好的。
     *
     * @return 去重后的 uid 数组；拿不到返回 null
     */
    public static int[] uidsFromRules(Item it) {
        if (it == null || it.module == null) {
            return null;
        }
        try {
            if (it.module.type != UmModule.TYPE_RULE) {
                return null;
            }
            java.util.LinkedHashSet<Integer> set = new java.util.LinkedHashSet<>();
            for (UmModule.Rule r : it.module.rules()) {
                set.add(r.uid);
            }
            if (set.isEmpty()) {
                return null;
            }
            int[] out = new int[set.size()];
            int i = 0;
            for (Integer u : set) {
                out[i++] = u;
            }
            return out;
        } catch (Throwable t) {
            return null;
        }
    }
}
