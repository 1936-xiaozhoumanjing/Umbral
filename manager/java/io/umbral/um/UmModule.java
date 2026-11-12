package io.umbral.um;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

/**
 * UM 模块文件格式。
 *
 * ══════════════════════════════════════════════════════
 *  文件布局
 * ══════════════════════════════════════════════════════
 *
 *   偏移  长度  内容
 *   0     4     magic "UMM1"
 *   4     1     version  (当前 1)
 *   5     1     type     0 = 纯规则文本, 1 = 字节码
 *   6     1     flags    保留
 *   7     1     keyId    0/1/2 = 用第几把钥匙；0xFF = 明文
 *   8     1     ivLen    通常 16
 *   9     3     保留
 *   12    4     plainLen 明文长度（LE）
 *   16    4     crc32    明文的 CRC（LE）
 *   20    4     reserved
 *   24    ivLen IV
 *   24+n  ...   密文（CTR 无填充，长度 == plainLen）
 *
 * ══════════════════════════════════════════════════════
 *  两种载荷
 * ══════════════════════════════════════════════════════
 *
 *  纯规则（type=0）：UTF-8 文本，一行一条
 *      # 注释
 *      uid 10560 dev 65082 ino 1073146 hide
 *      uid 10560 prop ro.product.model Pixel 9
 *
 *  字节码（type=1）：给内核 VM 执行的混淆程序（后续实现）
 *
 * ══════════════════════════════════════════════════════
 *  解密规则（按用户要求）
 * ══════════════════════════════════════════════════════
 *
 *  1. 头部 keyId 指定的那把先试
 *  2. 不对就把三把全试一遍 —— 谁解出来 CRC 对得上就用谁
 *     （CTR 解错密钥不会报错，只会得到乱码，所以必须靠 CRC 判真伪）
 *  3. 都不对 → 抛错，不猜
 *
 *  导入明文规则时：解析内容，然后用默认第 0 把钥匙加密再保存。
 */
public final class UmModule {

    public static final byte[] MAGIC = {'U', 'M', 'M', '1'};
    public static final int VERSION = 1;

    public static final int TYPE_RULE = 0;
    public static final int TYPE_BYTECODE = 1;

    private static final int HDR = 24;

    public String id = "";
    public String name = "";
    public int type = TYPE_RULE;
    public int keyId = UmCrypto.KEY_NONE;
    /** 解密后的明文（规则文本或字节码） */
    public byte[] plain;

    private UmModule() {
    }

    // ══════════════════ 打开 ══════════════════

    /**
     * 打开一个 .umb 文件内容。
     *
     * @return 解析结果；格式不认识返回 null
     * @throws UmException 头合法但三种密钥都解不开（被改过 / 不是我们的）
     */
    public static UmModule open(byte[] raw) throws UmException {
        if (raw == null || raw.length < HDR) {
            return null;
        }
        for (int i = 0; i < 4; i++) {
            if (raw[i] != MAGIC[i]) {
                return null;
            }
        }

        UmModule m = new UmModule();
        int ver = raw[4] & 0xFF;
        m.type = raw[5] & 0xFF;
        m.keyId = raw[7] & 0xFF;
        int ivLen = raw[8] & 0xFF;
        int plainLen = UmCrypto.getInt(raw, 12);
        int crc = UmCrypto.getInt(raw, 16);

        if (ver != VERSION) {
            throw new UmException("不支持的版本 " + ver);
        }
        if (ivLen <= 0 || ivLen > 32 || HDR + ivLen > raw.length) {
            throw new UmException("IV 长度非法 " + ivLen);
        }

        byte[] iv = new byte[ivLen];
        System.arraycopy(raw, HDR, iv, 0, ivLen);
        int off = HDR + ivLen;
        int clen = raw.length - off;
        if (clen <= 0) {
            throw new UmException("没有密文");
        }
        byte[] cipher = new byte[clen];
        System.arraycopy(raw, off, cipher, 0, clen);

        /* 明文（未加密）直接通过 */
        if (m.keyId == UmCrypto.KEY_NONE) {
            m.plain = cipher;
            return m;
        }

        /* ① 先试头部指定的那把 */
        byte[] p = UmCrypto.decrypt(cipher, m.keyId, iv);
        if (p != null && p.length == plainLen && UmCrypto.crc(p) == crc) {
            m.plain = p;
            return m;
        }

        /* ② 三把全试 —— 谁 CRC 对得上就用谁 */
        for (int k = 0; k < UmCrypto.keyCount(); k++) {
            if (k == m.keyId) {
                continue;
            }
            p = UmCrypto.decrypt(cipher, k, iv);
            if (p != null && p.length == plainLen && UmCrypto.crc(p) == crc) {
                m.keyId = k;
                m.plain = p;
                return m;
            }
        }

        throw new UmException("三种密钥都解不开（文件可能被改过）");
    }

    // ══════════════════ 保存 ══════════════════

    /** 用第 keyIdx 把钥匙重新加密（明文在 this.plain 里） */
    public byte[] seal(int keyIdx) {
        byte[] iv = UmCrypto.makeIv(plain);
        byte[] cipher = UmCrypto.encrypt(plain, keyIdx, iv);
        if (cipher == null) {
            throw new IllegalStateException("encrypt failed");
        }

        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(MAGIC, 0, 4);
        o.write(VERSION);
        o.write(type);
        o.write(0);                     /* flags */
        o.write(keyIdx);
        o.write(iv.length);
        o.write(0);
        o.write(0);
        o.write(0);
        UmCrypto.putInt(o, plain.length);
        UmCrypto.putInt(o, UmCrypto.crc(plain));
        UmCrypto.putInt(o, 0);          /* reserved */
        o.write(iv, 0, iv.length);
        o.write(cipher, 0, cipher.length);
        keyId = keyIdx;
        return o.toByteArray();
    }

    // ══════════════════ 导入 ══════════════════

    /**
     * 判断一段内容是不是「未加密的纯规则文本」。
     *
     * 用户要求：别人给纯规则没加密的 UM 模块，我们导入后要用固定密钥加密再存。
     * 识别方式：不是 UMM1 头，且能按 UTF-8 读成文本、首行像规则。
     */
    public static boolean looksLikePlainRules(byte[] raw) {
        if (raw == null || raw.length == 0 || raw.length > 256 * 1024) {
            return false;
        }
        if (raw.length >= 4) {
            boolean magic = true;
            for (int i = 0; i < 4; i++) {
                if (raw[i] != MAGIC[i]) {
                    magic = false;
                    break;
                }
            }
            if (magic) {
                return false;
            }
        }
        String s;
        try {
            s = new String(raw, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return false;
        }
        for (String line : s.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            return t.startsWith("uid ") || t.startsWith("prop ");
        }
        return false;
    }

    /** 把一段字节码（未混淆或已混淆的）包成 UR 模块 */
    public static UmModule fromBytecode(byte[] code, String id) {
        UmModule m = new UmModule();
        m.id = id;
        m.type = TYPE_BYTECODE;
        m.plain = code;
        return m;
    }

    /** 把明文规则文本包成一个 UM 模块（默认第 0 把钥匙） */
    public static UmModule fromPlainRules(byte[] raw, String id) {
        UmModule m = new UmModule();
        m.id = id;
        m.type = TYPE_RULE;
        m.plain = raw;
        return m;
    }

    // ══════════════════ 规则文本解析 ══════════════════

    /** 一条规则 */
    public static final class Rule {
        public int uid;
        public int dev;
        public long ino;
        public String action = "hide";
        public String prop;
        public String value;

        @Override
        public String toString() {
            if (prop != null) {
                return "prop uid=" + uid + " " + prop + "=" + value;
            }
            return "hide uid=" + uid + " dev=" + dev + " ino=" + ino;
        }
    }

    /** 解析规则文本（type=RULE 时可用） */
    public List<Rule> rules() throws UmException {
        List<Rule> out = new ArrayList<>();
        if (plain == null || type != TYPE_RULE) {
            return out;
        }
        String s;
        try {
            s = new String(plain, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new UmException("规则不是 UTF-8");
        }
        int ln = 0;
        for (String line : s.split("\n")) {
            ln++;
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            String[] f = t.split("\\s+");
            if (f.length >= 6 && "uid".equals(f[0]) && "dev".equals(f[2])
                    && "ino".equals(f[4])) {
                Rule r = new Rule();
                try {
                    r.uid = Integer.parseInt(f[1]);
                    r.dev = (int) Long.parseLong(f[3]);
                    r.ino = Long.parseLong(f[5]);
                } catch (NumberFormatException e) {
                    throw new UmException("第 " + ln + " 行数字格式错");
                }
                if (f.length >= 7) {
                    r.action = f[6];
                }
                out.add(r);
            } else if (f.length >= 4 && "uid".equals(f[0]) && "prop".equals(f[2])) {
                Rule r = new Rule();
                try {
                    r.uid = Integer.parseInt(f[1]);
                } catch (NumberFormatException e) {
                    throw new UmException("第 " + ln + " 行 uid 格式错");
                }
                r.prop = f[3];
                StringBuilder v = new StringBuilder();
                for (int i = 4; i < f.length; i++) {
                    if (v.length() > 0) {
                        v.append(' ');
                    }
                    v.append(f[i]);
                }
                r.value = v.toString();
                out.add(r);
            } else {
                throw new UmException("第 " + ln + " 行不认识: " + t);
            }
        }
        return out;
    }

    /** UM 自己的异常 */
    public static final class UmException extends Exception {
        public UmException(String m) {
            super(m);
        }
    }
}
