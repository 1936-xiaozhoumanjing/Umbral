package io.umbral.um;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * UM 加密层 —— 三种固定密钥，解密时三把一起试。
 *
 * ══════════════════════════════════════════════════════
 *  为什么是三把
 * ══════════════════════════════════════════════════════
 *
 *  历史原因 + 兼容性。用户拿到的 UM 模块可能来自：
 *    · 我们自己的工具加密的（用其中一把）
 *    · 别人手写的明文规则（导入时我们加密，用默认那把）
 *    · 旧版本 / 不同批次加密的（另外的钥匙）
 *
 *  与其让用户选"这是哪一版加密的"，不如**解密时全试一遍**：
 *  谁解出来的 CRC 对得上就用谁。对用户是透明的。
 *
 * ══════════════════════════════════════════════════════
 *  算法
 * ══════════════════════════════════════════════════════
 *
 *  AES-256-CTR + 每文件随机 IV。
 *  选 CTR 而不是 CBC：CTR 不需要 padding，密文长度 == 明文长度，
 *  对"规则文本"这种短载荷更省事；而且加密解密是同一个操作。
 */
public final class UmCrypto {

    /** 三种固定密钥（32 字节 = AES-256）。改这里就是换整套密钥体系。 */
    private static final byte[][] KEYS = {
            {
                    (byte) 0xA7, (byte) 0x3C, (byte) 0x91, (byte) 0x5E,
                    (byte) 0x0B, (byte) 0xD2, (byte) 0x77, (byte) 0x44,
                    (byte) 0x19, (byte) 0xE8, (byte) 0x63, (byte) 0xAF,
                    (byte) 0x2D, (byte) 0x86, (byte) 0x5B, (byte) 0xF0,
                    (byte) 0xC4, (byte) 0x11, (byte) 0x9D, (byte) 0x7A,
                    (byte) 0x36, (byte) 0xEB, (byte) 0x58, (byte) 0x0C,
                    (byte) 0x95, (byte) 0x42, (byte) 0xDF, (byte) 0x6B,
                    (byte) 0x20, (byte) 0xB9, (byte) 0x74, (byte) 0x8E,
            },
            {
                    (byte) 0x5F, (byte) 0xC2, (byte) 0x08, (byte) 0x9B,
                    (byte) 0x74, (byte) 0x3E, (byte) 0xA1, (byte) 0xD6,
                    (byte) 0x2B, (byte) 0x88, (byte) 0x4C, (byte) 0xF3,
                    (byte) 0x60, (byte) 0x1D, (byte) 0xBE, (byte) 0x57,
                    (byte) 0xCA, (byte) 0x39, (byte) 0x86, (byte) 0x02,
                    (byte) 0xEF, (byte) 0x75, (byte) 0x14, (byte) 0xA8,
                    (byte) 0x3B, (byte) 0xD0, (byte) 0x69, (byte) 0x92,
                    (byte) 0x4E, (byte) 0x1F, (byte) 0xC7, (byte) 0x53,
            },
            {
                    (byte) 0x33, (byte) 0x9A, (byte) 0xE1, (byte) 0x6C,
                    (byte) 0xBF, (byte) 0x40, (byte) 0x12, (byte) 0x8D,
                    (byte) 0x57, (byte) 0xEB, (byte) 0x24, (byte) 0x96,
                    (byte) 0xCD, (byte) 0x08, (byte) 0x71, (byte) 0xA4,
                    (byte) 0x3E, (byte) 0xF5, (byte) 0x82, (byte) 0x1B,
                    (byte) 0x6A, (byte) 0xD7, (byte) 0x4C, (byte) 0x99,
                    (byte) 0x05, (byte) 0xB2, (byte) 0x8F, (byte) 0x63,
                    (byte) 0xE0, (byte) 0x37, (byte) 0xAC, (byte) 0x5A,
            },
    };

    /** 明文标记（未加密） */
    public static final int KEY_NONE = 0xFF;

    private UmCrypto() {
    }

    public static int keyCount() {
        return KEYS.length;
    }

    /** 用第 idx 把密钥加密。IV 由调用方提供（8~16 字节）。 */
    public static byte[] encrypt(byte[] plain, int idx, byte[] iv) {
        if (idx < 0 || idx >= KEYS.length) {
            throw new IllegalArgumentException("bad key index " + idx);
        }
        return ctr(plain, KEYS[idx], iv);
    }

    /**
     * 用指定密钥解密。
     *
     * @return 明文；密钥不对时 CTR 不会报错（只会解出乱码），
     *         所以调用方必须用 CRC 校验结果 —— 见 {@link UmModule#open}。
     */
    public static byte[] decrypt(byte[] cipher, int idx, byte[] iv) {
        if (idx < 0 || idx >= KEYS.length) {
            return null;
        }
        return ctr(cipher, KEYS[idx], iv);
    }

    private static byte[] ctr(byte[] in, byte[] key, byte[] iv) {
        try {
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return c.doFinal(in);
        } catch (Exception e) {
            return null;
        }
    }

    public static int crc(byte[] data) {
        CRC32 c = new CRC32();
        c.update(data, 0, data.length);
        return (int) c.getValue();
    }

    /** 生成 16 字节 IV（用 CRC + 时间 + 内容摘要搅一下，够用） */
    public static byte[] makeIv(byte[] seed) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(seed == null ? new byte[0] : seed);
            md.update(String.valueOf(System.nanoTime()).getBytes(Charset.forName("UTF-8")));
            byte[] h = md.digest();
            byte[] iv = new byte[16];
            System.arraycopy(h, 0, iv, 0, 16);
            return iv;
        } catch (Exception e) {
            byte[] iv = new byte[16];
            long t = System.nanoTime();
            for (int i = 0; i < 16; i++) {
                iv[i] = (byte) (t >>> ((i % 8) * 8));
            }
            return iv;
        }
    }

    // ── 小端工具（格式统一用 LE，和内核侧一致）──

    public static void putInt(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >>> 8) & 0xFF);
        o.write((v >>> 16) & 0xFF);
        o.write((v >>> 24) & 0xFF);
    }

    public static int getInt(byte[] b, int off) {
        return (b[off] & 0xFF)
                | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16)
                | ((b[off + 3] & 0xFF) << 24);
    }
}
