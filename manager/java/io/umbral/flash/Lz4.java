package io.umbral.flash;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/** LZ4-legacy 解压 + 存储式压缩（不压缩，块头为负数，内核/lz4 工具都能解） */
final class Lz4 {

    private static final byte[] MAGIC = {0x02, 0x21, 0x4C, 0x18};

    private Lz4() {
    }

    /** 解 lz4-legacy：magic + [size][data]... */
    static byte[] decode(byte[] src) {
        if (src.length < 4) return src;
        int p = 4;
        ByteArrayOutputStream out = new ByteArrayOutputStream(src.length * 4);
        while (p + 4 <= src.length) {
            int blockSize = (src[p] & 0xFF) | ((src[p + 1] & 0xFF) << 8)
                    | ((src[p + 2] & 0xFF) << 16) | (src[p + 3] << 24);
            p += 4;
            if (blockSize == 0) break;
            if (blockSize < 0) {
                int n = -blockSize;
                if (p + n > src.length) n = src.length - p;
                out.write(src, p, n);
                p += n;
            } else {
                if (p + blockSize > src.length) blockSize = src.length - p;
                byte[] block = Arrays.copyOfRange(src, p, p + blockSize);
                p += blockSize;
                byte[] dec = decodeBlock(block);
                out.write(dec, 0, dec.length);
            }
        }
        return out.toByteArray();
    }

    /** 单个 LZ4 block 解压 */
    private static byte[] decodeBlock(byte[] in) {
        byte[] out = new byte[in.length * 6 + 64];
        int olen = 0;
        int i = 0;
        while (i < in.length) {
            int token = in[i++] & 0xFF;
            int litLen = token >>> 4;
            if (litLen == 15) {
                int b;
                do {
                    if (i >= in.length) break;
                    b = in[i++] & 0xFF;
                    litLen += b;
                } while (b == 255);
            }
            if (olen + litLen > out.length) out = grow(out, olen + litLen);
            if (i + litLen > in.length) litLen = in.length - i;
            System.arraycopy(in, i, out, olen, litLen);
            olen += litLen;
            i += litLen;
            if (i + 2 > in.length) break;

            int offset = (in[i] & 0xFF) | ((in[i + 1] & 0xFF) << 8);
            i += 2;
            if (offset == 0) break;

            int matchLen = token & 0x0F;
            if (matchLen == 15) {
                int b;
                do {
                    if (i >= in.length) break;
                    b = in[i++] & 0xFF;
                    matchLen += b;
                } while (b == 255);
            }
            matchLen += 4;

            if (olen + matchLen > out.length) out = grow(out, olen + matchLen);
            int start = olen - offset;
            for (int k = 0; k < matchLen; k++) {
                out[olen++] = out[start + k];
            }
        }
        return Arrays.copyOf(out, olen);
    }

    /** 存储模式：所有块标记为未压缩（负数块长） */
    static byte[] encodeStore(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + data.length / 1024 + 16);
        out.write(MAGIC, 0, 4);
        int pos = 0;
        final int CHUNK = 8 * 1024 * 1024; // 8MB/块
        while (pos < data.length) {
            int n = Math.min(CHUNK, data.length - pos);
            int neg = -n;
            out.write(neg & 0xFF);
            out.write((neg >> 8) & 0xFF);
            out.write((neg >> 16) & 0xFF);
            out.write((neg >> 24) & 0xFF);
            out.write(data, pos, n);
            pos += n;
        }
        return out.toByteArray();
    }

    private static byte[] grow(byte[] a, int need) {
        int cap = a.length;
        while (cap < need) cap = cap + (cap >> 1) + 64;
        return Arrays.copyOf(a, cap);
    }
}
