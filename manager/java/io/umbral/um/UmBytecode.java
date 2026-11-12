package io.umbral.um;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * UM 字节码：指令集 + 汇编器 + 参考解释器 + 混淆器。
 *
 * ══════════════════════════════════════════════════════
 *  为什么需要这一层
 * ══════════════════════════════════════════════════════
 *
 *  纯规则（uid/dev/ino → hide）只能表达「精确匹配」。
 *  一旦需要「uid 在某个范围、或者 dev 匹配且 ino 前缀匹配」这类逻辑，
 *  规则表就不够了 —— 那需要一门可执行的东西。
 *
 *  但直接把代码放进内核太危险（内核里跑任意代码 = 一次写错就崩系统）。
 *  所以设计成**受限字节码 VM**：
 *    · 只有约 12 条指令，能做比较 / 逻辑与 / 跳转 / 返回
 *    · 没有内存访问、没有指针、没有循环（跳转只能向前）
 *    · 只能返回「放行 / 拒绝 / 不存在」
 *  能力刚好够表达判定逻辑，但**理论上跑不出沙箱**。
 *
 * ══════════════════════════════════════════════════════
 *  指令集
 * ══════════════════════════════════════════════════════
 *
 *   0x00 END
 *   0x01 PUSH_UID          push 当前任务 uid
 *   0x02 PUSH_DEV          push 事件里的 dev
 *   0x03 PUSH_INO          push 事件里的 ino
 *   0x04 PUSH_U32  <u32>   push 常量
 *   0x05 PUSH_U64  <u64>   push 常量
 *   0x10 EQ                pop b, pop a, push (a == b)
 *   0x11 AND               pop b, pop a, push (a && b)
 *   0x12 JZ    <u16>       pop v, v==0 则向前跳到 offset
 *   0x13 JMP   <u16>       向前跳
 *   0x20 RET   <i32>       返回 errno（0=放行，-2=ENOENT）
 *
 *  规则「uid=U 且 dev=D 且 ino=I → ENOENT」编译成：
 *      PUSH_UID PUSH_U32 U EQ
 *      PUSH_DEV PUSH_U32 D EQ AND
 *      PUSH_INO PUSH_U64 I EQ AND
 *      JZ <下一条规则>
 *      RET -2
 *
 * ══════════════════════════════════════════════════════
 *  混淆（阶段 1：字节级 + 常量加密）
 * ══════════════════════════════════════════════════════
 *
 *  做法：
 *    ① 逐字节 XOR 一个按位置滚动的密钥流
 *    ② 头部带一个 16 字节随机 salt，混进密钥流
 *    ③ 静态反汇编出来是垃圾
 *
 *  诚实说明：这**不是**控制流平坦化，做不到抵抗专业逆向。
 *  要抵抗专业逆向需要阶段 2（真 VM 化 + 不透明谓词），
 *  那是另一个量级的工作，不能和「能跑起来」混在一起。
 */
public final class UmBytecode {

    // ── 指令 ──
    public static final int OP_END = 0x00;
    public static final int OP_PUSH_UID = 0x01;
    public static final int OP_PUSH_DEV = 0x02;
    public static final int OP_PUSH_INO = 0x03;
    public static final int OP_PUSH_U32 = 0x04;
    public static final int OP_PUSH_U64 = 0x05;
    public static final int OP_EQ = 0x10;
    public static final int OP_AND = 0x11;
    public static final int OP_JZ = 0x12;
    public static final int OP_JMP = 0x13;
    public static final int OP_RET = 0x20;

    /** 返回放行 */
    public static final int RET_ALLOW = 0;
    /** 返回 -ENOENT（让文件「不存在」） */
    public static final int RET_ENOENT = -2;

    public static final int MAX_PROGRAM = 64 * 1024;

    private UmBytecode() {
    }

    // ══════════════════ 汇编 ══════════════════

    /** 把规则表编译成字节码 */
    public static byte[] assembleRules(List<UmModule.Rule> rules) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        List<Integer> fixups = new ArrayList<>();   /* JZ 的 u16 位置 */

        for (UmModule.Rule r : rules) {
            if (r.prop != null) {
                continue;       /* 属性规则还没进 VM */
            }
            /* uid == U */
            o.write(OP_PUSH_UID);
            o.write(OP_PUSH_U32);
            putU32(o, r.uid);
            o.write(OP_EQ);
            /* && dev == D */
            o.write(OP_PUSH_DEV);
            o.write(OP_PUSH_U32);
            putU32(o, r.dev);
            o.write(OP_EQ);
            o.write(OP_AND);
            /* && ino == I */
            o.write(OP_PUSH_INO);
            o.write(OP_PUSH_U64);
            putU64(o, r.ino);
            o.write(OP_EQ);
            o.write(OP_AND);
            /* 不匹配就跳到下一条 */
            o.write(OP_JZ);
            fixups.add(o.size());
            putU16(o, 0);
            /* 命中：返回 ENOENT */
            o.write(OP_RET);
            putU32(o, RET_ENOENT);

            /* 回填 JZ 到「下一条规则的起点」= 当前偏移 */
            int here = o.size();
            byte[] tmp = o.toByteArray();
            int pos = fixups.remove(fixups.size() - 1);
            tmp[pos] = (byte) (here & 0xFF);
            tmp[pos + 1] = (byte) ((here >>> 8) & 0xFF);
            /* 重写流 */
            o.reset();
            o.write(tmp, 0, tmp.length);
        }

        /* 末尾默认放行 */
        o.write(OP_RET);
        putU32(o, RET_ALLOW);
        byte[] out = o.toByteArray();
        if (out.length > MAX_PROGRAM) {
            throw new IllegalStateException("程序太大 " + out.length);
        }
        return out;
    }

    // ══════════════════ 反汇编（调试用）══════════════════

    /** 把字节码反汇编成可读文本；遇到不认识的操作码就停 */
    public static String disassemble(byte[] code) {
        StringBuilder sb = new StringBuilder();
        int pc = 0;
        while (pc < code.length) {
            int at = pc;
            int op = code[pc++] & 0xFF;
            switch (op) {
                case OP_END:
                    sb.append(at).append(": END\n");
                    return sb.toString();
                case OP_PUSH_UID:
                    sb.append(at).append(": PUSH_UID\n");
                    break;
                case OP_PUSH_DEV:
                    sb.append(at).append(": PUSH_DEV\n");
                    break;
                case OP_PUSH_INO:
                    sb.append(at).append(": PUSH_INO\n");
                    break;
                case OP_PUSH_U32:
                    if (pc + 4 > code.length) {
                        return sb.append(at).append(": <truncated>\n").toString();
                    }
                    sb.append(at).append(": PUSH_U32 ").append(getU32(code, pc)).append('\n');
                    pc += 4;
                    break;
                case OP_PUSH_U64:
                    if (pc + 8 > code.length) {
                        return sb.append(at).append(": <truncated>\n").toString();
                    }
                    sb.append(at).append(": PUSH_U64 ").append(getU64(code, pc)).append('\n');
                    pc += 8;
                    break;
                case OP_EQ:
                    sb.append(at).append(": EQ\n");
                    break;
                case OP_AND:
                    sb.append(at).append(": AND\n");
                    break;
                case OP_JZ:
                    if (pc + 2 > code.length) {
                        return sb.append(at).append(": <truncated>\n").toString();
                    }
                    sb.append(at).append(": JZ ").append(getU16(code, pc)).append('\n');
                    pc += 2;
                    break;
                case OP_JMP:
                    if (pc + 2 > code.length) {
                        return sb.append(at).append(": <truncated>\n").toString();
                    }
                    sb.append(at).append(": JMP ").append(getU16(code, pc)).append('\n');
                    pc += 2;
                    break;
                case OP_RET:
                    if (pc + 4 > code.length) {
                        return sb.append(at).append(": <truncated>\n").toString();
                    }
                    sb.append(at).append(": RET ").append(getU32(code, pc)).append('\n');
                    pc += 4;
                    return sb.toString();
                default:
                    return sb.append(at).append(": <bad op ").append(op).append(">\n").toString();
            }
        }
        return sb.toString();
    }

    // ══════════════════ 参考解释器 ══════════════════

    /**
     * 在被控环境里跑字节码。
     *
     * 沙箱保证：
     *   · 只有 64 深度的小栈
     *   · 跳转只能向前（目标必须 > 当前 pc），所以**不可能死循环**
     *   · 步数上限 = 代码长度 × 4，超了就返回放行（失败安全）
     *   · 没有内存访问指令
     */
    public static int run(byte[] code, int uid, int dev, long ino) {
        long[] stack = new long[64];
        int sp = 0;
        int pc = 0;
        int steps = 0;
        int limit = code.length * 4 + 64;

        while (pc < code.length && steps++ < limit) {
            int op = code[pc++] & 0xFF;
            switch (op) {
                case OP_END:
                    return RET_ALLOW;
                case OP_PUSH_UID:
                    if (sp >= stack.length) {
                        return RET_ALLOW;
                    }
                    stack[sp++] = uid;
                    break;
                case OP_PUSH_DEV:
                    if (sp >= stack.length) {
                        return RET_ALLOW;
                    }
                    stack[sp++] = dev;
                    break;
                case OP_PUSH_INO:
                    if (sp >= stack.length) {
                        return RET_ALLOW;
                    }
                    stack[sp++] = ino;
                    break;
                case OP_PUSH_U32:
                    if (pc + 4 > code.length || sp >= stack.length) {
                        return RET_ALLOW;
                    }
                    stack[sp++] = getU32(code, pc);
                    pc += 4;
                    break;
                case OP_PUSH_U64:
                    if (pc + 8 > code.length || sp >= stack.length) {
                        return RET_ALLOW;
                    }
                    stack[sp++] = getU64(code, pc);
                    pc += 8;
                    break;
                case OP_EQ:
                    if (sp < 2) {
                        return RET_ALLOW;
                    }
                    {
                        long b2 = stack[--sp];
                        long a2 = stack[--sp];
                        stack[sp++] = (a2 == b2) ? 1 : 0;
                    }
                    break;
                case OP_AND:
                    if (sp < 2) {
                        return RET_ALLOW;
                    }
                    {
                        long b2 = stack[--sp];
                        long a2 = stack[--sp];
                        stack[sp++] = (a2 != 0 && b2 != 0) ? 1 : 0;
                    }
                    break;
                case OP_JZ:
                    if (pc + 2 > code.length || sp < 1) {
                        return RET_ALLOW;
                    }
                    {
                        int tgt = getU16(code, pc);
                        pc += 2;
                        long v = stack[--sp];
                        if (v == 0) {
                            /* 只允许向前跳，杜绝死循环 */
                            if (tgt <= pc || tgt > code.length) {
                                return RET_ALLOW;
                            }
                            pc = tgt;
                        }
                    }
                    break;
                case OP_JMP:
                    if (pc + 2 > code.length) {
                        return RET_ALLOW;
                    }
                    {
                        int tgt = getU16(code, pc);
                        pc += 2;
                        if (tgt <= pc || tgt > code.length) {
                            return RET_ALLOW;
                        }
                        pc = tgt;
                    }
                    break;
                case OP_RET:
                    if (pc + 4 > code.length) {
                        return RET_ALLOW;
                    }
                    return getU32(code, pc);
                default:
                    /* 不认识的操作码 → 失败安全，放行 */
                    return RET_ALLOW;
            }
        }
        return RET_ALLOW;
    }

    // ══════════════════ 混淆 ══════════════════

    /**
     * 字节级混淆：XOR 密钥流（含随机 salt）。
     *
     * 对称的 —— 再调一次就还原。真正保护强度靠外层的 AES 加密，
     * 这一层只是让「解出明文之后也不能直接看懂」。
     */
    public static byte[] xorMask(byte[] code, byte[] salt) {
        if (code == null || salt == null || salt.length == 0) {
            return code;
        }
        byte[] out = new byte[code.length];
        int s = 0;
        for (int i = 0; i < code.length; i++) {
            /* 滚动密钥：salt 循环 + 位置扰动 */
            int k = salt[s] ^ (byte) (i * 131);
            out[i] = (byte) (code[i] ^ k);
            s = (s + 1) % salt.length;
        }
        return out;
    }

    // ══════════════════ 小端工具 ══════════════════

    private static void putU16(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >>> 8) & 0xFF);
    }

    private static void putU32(ByteArrayOutputStream o, int v) {
        UmCrypto.putInt(o, v);
    }

    private static void putU64(ByteArrayOutputStream o, long v) {
        for (int i = 0; i < 8; i++) {
            o.write((int) ((v >>> (i * 8)) & 0xFF));
        }
    }

    private static int getU16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static int getU32(byte[] b, int off) {
        return UmCrypto.getInt(b, off);
    }

    private static long getU64(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; i--) {
            v = (v << 8) | (b[off + i] & 0xFFL);
        }
        return v;
    }
}
