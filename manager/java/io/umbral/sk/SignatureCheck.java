package io.umbral.sk;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.io.File;
import java.io.FileOutputStream;
import java.security.MessageDigest;

/**
 * 管理器签名摘要 —— 授权表要绑定的「身份」。
 *
 * ══════════════════════════════════════════════════════
 *  为什么要它（对齐 KernelSU 的 signature 机制）
 * ══════════════════════════════════════════════════════
 *
 *  KSU 的 allowlist 不是只记 uid，而是记 (uid, 包名, APK 签名)。
 *  原因很实际：uid 可以被冒用 —— 任何拿到同一个 uid 的东西都能
 *  自称「管理器」然后给自己发授权。
 *
 *  我们现在的授权表只记 uid（/proc/umbral/grants 里 `uid 10563 shadow`），
 *  所以下面这种情况会出问题：
 *      别的 App 伪造一个同样的 uid，或者管理器被替换成改了签名的版本
 *      → 授权照样发下去
 *
 *  这一版的职责：把本 APK 的签名摘要算出来、落盘、暴露给自检。
 *  内核侧校验（su 请求时比对）需要改内核，等 WSL 修好后接。
 */
public final class SignatureCheck {

    public static final String OUT_PATH = "/data/local/tmp/umbral/signature.txt";

    /** 最近一次算出来的摘要（sha256，小写 hex） */
    public static String digest = "";
    /** 包名 + versionCode，便于核对 */
    public static String identity = "";

    private SignatureCheck() {
    }

    /**
     * 算签名摘要并存盘。
     *
     * @return 摘要字符串；失败返回空串
     */
    @SuppressWarnings("deprecation")
    public static String record(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();

            Signature[] sigs;
            try {
                /* API 28+ */
                PackageInfo pi = pm.getPackageInfo(pkg,
                        PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi.signingInfo != null) {
                    sigs = pi.signingInfo.hasMultipleSigners()
                            ? pi.signingInfo.getApkContentsSigners()
                            : pi.signingInfo.getSigningCertificateHistory();
                } else {
                    sigs = null;
                }
            } catch (Throwable t) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                sigs = pi.signatures;
            }

            if (sigs == null || sigs.length == 0) {
                return "";
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (Signature s : sigs) {
                if (s != null) {
                    md.update(s.toByteArray());
                }
            }
            byte[] d = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            digest = sb.toString();

            PackageInfo any = pm.getPackageInfo(pkg, 0);
            identity = pkg + " v" + any.versionCode;

            /* 落盘：内核侧（以后）和自检都读这一份 */
            File f = new File(OUT_PATH);
            File dir = f.getParentFile();
            if (dir != null && !dir.exists()) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
            }
            FileOutputStream fo = new FileOutputStream(f, false);
            fo.write((digest + "\n" + identity + "\n").getBytes("UTF-8"));
            fo.flush();
            fo.getFD().sync();
            fo.close();

            return digest;
        } catch (Throwable t) {
            return "";
        }
    }
}
