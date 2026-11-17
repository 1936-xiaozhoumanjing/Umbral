package io.umbral;

import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * 隐私与合规说明页。
 *
 * 目的：把「本应用到底做了什么、没做什么、数据去哪了」一次讲清，
 * 而不是弹一个 AlertDialog 塞两行字。
 */
public class PrivacyActivity extends BaseActivity {

    private static final String BODY =
        "一、本应用做了什么\n"
      + "1. 内核模块（umbral）在你自己的设备上提供影子权限：让被授权的进程获得 root 能力，"
      + "而 uid 保持不变。全部逻辑在内核态完成，不修改系统分区。\n"
      + "2. 刷入功能：把本应用自带的 first-stage init 与内核模块写入你选择的引导镜像（boot / init_boot / vendor_boot），"
      + "由你自己决定是否刷入。\n"
      + "3. 模块管理：识别并启停标准格式的 ZIP 模块（module.prop + 脚本），与 Magisk / KernelSU 生态兼容。\n"
      + "4. 启动状态伪装（可选，默认关闭）：把 ro.boot.verifiedbootstate 与 ro.boot.flash.locked "
      + "在内存中改写为未解锁状态。该改动只存在于内存，重启即恢复。\n"
      + "\n二、本应用不做什么\n"
      + "1. 不收集、不上传任何个人信息、设备标识、应用列表或使用记录。\n"
      + "2. 不包含广告、统计 SDK、远程配置或任何联网上报逻辑。\n"
      + "3. 不修改系统 APK、不注入第三方应用、不窃取凭据。\n"
      + "4. 不提供、也不下载任何游戏辅助、外挂或破解内容。\n"
      + "\n三、数据存放位置\n"
      + "1. 授权名单、模块状态、日志：仅保存在本应用私有目录 "
      + "/data/data/io.umbral/（卸载即删除）。\n"
      + "2. 内核模块与 init：随刷入镜像存在，或在使用时临时释放到私有目录，"
      + "用完即删，不写入公共存储。\n"
      + "3. 本应用不建立账号体系，不需要也不要求任何账号信息。\n"
      + "\n四、权限说明\n"
      + "· 存储权限：读取你选择的引导镜像文件、导入导出模块包。\n"
      + "· 查询应用列表：用于展示可授权的应用并给它们分配影子权限。\n"
      + "· 网络权限：仅用于本机回环地址 127.0.0.1 上的本地网页服务"
      + "（模块自带的网页界面），不发起任何外部网络请求。\n"
      + "\n五、风险与责任\n"
      + "1. 修改引导镜像、启用影子权限会改变设备的安全状态，可能导致保修失效、"
      + "部分应用拒绝运行（如银行、支付、部分游戏）。\n"
      + "2. 刷入操作前请务必自行备份原始镜像，并确认具备救砖手段（fastboot / 9008）。\n"
      + "3. 是否使用、如何使用，完全由你自行决定并承担相应后果。\n"
      + "4. 请在符合当地法律法规的前提下使用本工具；不得用于侵犯他人权益。\n"
      + "\n六、卸载与还原\n"
      + "1. 卸载本应用不会移除已刷入的内核模块；还原方法是刷回原始引导镜像。\n"
      + "2. 本应用无后台常驻服务，卸载后不残留进程。\n"
      + "3. 启动状态伪装在重启后自动失效，无需额外还原。";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        setTitle("隐私与合规");

        ScrollView sv = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (18 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView tv = new TextView(this);
        tv.setText(BODY);
        tv.setTextSize(13);
        tv.setLineSpacing(0, 1.35f);
        tv.setGravity(Gravity.START);
        root.addView(tv);

        sv.addView(root);
        setContentView(sv);
    }
}
