package dev.claudestudio.browser

import android.app.Activity

/** Website channel intentionally has no downloader, URL or installer until trust is provisioned. */
class ChannelUpdateClient : UpdateClient {
    override fun check(callback: (UpdateResult) -> Unit) = callback(UpdateResult.Blocked(
        "官网 APK 更新未启用：缺少签名清单、公钥、HTTPS 源与已批准的应用签名。未联网、未下载。"))
    override fun confirmInstall(activity: Activity, publish: (String) -> Unit) =
        publish("安装已关闭：必须先验签、核对 APK 包名/签名证书与更高 versionCode，再由用户确认系统安装。")
}
