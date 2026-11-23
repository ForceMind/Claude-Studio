package dev.claudestudio.browser

import android.app.Activity
import com.google.android.play.core.appupdate.AppUpdateInfo
import com.google.android.play.core.appupdate.AppUpdateManagerFactory
import com.google.android.play.core.appupdate.AppUpdateOptions
import com.google.android.play.core.install.model.AppUpdateType
import com.google.android.play.core.install.model.UpdateAvailability

/** Play channel delegates delivery and package authentication to Google Play, never website APKs. */
class ChannelUpdateClient(private val activity: Activity) : UpdateClient {
    private val manager by lazy { AppUpdateManagerFactory.create(activity) }
    private var available: AppUpdateInfo? = null
    override fun check(callback: (UpdateResult) -> Unit) {
        if (!BuildConfig.PLAY_UPDATE_ENABLED) {
            callback(UpdateResult.Blocked("Play 检查未启用：尚无获批包名、Play 测试轨道与签名配置。未调用 Play API。"))
            return
        }
        manager.appUpdateInfo.addOnSuccessListener { info ->
            available = info.takeIf {
                it.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE &&
                    it.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)
            }
            callback(available?.let { UpdateResult.Available("Play versionCode ${it.availableVersionCode()}") }
                ?: UpdateResult.Current)
        }.addOnFailureListener { callback(UpdateResult.Unreachable("Play 检查失败；稍后重试。")) }
    }
    override fun confirmInstall(activity: Activity, publish: (String) -> Unit) {
        if (!BuildConfig.PLAY_UPDATE_ENABLED) { publish("Play 安装未启用。"); return }
        val info = available ?: run { publish("没有可确认的 Play 更新，请先检查。"); return }
        // Only this explicit action opens Play's own consent, download and installation flow.
        try {
            available = null
            manager.startUpdateFlow(info, activity,
                AppUpdateOptions.newBuilder(AppUpdateType.IMMEDIATE).build())
                .addOnSuccessListener { result ->
                    publish(if (result == Activity.RESULT_CANCELED) "已取消 Play 更新；可继续使用。"
                        else if (result == Activity.RESULT_OK) "Play 更新流程已返回；实际安装由 Play 确认。"
                        else "Play 更新未完成，请重新检查后再确认。")
                }.addOnFailureListener { publish("Play 更新未完成，请重新检查后再确认。") }
            publish("已请求 Play 确认界面；完成与取消由 Play 管理。")
        } catch (_: Exception) { publish("Play 更新界面无法启动，请重新检查。"); available = null }
    }
}
