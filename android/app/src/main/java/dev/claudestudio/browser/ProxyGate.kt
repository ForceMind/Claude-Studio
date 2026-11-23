package dev.claudestudio.browser

import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import java.util.concurrent.Executor

/** One common process-wide HTTP upstream. No per-profile or OS-wide isolation is claimed. */
class ProxyGate {
    @Volatile var ready = false
        private set
    private var applying = false
    fun apply(host: String, portText: String, executor: Executor, publish: (String) -> Unit) {
        if (ready || applying) { publish("本次运行的共同代理已锁定；更换前请完全退出原型。"); return }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            publish("当前 WebView 不支持 PROXY_OVERRIDE，所有页面保持关闭。"); return
        }
        // Numeric IPv4 only: do not silently resolve a proxy hostname through Android DNS.
        val octets = host.split('.')
        val port = portText.toIntOrNull()
        if (octets.size != 4 || octets.any { octet ->
                val number = octet.toIntOrNull()
                octet.isEmpty() || octet.any { c -> c !in '0'..'9' } ||
                    number == null || number !in 0..255 || octet != number.toString()
            } || port == null || port !in 1..65535) {
            publish("请输入明确的数字 IPv4 HTTP 上游和 1–65535 端口；不接受凭据、PAC 或 DIRECT。"); return
        }
        applying = true
        try {
            val config = ProxyConfig.Builder().addProxyRule("http://$host:$port")
                .removeImplicitRules().build()
            ProxyController.getInstance().setProxyOverride(config, executor) {
                applying = false
                ready = true
                publish("共同 HTTP 代理设置已应用。尚未验证上游可用性或网络隔离；可打开本地合成页。")
            }
        } catch (_: RuntimeException) {
            applying = false
            publish("代理设置失败，所有页面保持关闭。")
        }
    }
}
