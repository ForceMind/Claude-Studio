package dev.claudestudio.browser

import android.app.Activity
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.view.ViewGroup
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.webkit.ProfileStore
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.io.ByteArrayInputStream
import java.util.UUID

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val policy = UpdatePolicy(System.currentTimeMillis())
    private val gate = ProxyGate()
    private val views = mutableMapOf<Pair<String, String>, WebView>()
    private lateinit var sessions: SessionStore
    private lateinit var pageHost: LinearLayout
    private lateinit var tabBar: LinearLayout
    private lateinit var pageStatus: TextView
    private lateinit var updateStatus: TextView
    private lateinit var updates: UpdateClient
    private var profilesReady = false
    private var active = false
    private var destroyed = false
    private var connectivity: ConnectivityManager? = null
    private var checkGeneration = 0
    private var checkTimeout: Runnable? = null
    private val tick = Runnable { reconcile() }
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { handler.post { policy.online(); reconcile() } }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(16, 16, 16, 16) }
        setContentView(root)
        root.addView(TextView(this).apply { text = "Claude Browser Android · 合成原型\n仅 A/B 合成资料；真实网页、下载与发布关闭。" })
        pageStatus = TextView(this).also { root.addView(it) }
        updateStatus = TextView(this).also { root.addView(it) }
        updates = createUpdateClient(this)
        row(root).apply {
            button(this, "确认安装更新") { updates.confirmInstall(this@MainActivity) { updateStatus.text = it } }
        }
        val proxyRow = row(root)
        val host = EditText(this).apply { hint = "HTTP 代理 IPv4"; setSingleLine() }
        val port = EditText(this).apply { hint = "端口"; inputType = 2; setSingleLine() }
        proxyRow.addView(host, LinearLayout.LayoutParams(0, -2, 2f))
        proxyRow.addView(port, LinearLayout.LayoutParams(0, -2, 1f))
        button(root, "应用共同代理（本次运行锁定）") {
            if (profilesReady) gate.apply(host.text.toString(), port.text.toString(),
                java.util.concurrent.Executor { command -> handler.post(command) }) { pageStatus.text = it }
        }
        val accounts = row(root)
        listOf("A", "B").forEach { account -> button(accounts, "账户 $account") {
            if (profilesReady && gate.ready) {
                sessions.activeAccount = account; persist(); showSelected()
            } else pageStatus.text = "需要 MULTI_PROFILE 和已应用的共同代理；未导航。"
        } }
        button(accounts, "新合成标签") {
            if (profilesReady && gate.ready) addTab(sessions.activeAccount, false, true)
            else pageStatus.text = "尚未满足导航条件。"
        }
        tabBar = row(root)
        pageHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(pageHost, LinearLayout.LayoutParams(-1, 0, 1f))
        profilesReady = initializeProfiles()
        try {
            connectivity = getSystemService(ConnectivityManager::class.java)
            connectivity?.registerDefaultNetworkCallback(networkCallback)
        } catch (_: RuntimeException) { /* Foreground reconciliation still runs every minute. */ }
        // Each cold launch is a startup check; configuration changes are handled by this Activity.
        policy.open()
    }

    private fun initializeProfiles(): Boolean {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            pageStatus.text = "WebView 缺少 MULTI_PROFILE，拒绝开启多账号；不退回默认 CookieManager。"
            return false
        }
        return try {
            sessions = SessionStore(this)
            val store = ProfileStore.getInstance()
            listOf("A", "B").forEach { store.getOrCreateProfile(profileName(it)) }
            pageStatus.text = "A/B 持久资料已准备；尚未应用代理，未创建或导航 WebView。"
            true
        } catch (_: Exception) {
            pageStatus.text = "资料初始化失败；保留原始资料，关闭页面入口。"
            false
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        policy.open() // A new launcher intent is an explicit open, unlike ordinary foreground resume.
        reconcile()
    }

    override fun onStart() { super.onStart(); active = true; reconcile() }
    override fun onStop() {
        active = false
        handler.removeCallbacks(tick)
        if (profilesReady) {
            listOf("A", "B").forEach { ProfileStore.getInstance().getProfile(profileName(it))?.cookieManager?.flush() }
            persist()
        }
        super.onStop()
    }
    override fun onDestroy() {
        destroyed = true
        handler.removeCallbacksAndMessages(null)
        try { connectivity?.unregisterNetworkCallback(networkCallback) } catch (_: RuntimeException) { }
        views.values.forEach { view -> (view.parent as? ViewGroup)?.removeView(view); view.destroy() }
        updates.close()
        super.onDestroy()
    }

    private fun reconcile() {
        if (!active || destroyed) return
        handler.removeCallbacks(tick)
        val check = policy.poll(System.currentTimeMillis())
        if (check != null) {
            updateStatus.text = "正在检查 ${check.trigger}；不会自动下载或安装。"
            val generation = ++checkGeneration
            checkTimeout = Runnable {
                if (!destroyed && generation == checkGeneration) {
                    checkGeneration++
                    policy.complete(System.currentTimeMillis(), false)
                    updateStatus.text = "更新检查超时；恢复后按退避策略重试，不下载。"
                    reconcile()
                }
            }.also { handler.postDelayed(it, 15_000) }
            updates.check { result -> handler.post {
                if (!destroyed && generation == checkGeneration) {
                    checkGeneration++
                    checkTimeout?.let { handler.removeCallbacks(it) }
                    checkTimeout = null
                    policy.complete(System.currentTimeMillis(),
                        result is UpdateResult.Current || result is UpdateResult.Available,
                        result is UpdateResult.Blocked)
                    updateStatus.text = when (result) {
                        UpdateResult.Current -> "检查完成，没有更新。"
                        is UpdateResult.Available -> "发现更新：${result.description}；等待确认。"
                        is UpdateResult.Blocked -> result.reason
                        is UpdateResult.Unreachable -> result.reason
                    }
                    reconcile()
                }
            } }
        } else handler.postDelayed(tick, policy.nextDelay(System.currentTimeMillis()))
    }

    private fun addTab(account: String, popup: Boolean, navigate: Boolean): WebView? {
        val tabs = sessions.tabs.getValue(account)
        if (tabs.size >= SessionStore.MAX_TABS) { pageStatus.text = "每账户最多 12 个合成标签。"; return null }
        val tab = SavedTab(UUID.randomUUID().toString(), SessionStore.HOME, popup)
        tabs += tab
        sessions.activeAccount = account
        sessions.selected[account] = tab.id
        if (!persist()) return null
        val view = createView(account, tab)
        showSelected(false)
        if (navigate) view.loadUrl(tab.url)
        return view
    }

    private fun createView(account: String, tab: SavedTab): WebView {
        check(profilesReady && gate.ready)
        return views.getOrPut(account to tab.id) {
            WebView(this).also { web ->
                // MUST be the first operation after construction, including popup transport WebViews.
                WebViewCompat.setProfile(web, profileName(account))
                web.settings.apply {
                    javaScriptEnabled = true
                    domStorageEnabled = true
                    setSupportMultipleWindows(true)
                    javaScriptCanOpenWindowsAutomatically = false
                    allowFileAccess = false
                    allowContentAccess = false
                    mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW
                    blockNetworkLoads = true // Local assets only, even after the proxy callback.
                }
                val loader = WebViewAssetLoader.Builder().addPathHandler("/assets/",
                    WebViewAssetLoader.AssetsPathHandler(this)).build()
                web.webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
                        !gate.ready || !SessionStore.isSyntheticUrl(request.url.toString())
                    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse {
                        if (gate.ready && SessionStore.isSyntheticUrl(request.url.toString())) {
                            loader.shouldInterceptRequest(request.url)?.let { return it }
                        }
                        return WebResourceResponse("text/plain", "UTF-8", 403, "Blocked",
                            emptyMap(), ByteArrayInputStream("Synthetic prototype: external content blocked".toByteArray()))
                    }
                    override fun onPageFinished(view: WebView, url: String) {
                        if (views[account to tab.id] !== view) return
                        if (SessionStore.isSyntheticUrl(url)) { tab.url = url; persist() }
                        if (profilesReady && sessions.activeAccount == account && sessions.selected[account] == tab.id) {
                            pageStatus.text = "账户 $account · ${if (tab.popup) "合成弹窗" else "合成标签"} · $url"
                        }
                    }
                }
                web.webChromeClient = object : WebChromeClient() {
                    override fun onCreateWindow(view: WebView, isDialog: Boolean, isUserGesture: Boolean, resultMsg: Message): Boolean {
                        if (!isUserGesture || !profilesReady || !gate.ready || sessions.activeAccount != account ||
                            sessions.selected[account] != tab.id || views[account to tab.id] !== view) return false
                        val child = addTab(account, true, false) ?: return false
                        val transport = resultMsg.obj as WebView.WebViewTransport
                        transport.webView = child
                        resultMsg.sendToTarget() // Chromium performs its first navigation; never replay with loadUrl.
                        return true
                    }
                    override fun onCloseWindow(window: WebView) {
                        val list = sessions.tabs.getValue(account)
                        val index = list.indexOfFirst { it.popup && views[account to it.id] === window }
                        if (list.size <= 1 || index == -1) return
                        val closed = list.removeAt(index)
                        views.remove(account to closed.id)
                        (window.parent as? ViewGroup)?.removeView(window)
                        window.destroy()
                        if (sessions.selected[account] == closed.id) {
                            sessions.selected[account] = list[minOf(index, list.lastIndex)].id
                        }
                        if (persist() && sessions.activeAccount == account) showSelected()
                    }
                }
            }
        }
    }

    private fun showSelected(navigate: Boolean = true) {
        if (!profilesReady || !gate.ready) return
        val account = sessions.activeAccount
        val list = sessions.tabs.getValue(account)
        val selected = list.first { it.id == sessions.selected[account] }
        val existing = views[account to selected.id]
        val web = existing ?: createView(account, selected)
        pageHost.removeAllViews()
        (web.parent as? ViewGroup)?.removeView(web)
        pageHost.addView(web, LinearLayout.LayoutParams(-1, -1))
        tabBar.removeAllViews()
        list.forEachIndexed { index, tab -> button(tabBar, "$account ${index + 1}${if (tab.popup) " 弹窗" else ""}") {
            sessions.selected[account] = tab.id; persist(); showSelected()
        } }
        pageStatus.text = "账户 $account · ${if (selected.popup) "合成弹窗" else "合成标签"} · ${selected.url}"
        if (navigate && existing == null) web.loadUrl(selected.url)
    }
    private fun persist(): Boolean = try { sessions.save(); true } catch (_: Exception) {
        profilesReady = false
        views.values.forEach { it.stopLoading(); it.settings.blockNetworkLoads = true }
        pageHost.removeAllViews()
        pageStatus.text = "资料保存失败，已关闭页面入口；保留原始资料。"
        false
    }
    private fun profileName(account: String) = "claude-browser-$account-v1"
    private fun row(parent: LinearLayout) = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; parent.addView(this) }
    private fun button(parent: LinearLayout, label: String, action: () -> Unit) = Button(this).also {
        it.text = label; it.setOnClickListener { action() }; parent.addView(it)
    }
}
