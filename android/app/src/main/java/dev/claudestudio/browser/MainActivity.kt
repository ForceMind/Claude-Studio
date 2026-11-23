package dev.claudestudio.browser

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Bitmap
import android.net.ConnectivityManager
import android.net.Network
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.os.SystemClock
import android.view.ViewGroup
import android.webkit.WebChromeClient
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.webkit.ProfileStore
import androidx.webkit.WebStorageCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.io.ByteArrayInputStream
import java.lang.ref.WeakReference
import java.util.UUID

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val policy = UpdatePolicy(System.currentTimeMillis())
    private val gate = ProxyGate()
    private val views = mutableMapOf<Pair<String, String>, WebView>()
    private val closedTabs = ClosedTabs(SystemClock::elapsedRealtime, ::destroyView)
    private val tabExpiry = Runnable { scheduleTabExpiry(); renderTabs() }
    private lateinit var sessions: SessionStore
    private lateinit var accounts: LinearLayout
    private lateinit var pageHost: LinearLayout
    private lateinit var tabBar: LinearLayout
    private lateinit var restoreButton: Button
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
        accounts = row(root)
        row(root).apply {
            button(this, "账号设置", ::showAccountSettings)
            button(this, "关闭标签", ::closeSelectedTab)
            restoreButton = button(this, "撤销关闭", ::restoreTab).also { it.isEnabled = false }
        }
        tabBar = row(root)
        tabBar.addOnLayoutChangeListener { _, left, _, right, _, oldLeft, _, oldRight, _ ->
            if (right - left != oldRight - oldLeft) tabBar.post { if (!destroyed) renderTabs() }
        }
        pageHost = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(pageHost, LinearLayout.LayoutParams(-1, 0, 1f))
        profilesReady = initializeProfiles()
        renderAccounts()
        if (profilesReady) sessions.accountOrder.filter(sessions.loginCleanup.isPending).forEach(::clearLogin)
        try {
            connectivity = getSystemService(ConnectivityManager::class.java)
            connectivity?.registerDefaultNetworkCallback(networkCallback)
        } catch (_: RuntimeException) { /* Foreground reconciliation still runs every minute. */ }
        // Each cold launch is a startup check; configuration changes are handled by this Activity.
        policy.open()
    }

    private fun renderAccounts() {
        accounts.removeAllViews()
        val order = if (profilesReady) sessions.accountOrder else listOf("A", "B")
        order.forEach { account -> button(accounts, "账号 $account") {
            if (canOpen(account)) {
                sessions.activeAccount = account
                if (persist()) showSelected()
            } else pageStatus.text = if (profilesReady && sessions.loginCleanup.isPending(account))
                "账号 $account 正在等待清除本机登录。" else "需要多资料能力和已应用的共同代理。"
        } }
        button(accounts, "新标签") {
            if (profilesReady && canOpen(sessions.activeAccount)) addTab(sessions.activeAccount, false, true)
            else pageStatus.text = "尚未满足导航条件。"
        }
    }

    private fun canOpen(account: String): Boolean = profilesReady && gate.ready && !sessions.loginCleanup.isPending(account)

    private fun showAccountSettings() {
        if (!profilesReady) return
        val order = sessions.accountOrder
        val options = (listOf("交换账号顺序") + order.map { "清除账号 $it 的本机登录" }).toTypedArray()
        AlertDialog.Builder(this).setTitle("账号设置").setItems(options) { _, index ->
            if (index == 0) {
                sessions.swapAccounts()
                if (persist()) renderAccounts()
            } else {
                val account = order[index - 1]
                AlertDialog.Builder(this).setTitle("清除账号 $account 的本机登录？")
                    .setMessage("该账号的 Cookie、网站存储和缓存将清除，本地草稿可能丢失。已保存的标签地址仍可打开。")
                    .setNegativeButton("取消", null).setPositiveButton("清除") { _, _ -> clearLogin(account) }.show()
            }
        }.show()
    }

    private fun clearLogin(account: String) {
        if (!profilesReady || destroyed) return
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.DELETE_BROWSING_DATA)) {
            pageStatus.text = "当前 WebView 不支持按账号清除本机登录。"
            return
        }
        val cleanup = sessions.loginCleanup
        val token = try { cleanup.begin(account) } catch (_: RuntimeException) {
            pageStatus.text = "无法保存清理状态，请重试。"
            return
        } ?: return
        val activity = WeakReference(this)
        try {
            val profile = checkNotNull(ProfileStore.getInstance().getProfile(profileName(account)))
            views.keys.filter { it.first == account }.forEach { key -> views.remove(key)?.let(::destroyView) }
            closedTabs.clear(account)
            scheduleTabExpiry()
            if (sessions.activeAccount == account) renderTabs()
            pageStatus.text = "正在清除账号 $account 的本机登录。"
            WebStorageCompat.deleteBrowsingData(profile.webStorage) {
                val completed = try { cleanup.finish(account, token) } catch (_: RuntimeException) {
                    activity.get()?.onLoginCleanupFinished(account, false)
                    return@deleteBrowsingData
                }
                if (completed) activity.get()?.onLoginCleanupFinished(account, true)
            }
        } catch (_: RuntimeException) {
            cleanup.fail(account, token)
            onLoginCleanupFinished(account, false)
        }
    }

    private fun onLoginCleanupFinished(account: String, completed: Boolean) {
        if (destroyed || !profilesReady) return
        if (completed && sessions.activeAccount == account && canOpen(account)) showSelected()
        pageStatus.text = if (completed) "已清除账号 $account 的本机登录。"
            else "账号 $account 的本机登录清理未完成，请在账号设置重试。"
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

    override fun onStart() { super.onStart(); active = true; scheduleTabExpiry(); reconcile() }
    override fun onStop() {
        active = false
        handler.removeCallbacks(tick)
        if (profilesReady) {
            sessions.accountOrder.filterNot(sessions.loginCleanup.isPending).forEach {
                ProfileStore.getInstance().getProfile(profileName(it))?.cookieManager?.flush()
            }
            persist()
        }
        super.onStop()
    }
    override fun onDestroy() {
        destroyed = true
        handler.removeCallbacksAndMessages(null)
        try { connectivity?.unregisterNetworkCallback(networkCallback) } catch (_: RuntimeException) { }
        closedTabs.clear()
        views.values.forEach(::destroyView)
        views.clear()
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
        if (!canOpen(account)) return null
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

    private fun closeSelectedTab() {
        if (!profilesReady) return
        val account = sessions.activeAccount
        if (!canOpen(account)) return
        val tabs = sessions.tabs.getValue(account)
        val index = tabs.indexOfFirst { it.id == sessions.selected[account] }
        val tab = tabs.removeAt(index)
        views.remove(account to tab.id)?.let { page ->
            if (!tab.popup && tab.url == SessionStore.HOME && page.url == tab.url && page.progress == 100 && tabs.none { it.popup }) {
                (page.parent as? ViewGroup)?.removeView(page)
                page.onPause()
                closedTabs.remember(account, tab, index, page)
                scheduleTabExpiry()
            } else destroyView(page)
        }
        if (tabs.isEmpty()) tabs += SavedTab(UUID.randomUUID().toString(), SessionStore.HOME)
        sessions.selected[account] = tabs[minOf(index, tabs.lastIndex)].id
        if (persist()) showSelected()
    }

    private fun restoreTab() {
        if (!profilesReady) return
        val account = sessions.activeAccount
        if (!canOpen(account)) return
        val tabs = sessions.tabs.getValue(account)
        if (tabs.size >= SessionStore.MAX_TABS) return
        val entry = closedTabs.take(account) ?: return renderTabs()
        scheduleTabExpiry()
        val page = entry.page
        if (page != null && page.url != entry.tab.url) {
            destroyView(page)
            renderTabs()
            return
        }
        tabs.add(entry.index.coerceAtMost(tabs.size), entry.tab)
        sessions.selected[account] = entry.tab.id
        if (persist()) {
            if (page != null) views[account to entry.tab.id] = page
            showSelected()
        } else if (page != null) destroyView(page)
    }

    private fun scheduleTabExpiry() {
        handler.removeCallbacks(tabExpiry)
        closedTabs.expire()
        closedTabs.nextExpiry()?.let { handler.postDelayed(tabExpiry, (it - SystemClock.elapsedRealtime()).coerceAtLeast(1)) }
    }

    private fun destroyView(view: WebView) {
        (view.parent as? ViewGroup)?.removeView(view)
        view.destroy()
    }

    private fun createView(account: String, tab: SavedTab): WebView {
        check(canOpen(account))
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
                    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                        if (views[account to tab.id] !== view && request.isForMainFrame) discardClosedNavigation(account, tab.id, view)
                        return views[account to tab.id] !== view || !canOpen(account) || !SessionStore.isSyntheticUrl(request.url.toString())
                    }
                    override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
                        if (views[account to tab.id] !== view) discardClosedNavigation(account, tab.id, view)
                    }
                    override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
                        val key = account to tab.id
                        if (views[key] === view) {
                            views.remove(key)
                            destroyView(view)
                            if (sessions.activeAccount == account) pageStatus.text = "网页进程已退出，请重新选择标签。"
                        } else closedTabs.discard(account, tab.id, view)
                        return true
                    }
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
                        if (!isUserGesture || !canOpen(account) || sessions.activeAccount != account ||
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

    private fun discardClosedNavigation(account: String, tab: String, view: WebView) {
        handler.post {
            if (closedTabs.discard(account, tab, view)) {
                scheduleTabExpiry()
                renderTabs()
            }
        }
    }

    private fun showSelected(navigate: Boolean = true) {
        if (!profilesReady || !canOpen(sessions.activeAccount)) return
        val account = sessions.activeAccount
        val list = sessions.tabs.getValue(account)
        val selected = list.first { it.id == sessions.selected[account] }
        val existing = views[account to selected.id]
        val web = existing ?: createView(account, selected)
        pageHost.removeAllViews()
        (web.parent as? ViewGroup)?.removeView(web)
        pageHost.addView(web, LinearLayout.LayoutParams(-1, -1))
        web.onResume()
        renderTabs()
        pageStatus.text = "账户 $account · ${if (selected.popup) "合成弹窗" else "合成标签"} · ${selected.url}"
        if (navigate && existing == null) web.loadUrl(selected.url)
    }

    private fun renderTabs() {
        tabBar.removeAllViews()
        restoreButton.isEnabled = false
        if (!profilesReady || !canOpen(sessions.activeAccount)) return
        val account = sessions.activeAccount
        val tabs = sessions.tabs.getValue(account)
        restoreButton.isEnabled = tabs.size < SessionStore.MAX_TABS && closedTabs.has(account)
        val selected = tabs.indexOfFirst { it.id == sessions.selected[account] }
        val slotWidth = (84 * resources.displayMetrics.density).toInt().coerceAtLeast(1)
        val inline = visibleTabIndices(tabs.size, selected, tabBar.width / slotWidth)
        val hidden = tabs.indices.filterNot { it in inline }
        fun label(index: Int) = "$account ${index + 1}${if (tabs[index].popup) " 弹窗" else ""}"
        fun choose(id: String) {
            if (canOpen(account) && sessions.activeAccount == account && tabs.any { it.id == id }) {
                sessions.selected[account] = id
                if (persist()) showSelected()
            }
        }
        inline.forEach { index ->
            val id = tabs[index].id
            tabButton(label(index)) { choose(id) }.isEnabled = index != selected
        }
        if (hidden.isNotEmpty()) {
            val labels = hidden.map(::label).toTypedArray()
            val ids = hidden.map { tabs[it].id }
            tabButton("更多") {
                AlertDialog.Builder(this).setTitle("账号 $account 的其他标签")
                    .setItems(labels) { _, index -> choose(ids[index]) }.show()
            }
        }
    }

    private fun tabButton(label: String, action: () -> Unit): Button = button(tabBar, label, action).also {
        it.layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        it.minWidth = 0
        it.minimumWidth = 0
        it.setPadding(0, it.paddingTop, 0, it.paddingBottom)
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
