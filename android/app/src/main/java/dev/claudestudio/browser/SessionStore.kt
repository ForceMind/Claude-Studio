package dev.claudestudio.browser

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class SavedTab(val id: String, var url: String, val popup: Boolean = false)

internal data class AccountLayout(
    var accountOrder: List<String>,
    var activeAccount: String,
    val tabs: Map<String, MutableList<SavedTab>>,
    val selected: MutableMap<String, String>
) {
    fun without(account: String): AccountLayout {
        require(account in accountOrder) { "账号不存在。" }
        require(accountOrder.size > 1) { "至少保留一个账号。" }
        val retained = accountOrder.filterNot { it == account }
        return AccountLayout(retained, activeAccount.takeUnless { it == account } ?: retained.first(),
            tabs - account, (selected - account).toMutableMap())
    }

    fun encode(): String {
        val root = JSONObject().put("schema", if (accountOrder.size == 2) 1 else 2)
            .put("activeAccount", activeAccount).put("selected", JSONObject(selected))
            .put("accountOrder", JSONArray(accountOrder))
        tabs.forEach { (account, list) ->
            val values = JSONArray()
            list.forEach { values.put(JSONObject().put("id", it.id).put("url", it.url).put("popup", it.popup)) }
            root.put(account, values)
        }
        return root.toString()
    }

    companion object {
        private val defaults = listOf("A", "B")

        fun mayRemove(order: List<String>, account: String, pending: String?): Boolean =
            order.size > 1 && account in order && (pending == null || pending == account)

        fun create(): AccountLayout {
            val tabs = defaults.associateWith { mutableListOf(SavedTab(UUID.randomUUID().toString(), SessionStore.HOME)) }
            return AccountLayout(defaults, defaults.first(), tabs, tabs.mapValues { it.value.first().id }.toMutableMap())
        }

        fun read(raw: String): AccountLayout {
            val root = JSONObject(raw)
            val order = order(root)
            val active = root.getString("activeAccount")
            require(active in order) { "活动账号不在资料清单内。" }
            val selections = root.getJSONObject("selected")
            val tabs = order.associateWith { account ->
                val array = root.getJSONArray(account)
                require(array.length() in 1..SessionStore.MAX_TABS)
                val ids = mutableSetOf<String>()
                MutableList(array.length()) { index ->
                    val tab = array.getJSONObject(index)
                    val id = tab.getString("id")
                    val url = tab.getString("url")
                    require(id.isNotBlank() && ids.add(id) && SessionStore.isSyntheticUrl(url))
                    SavedTab(id, url, tab.optBoolean("popup"))
                }
            }
            val selected = order.associateWith { account ->
                selections.getString(account).also { id -> require(tabs.getValue(account).any { it.id == id }) }
            }
            require((defaults - order.toSet()).none { root.has(it) || selections.has(it) })
            return AccountLayout(order, active, tabs, selected.toMutableMap())
        }

        fun order(root: JSONObject): List<String> {
            val schema = root.getInt("schema")
            val stored = root.optJSONArray("accountOrder")?.let { array -> List(array.length()) { array.optString(it) } }
            return when (schema) {
                1 -> stored?.takeIf { it.size == defaults.size && it.toSet() == defaults.toSet() } ?: defaults
                2 -> requireNotNull(stored?.takeIf { it.size == 1 && it.single() in defaults }) { "资料账号清单无效。" }
                else -> error("不支持的标签资料版本；保留原始资料。")
            }
        }
    }
}

class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("sessions-v1", Context.MODE_PRIVATE)
    private var layout = prefs.getString(LAYOUT, null)?.let { AccountLayout.read(it) } ?: AccountLayout.create().also {
        check(prefs.edit().putString(LAYOUT, it.encode()).commit()) { "无法初始化账号布局。" }
    }
    internal val loginCleanup = LoginCleanup(::pendingAction, ::persistIntent, ::persistCompletion, cleanupInFlight)
    val tabs get() = layout.tabs
    val accountOrder get() = layout.accountOrder
    val selected get() = layout.selected
    var activeAccount: String
        get() = layout.activeAccount
        set(value) { require(value in accountOrder); layout.activeAccount = value }

    fun swapAccounts() { layout.accountOrder = accountOrder.reversed() }

    fun save() {
        check(latestOrder().toSet() == accountOrder.toSet()) { "账号清单已变更。" }
        val previous = prefs.getString(LAYOUT, null)
        if (!prefs.edit().putString(LAYOUT, layout.encode()).commit()) {
            prefs.edit().putString(LAYOUT, previous).apply()
            error("标签保存失败，停止继续修改。")
        }
    }

    internal fun hasCurrentAccount(account: String): Boolean =
        account in accountOrder && runCatching { account in latestOrder() }.getOrDefault(false)

    internal fun mayRemove(account: String): Boolean = runCatching {
        AccountLayout.mayRemove(latestOrder(), account, pendingRemoval()) &&
            pendingAction(account) != CleanupAction.CLEAR
    }.getOrDefault(false)

    internal fun observeChanges(layoutChanged: () -> Unit, removalStarted: (String) -> Unit):
        SharedPreferences.OnSharedPreferenceChangeListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        when (key) {
            LAYOUT -> layoutChanged()
            REMOVE -> pendingRemoval()?.let(removalStarted)
            else -> Unit
        }
    }.also(prefs::registerOnSharedPreferenceChangeListener)

    internal fun stopObserving(listener: SharedPreferences.OnSharedPreferenceChangeListener) =
        prefs.unregisterOnSharedPreferenceChangeListener(listener)

    internal fun refreshMembership(): Boolean {
        if (latestOrder().toSet() == accountOrder.toSet()) return false
        layout = AccountLayout.read(checkNotNull(prefs.getString(LAYOUT, null)))
        return true
    }

    private fun latestOrder() = AccountLayout.order(JSONObject(checkNotNull(prefs.getString(LAYOUT, null))))
    private fun pendingRemoval() = prefs.getString(REMOVE, null)
    private fun pendingAction(account: String): CleanupAction? = when {
        pendingRemoval() == account -> CleanupAction.REMOVE
        prefs.getBoolean("cleanup.$account", false) -> CleanupAction.CLEAR
        else -> null
    }

    private fun persistIntent(account: String, action: CleanupAction) {
        check(account in latestOrder()) { "账号不存在。" }
        if (action == CleanupAction.CLEAR) {
            saveLoginCleanup(account, true)
            return
        }
        check(mayRemove(account)) { "无法移除此账号。" }
        if (pendingRemoval() == account) return
        if (!prefs.edit().putString(REMOVE, account).commit()) {
            prefs.edit().remove(REMOVE).apply()
            error("无法保存账号移除状态。")
        }
    }

    private fun persistCompletion(account: String, action: CleanupAction) {
        if (action == CleanupAction.CLEAR) {
            saveLoginCleanup(account, false)
            return
        }
        check(pendingRemoval() == account) { "账号移除状态已变更。" }
        val previous = checkNotNull(prefs.getString(LAYOUT, null))
        val retained = AccountLayout.read(previous).without(account)
        if (!prefs.edit().putString(LAYOUT, retained.encode()).remove(REMOVE).commit()) {
            prefs.edit().putString(LAYOUT, previous).putString(REMOVE, account).apply()
            error("无法保存移除后的账号资料。")
        }
        layout = retained
    }

    private fun saveLoginCleanup(account: String, pending: Boolean) {
        val key = "cleanup.$account"
        val previous = prefs.getBoolean(key, false)
        if (previous == pending) return
        if (!prefs.edit().putBoolean(key, pending).commit()) {
            prefs.edit().putBoolean(key, previous).apply()
            error("账号清理状态保存失败。")
        }
    }

    companion object {
        private const val LAYOUT = "layout"
        private const val REMOVE = "pendingRemoval"
        private val cleanupInFlight = mutableMapOf<String, LoginCleanup.Attempt>()
        const val MAX_TABS = 12
        const val HOME = "https://appassets.androidplatform.net/assets/demo.html"
        fun isSyntheticUrl(url: String): Boolean = url == HOME || url == "https://appassets.androidplatform.net/assets/popup.html"
    }
}
