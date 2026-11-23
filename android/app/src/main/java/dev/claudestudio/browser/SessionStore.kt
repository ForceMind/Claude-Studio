package dev.claudestudio.browser

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class SavedTab(val id: String, var url: String, val popup: Boolean = false)

class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("sessions-v1", Context.MODE_PRIVATE)
    internal val loginCleanup = LoginCleanup({ prefs.getBoolean("cleanup.$it", false) }, { account, pending ->
        val key = "cleanup.$account"
        if (!prefs.edit().putBoolean(key, pending).commit()) {
            if (!pending) prefs.edit().putBoolean(key, true).apply()
            error("账号清理状态保存失败。")
        }
    }, cleanupInFlight)
    val tabs = linkedMapOf("A" to mutableListOf<SavedTab>(), "B" to mutableListOf())
    var accountOrder: List<String> = tabs.keys.toList()
        private set
    var activeAccount: String = "A"
    val selected = mutableMapOf<String, String>()

    init {
        val raw = prefs.getString("layout", null)
        if (raw == null) {
            tabs.forEach { (account, list) ->
                list += SavedTab(UUID.randomUUID().toString(), HOME)
                selected[account] = list.first().id
            }
            save()
        } else {
            // Never silently replace unreadable user state with empty profiles.
            val root = JSONObject(raw)
            require(root.getInt("schema") == 1) { "不支持的标签资料版本；保留原始资料。" }
            root.optJSONArray("accountOrder")?.let { order ->
                val savedOrder = List(order.length()) { order.optString(it) }
                if (savedOrder.size == tabs.size && savedOrder.toSet() == tabs.keys) accountOrder = savedOrder
            }
            activeAccount = root.getString("activeAccount").also { require(it in tabs) }
            tabs.forEach { (account, list) ->
                val array = root.getJSONArray(account)
                require(array.length() in 1..MAX_TABS)
                repeat(array.length()) { index ->
                    val value = array.getJSONObject(index)
                    val id = value.getString("id")
                    require(id.isNotBlank() && list.none { it.id == id })
                    val url = value.getString("url")
                    require(isSyntheticUrl(url)) { "标签 URL 不在合成资源范围；保留原始资料。" }
                    list += SavedTab(id, url, value.optBoolean("popup"))
                }
                selected[account] = root.getJSONObject("selected").getString(account)
                require(list.any { it.id == selected[account] })
            }
        }
    }

    fun swapAccounts() { accountOrder = accountOrder.reversed() }

    fun save() {
        val root = JSONObject().put("schema", 1).put("activeAccount", activeAccount)
            .put("selected", JSONObject(selected.toMap()))
            .put("accountOrder", JSONArray(accountOrder))
        tabs.forEach { (account, list) ->
            val values = JSONArray()
            list.forEach { values.put(JSONObject().put("id", it.id).put("url", it.url).put("popup", it.popup)) }
            root.put(account, values)
        }
        check(prefs.edit().putString("layout", root.toString()).commit()) { "标签保存失败，停止继续修改。" }
    }

    companion object {
        private val cleanupInFlight = mutableMapOf<String, Any>()
        const val MAX_TABS = 12
        const val HOME = "https://appassets.androidplatform.net/assets/demo.html"
        fun isSyntheticUrl(url: String): Boolean =
            url == HOME || url == "https://appassets.androidplatform.net/assets/popup.html"
    }
}
