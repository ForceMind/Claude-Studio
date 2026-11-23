package dev.claudestudio.browser

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class SavedTab(val id: String, var url: String, val popup: Boolean = false)

class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("sessions-v1", Context.MODE_PRIVATE)
    val tabs = linkedMapOf("A" to mutableListOf<SavedTab>(), "B" to mutableListOf())
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

    fun save() {
        val root = JSONObject().put("schema", 1).put("activeAccount", activeAccount)
            .put("selected", JSONObject(selected.toMap()))
        tabs.forEach { (account, list) ->
            val values = JSONArray()
            list.forEach { values.put(JSONObject().put("id", it.id).put("url", it.url).put("popup", it.popup)) }
            root.put(account, values)
        }
        check(prefs.edit().putString("layout", root.toString()).commit()) { "标签保存失败，停止继续修改。" }
    }

    companion object {
        const val MAX_TABS = 12
        const val HOME = "https://appassets.androidplatform.net/assets/demo.html"
        fun isSyntheticUrl(url: String): Boolean =
            url == HOME || url == "https://appassets.androidplatform.net/assets/popup.html"
    }
}
