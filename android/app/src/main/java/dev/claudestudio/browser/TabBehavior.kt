package dev.claudestudio.browser

internal fun visibleTabIndices(count: Int, selected: Int, slots: Int): List<Int> {
    val available = slots.coerceAtLeast(2)
    if (count <= available) return (0 until count).toList()
    val inline = available - 1
    return if (selected < inline) (0 until inline).toList()
    else (0 until (inline - 1)).toList() + selected
}

internal class ClosedTabs<T : Any>(private val now: () -> Long, private val dispose: (T) -> Unit) {
    data class Entry<T>(val account: String, val tab: SavedTab, val index: Int, val deadline: Long, var page: T?)

    private val entries = mutableListOf<Entry<T>>()

    fun remember(account: String, tab: SavedTab, index: Int, page: T) {
        expire()
        entries += Entry(account, tab, index, now() + 10 * 60_000, page)
        val retained = entries.filter { it.page != null }
        if (retained.size > 5) release(retained.first())
        if (entries.size > SessionStore.MAX_TABS) release(entries.removeAt(0))
    }

    fun take(account: String): Entry<T>? {
        expire()
        val index = entries.indexOfLast { it.account == account }
        return if (index < 0) null else entries.removeAt(index)
    }

    fun has(account: String): Boolean = entries.any { it.account == account && it.deadline > now() }

    fun discard(account: String, tab: String, page: T): Boolean {
        val index = entries.indexOfFirst { it.account == account && it.tab.id == tab && it.page === page }
        if (index < 0) return false
        release(entries.removeAt(index))
        return true
    }

    fun clear(account: String? = null) = remove { account == null || it.account == account }
    fun expire() = remove { it.deadline <= now() }
    fun nextExpiry(): Long? = entries.firstOrNull()?.deadline

    private fun remove(predicate: (Entry<T>) -> Boolean) {
        val iterator = entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (!predicate(entry)) continue
            iterator.remove()
            release(entry)
        }
    }

    private fun release(entry: Entry<T>) {
        val page = entry.page ?: return
        entry.page = null
        dispose(page)
    }
}
