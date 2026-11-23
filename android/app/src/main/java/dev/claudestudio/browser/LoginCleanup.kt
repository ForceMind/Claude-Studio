package dev.claudestudio.browser

internal class LoginCleanup(
    val isPending: (String) -> Boolean,
    private val setPending: (String, Boolean) -> Unit,
    private val inFlight: MutableMap<String, Any>
) {
    fun begin(account: String): Any? {
        if (account in inFlight) return null
        setPending(account, true)
        return Any().also { inFlight[account] = it }
    }

    fun finish(account: String, token: Any): Boolean {
        if (inFlight[account] !== token) return false
        try { setPending(account, false) } finally { inFlight.remove(account) }
        return true
    }

    fun fail(account: String, token: Any) {
        if (inFlight[account] === token) inFlight.remove(account)
    }
}
