package dev.claudestudio.browser

internal enum class CleanupAction { CLEAR, REMOVE }

internal class LoginCleanup(
    val pendingAction: (String) -> CleanupAction?,
    private val persistIntent: (String, CleanupAction) -> Unit,
    private val persistCompletion: (String, CleanupAction) -> Unit,
    private val inFlight: MutableMap<String, Attempt>
) {
    class Attempt(val action: CleanupAction)

    fun isPending(account: String): Boolean = pendingAction(account) != null
    fun isRunning(account: String): Boolean = account in inFlight

    fun begin(account: String, action: CleanupAction): Attempt? {
        if (account in inFlight) return null
        val pending = pendingAction(account)
        if (pending != null && pending != action) return null
        persistIntent(account, action)
        return Attempt(action).also { inFlight[account] = it }
    }

    fun finish(account: String, token: Attempt): Boolean {
        if (inFlight[account] !== token) return false
        try { persistCompletion(account, token.action) } finally { inFlight.remove(account) }
        return true
    }

    fun fail(account: String, token: Attempt) {
        if (inFlight[account] === token) inFlight.remove(account)
    }
}
