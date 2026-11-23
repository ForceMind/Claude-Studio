package dev.claudestudio.browser

import android.app.Activity

sealed class UpdateResult {
    data object Current : UpdateResult()
    data class Available(val description: String) : UpdateResult()
    data class Blocked(val reason: String) : UpdateResult()
    data class Unreachable(val reason: String) : UpdateResult()
}

interface UpdateClient {
    fun check(callback: (UpdateResult) -> Unit)
    /** Called only by an explicit native confirmation button, never by a timer. */
    fun confirmInstall(activity: Activity, publish: (String) -> Unit)
    fun close() {}
}
