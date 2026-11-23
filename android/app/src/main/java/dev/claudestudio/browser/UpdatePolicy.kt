package dev.claudestudio.browser

/** Pure wall-clock policy shared by foreground timers, resume and connectivity recovery. */
class UpdatePolicy(private val openedAt: Long) {
    enum class Trigger { STARTUP, NOON, BOTH }
    data class Check(val trigger: Trigger, val noon: Long?)
    private var pendingOpen = false
    private var completedNoon = Long.MIN_VALUE
    private var observedNoon = Long.MIN_VALUE
    private var retryAt = Long.MIN_VALUE
    private var failures = 0
    private var inFlight: Check? = null

    fun open() { pendingOpen = true; if (inFlight == null) resetRetry() }
    fun online() { if (retryAt != Long.MIN_VALUE && retryAt != Long.MAX_VALUE) resetRetry() }
    fun poll(now: Long): Check? {
        if (inFlight != null) return null
        val noon = latestNoon(now)
        val daily = noon > openedAt && noon > completedNoon
        if (daily && noon > observedNoon) { observedNoon = noon; resetRetry() }
        if ((!pendingOpen && !daily) || now < retryAt) return null
        return Check(if (pendingOpen) { if (daily) Trigger.BOTH else Trigger.STARTUP } else Trigger.NOON,
            if (daily) noon else null).also { inFlight = it }
    }
    fun complete(now: Long, success: Boolean, invalid: Boolean = false) {
        val check = inFlight ?: return
        inFlight = null
        if (success) {
            pendingOpen = false
            check.noon?.let { completedNoon = it }
            resetRetry()
        } else {
            val delays = longArrayOf(30_000, 120_000, 600_000)
            val delay = delays[failures.coerceAtMost(delays.lastIndex)]
            failures = (failures + 1).coerceAtMost(delays.lastIndex)
            retryAt = if (invalid) Long.MAX_VALUE else now + delay
        }
    }
    fun nextDelay(now: Long): Long {
        if (inFlight != null) return 60_000
        val noon = latestNoon(now)
        val pending = pendingOpen || (noon > openedAt && noon > completedNoon)
        val next = minOf(noon + DAY, now + 60_000, if (pending) retryAt else Long.MAX_VALUE)
        return (next - now).coerceAtLeast(1)
    }
    private fun resetRetry() { failures = 0; retryAt = Long.MIN_VALUE }
    companion object {
        const val DAY = 86_400_000L
        // Beijing noon is 04:00 UTC, independent of the phone's time zone or DST.
        fun latestNoon(now: Long): Long = Math.floorDiv(now - 14_400_000L, DAY) * DAY + 14_400_000L
    }
}
