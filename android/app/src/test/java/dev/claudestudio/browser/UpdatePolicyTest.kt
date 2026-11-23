package dev.claudestudio.browser

import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class UpdatePolicyTest {
    private fun time(value: String) = Instant.parse(value).toEpochMilli()
    private val beforeNoon = time("2026-11-23T03:59:00Z")
    private val noon = time("2026-11-23T04:00:00Z")

    @Test fun startupAndOrdinaryResumeAreDifferent() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open()
        assertEquals(UpdatePolicy.Trigger.STARTUP, policy.poll(beforeNoon)!!.trigger)
        policy.complete(beforeNoon, true)
        assertNull(policy.poll(beforeNoon + 1))
        policy.open()
        assertEquals(UpdatePolicy.Trigger.STARTUP, policy.poll(beforeNoon + 2)!!.trigger)
    }
    @Test fun completedBeforeNoonDoesNotReplaceNoonCheck() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open(); policy.poll(beforeNoon); policy.complete(beforeNoon, true)
        assertEquals(UpdatePolicy.Trigger.NOON, policy.poll(noon)!!.trigger)
        policy.complete(noon, true)
        assertNull(policy.poll(noon + 1))
    }
    @Test fun requestCrossingNoonMustThenCheckNoon() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open(); policy.poll(beforeNoon)
        assertNull(policy.poll(noon))
        policy.complete(noon + 1, true)
        assertEquals(UpdatePolicy.Trigger.NOON, policy.poll(noon + 1)!!.trigger)
    }
    @Test fun sleepAcrossDaysChecksLatestPastNoonOnlyOnce() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open(); policy.poll(beforeNoon); policy.complete(beforeNoon, true)
        val wake = time("2026-11-26T03:00:00Z")
        assertEquals(time("2026-11-25T04:00:00Z"), policy.poll(wake)!!.noon)
        policy.complete(wake, true)
        assertNull(policy.poll(wake + 1))
        assertEquals(UpdatePolicy.Trigger.NOON, policy.poll(time("2026-11-26T04:00:00Z"))!!.trigger)
    }
    @Test fun coldLaunchDoesNotReplayPastDays() {
        val now = time("2026-11-26T05:00:00Z")
        val policy = UpdatePolicy(now)
        policy.open()
        assertEquals(UpdatePolicy.Check(UpdatePolicy.Trigger.STARTUP, null), policy.poll(now))
        policy.complete(now, true)
        assertNull(policy.poll(now + 1))
    }
    @Test fun failureBackoffIsBoundedAndNetworkRecoveryCanRetry() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open(); policy.poll(beforeNoon); policy.complete(beforeNoon, false)
        assertNull(policy.poll(beforeNoon + 29_999))
        assertNotNull(policy.poll(beforeNoon + 30_000))
        policy.complete(beforeNoon + 30_000, false)
        // Crossing noon creates a new due slot and resets backoff.
        assertEquals(UpdatePolicy.Trigger.BOTH, policy.poll(noon)!!.trigger)
        policy.complete(noon, false)
        policy.online()
        assertNotNull(policy.poll(noon + 1))
    }
    @Test fun invalidConfigurationWaitsForNewOpenOrNoon() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open(); policy.poll(beforeNoon); policy.complete(beforeNoon, false, true)
        policy.online()
        assertNull(policy.poll(beforeNoon + 1))
        assertNotNull(policy.poll(noon))
    }
    @Test fun consecutiveFailuresCapAtTenMinutes() {
        var now = time("2026-11-23T00:00:00Z")
        val policy = UpdatePolicy(now)
        policy.open()
        for (delay in longArrayOf(30_000, 120_000, 600_000, 600_000)) {
            assertNotNull(policy.poll(now))
            policy.complete(now, false)
            assertNull(policy.poll(now + delay - 1))
            now += delay
        }
        assertNotNull(policy.poll(now))
    }
    @Test fun repeatedOpenAndPollMergeWhileInFlight() {
        val policy = UpdatePolicy(beforeNoon)
        policy.open(); assertNotNull(policy.poll(beforeNoon))
        policy.open(); assertNull(policy.poll(beforeNoon + 1))
        policy.complete(beforeNoon + 2, true)
        assertNull(policy.poll(beforeNoon + 3))
    }
    @Test fun utcMappingHasNoPhoneTimeZoneDependency() {
        assertEquals(noon, UpdatePolicy.latestNoon(noon))
        assertEquals(noon - UpdatePolicy.DAY, UpdatePolicy.latestNoon(noon - 1))
    }
}
