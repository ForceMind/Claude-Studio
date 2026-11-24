package dev.claudestudio.browser

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AccountRemovalTest {
    private fun existing(active: String, ordered: Boolean = true): String = """
        {"schema":1,"activeAccount":"$active","selected":{"A":"tab-a","B":"tab-b"},
         "A":[{"id":"tab-a","url":"${SessionStore.HOME}"}],
         "B":[{"id":"tab-b","url":"${SessionStore.HOME}"}]
         ${if (ordered) ",\"accountOrder\":[\"B\",\"A\"]" else ""}}
    """.trimIndent()

    @Test fun oldLayoutsKeepAccountOrderSelectionAndTabIds() {
        val oldest = AccountLayout.read(existing("B", ordered = false))
        assertEquals(listOf("A", "B"), oldest.accountOrder)
        assertEquals("B", oldest.activeAccount)
        assertEquals("tab-b", oldest.selected["B"])
        assertEquals(listOf("B", "A"), AccountLayout.read(existing("B")).accountOrder)
        assertEquals(1, JSONObject(oldest.encode()).getInt("schema"))
    }

    @Test fun removalOfCurrentOrOtherAccountSurvivesRestartForBothTargets() {
        for (target in listOf("A", "B")) {
            val retained = if (target == "A") "B" else "A"
            for (previous in listOf(target, retained)) {
                val before = AccountLayout.read(existing(previous))
                val encoded = before.without(target).encode()
                val restarted = AccountLayout.read(encoded)
                assertEquals(listOf(retained), restarted.accountOrder)
                assertEquals(retained, restarted.activeAccount)
                assertEquals(before.tabs[retained], restarted.tabs[retained])
                assertEquals(before.selected[retained], restarted.selected[retained])
                assertEquals(setOf(retained), restarted.tabs.keys)
                val saved = JSONObject(encoded)
                assertEquals(2, saved.getInt("schema"))
                assertFalse(saved.has(target))
                assertFalse(saved.getJSONObject("selected").has(target))
            }
        }
    }

    @Test fun lastAccountAndMalformedMembershipAreRejected() {
        val retained = AccountLayout.read(existing("B")).without("A")
        assertFalse(AccountLayout.mayRemove(retained.accountOrder, "B", null))
        assertThrows(IllegalArgumentException::class.java) { retained.without("B") }
        val corrupt = JSONObject(retained.encode()).put("accountOrder", org.json.JSONArray())
        assertThrows(IllegalArgumentException::class.java) { AccountLayout.read(corrupt.toString()) }
    }

    @Test fun confirmationRecordsOnlyTheTargetAndRemovalCannotOverlap() {
        val saved = AccountLayout.read(existing("B"))
        var pending: String? = null
        val attempts = LoginCleanup({ if (it == pending) CleanupAction.REMOVE else null }, { account, _ ->
            check(AccountLayout.mayRemove(saved.accountOrder, account, pending))
            pending = account
        }, { _, _ -> error("App did not receive a completion callback") }, mutableMapOf())
        assertNull(pending) // The abandoned confirmation never calls begin.
        assertEquals(2, saved.accountOrder.size)
        val accepted = attempts.begin("B", CleanupAction.REMOVE)
        assertNotNull(accepted)
        assertEquals("B", pending)
        assertFalse(attempts.isPending("A"))
        assertNull(attempts.begin("B", CleanupAction.REMOVE))
        assertThrows(IllegalStateException::class.java) { attempts.begin("A", CleanupAction.REMOVE) }
        assertEquals("B", pending)
        assertEquals("tab-a", saved.selected["A"])
    }

    @Test fun failedCompletionCanResumeFromDurableIntentWithoutChangingTheOtherAccount() {
        var disk = existing("B")
        var pending: String? = null
        var failWrite = true
        fun install(inFlight: MutableMap<String, LoginCleanup.Attempt>) = LoginCleanup(
            { if (it == pending) CleanupAction.REMOVE else null },
            { account, _ -> pending = account },
            { account, action ->
                check(action == CleanupAction.REMOVE && account == pending)
                check(!failWrite) { "simulated commit failure" }
                disk = AccountLayout.read(disk).without(account).encode()
                pending = null
            }, inFlight)
        val first = install(mutableMapOf())
        val token = checkNotNull(first.begin("B", CleanupAction.REMOVE))
        assertThrows(IllegalStateException::class.java) { first.finish("B", token) }
        assertEquals(existing("B"), disk)
        assertEquals("B", pending)
        val afterRestart = install(mutableMapOf())
        assertEquals(CleanupAction.REMOVE, afterRestart.pendingAction("B"))
        assertNull(afterRestart.begin("B", CleanupAction.CLEAR))
        val retry = checkNotNull(afterRestart.begin("B", CleanupAction.REMOVE))
        assertFalse(first.finish("B", token))
        failWrite = false
        assertTrue(afterRestart.finish("B", retry))
        assertNull(pending)
        val retained = AccountLayout.read(disk)
        assertEquals(listOf("A"), retained.accountOrder)
        assertEquals("tab-a", retained.selected["A"])
    }
}
