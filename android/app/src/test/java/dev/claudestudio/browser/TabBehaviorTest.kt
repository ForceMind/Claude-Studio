package dev.claudestudio.browser

import org.junit.Assert.*
import org.junit.Test

class TabBehaviorTest {
    @Test fun overflowKeepsTheSelectedTabAndReservesOneSlot() {
        assertEquals(listOf(0, 1, 2), visibleTabIndices(3, 2, 3))
        assertEquals(listOf(0, 1, 5), visibleTabIndices(6, 5, 4))
        assertEquals(listOf(4), visibleTabIndices(6, 4, 0))
    }

    @Test fun restoresOriginalPageOnlyForItsAccount() {
        val handles = ClosedTabs<Any>({ 0 }) { fail("The original page should be retained") }
        val page = Any()
        val tab = SavedTab("shared-id", SessionStore.HOME)
        handles.remember("A", tab, 2, page)
        assertNull(handles.take("B"))
        val restored = checkNotNull(handles.take("A"))
        assertSame(page, restored.page)
        assertSame(tab, restored.tab)
        assertEquals(2, restored.index)
        assertNull(handles.take("A"))
    }

    @Test fun evictsOnlyTheOldestViewAndExpiresSafeFallback() {
        var now = 0L
        val disposed = mutableListOf<Int>()
        val handles = ClosedTabs({ now }, disposed::add)
        repeat(6) { handles.remember(if (it == 0) "A" else "B", SavedTab("tab-$it", SessionStore.HOME), 0, it) }
        assertEquals(listOf(0), disposed)
        now = 599_999
        assertNull(checkNotNull(handles.take("A")).page)
        now = 600_000
        assertNull(handles.take("B"))
        assertEquals((0..5).toList(), disposed)
    }

    @Test fun clearingOrInvalidatingARecordDoesNotReviveItsPage() {
        val released = mutableListOf<Any>()
        val handles = ClosedTabs({ 10 }, released::add)
        val a = Any()
        val b = Any()
        handles.remember("A", SavedTab("same", SessionStore.HOME), 0, a)
        handles.remember("B", SavedTab("same", SessionStore.HOME), 0, b)
        assertFalse(handles.discard("B", "same", a))
        handles.clear("A")
        assertEquals(listOf(a), released)
        assertNull(handles.take("A"))
        assertTrue(handles.discard("B", "same", b))
        assertNull(handles.take("B"))
    }

    @Test fun pendingCleanupSurvivesRecreationAndAnOldCallbackCannotUnlockIt() {
        val pending = mutableMapOf<String, CleanupAction>()
        val inFlight = mutableMapOf<String, LoginCleanup.Attempt>()
        fun attempts(active: MutableMap<String, LoginCleanup.Attempt>) = LoginCleanup(pending::get,
            { account, action -> pending[account] = action }, { account, _ -> pending.remove(account) }, active)
        val first = attempts(inFlight)
        val old = checkNotNull(first.begin("A", CleanupAction.CLEAR))
        assertTrue(first.isPending("A"))
        assertFalse(first.isPending("B"))
        assertNull(attempts(inFlight).begin("A", CleanupAction.CLEAR))
        first.fail("A", old)
        val reopened = attempts(inFlight)
        val retry = checkNotNull(reopened.begin("A", CleanupAction.CLEAR))
        assertFalse(first.finish("A", old))
        assertTrue(reopened.isPending("A"))
        assertTrue(reopened.finish("A", retry))
        assertFalse(reopened.isPending("A"))
    }
}
