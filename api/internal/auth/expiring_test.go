package auth

import (
	"strconv"
	"testing"
	"time"
)

type expRec struct {
	exp       time.Time
	destroyed bool
}

func newTestExpiring(c *testClock, max int) *expiring[*expRec] {
	return newExpiring(c.Now, max, func(r *expRec) time.Time { return r.exp }, func(r *expRec) { r.destroyed = true })
}

// TC-1005-13: on the injected clock a record answers absent from its
// expiry; at the cap the record nearest expiry is evicted (or every
// expired one); prune drops expired records; each sees live ones only.
// The bridge's map is capped at 1024, so the 1025th evicts.
func TestExpiring_TC1005_13(t *testing.T) {
	c := newTestClock()
	e := newTestExpiring(c, maxBridgeRecords)
	recs := map[string]*expRec{}
	for i := range maxBridgeRecords {
		k := strconv.Itoa(i)
		// Record 7 expires first.
		exp := c.Now().Add(bridgeLifetime + time.Duration(i+1)*time.Second)
		if i == 7 {
			exp = c.Now().Add(time.Minute)
		}
		recs[k] = &expRec{exp: exp}
		e.put(k, recs[k])
	}
	e.put("overflow", &expRec{exp: c.Now().Add(bridgeLifetime)})
	if e.size() != maxBridgeRecords || e.live("7") || !recs["7"].destroyed || !e.live("overflow") || !e.live("8") {
		t.Errorf("the 1025th record evicted the wrong one: size %d", e.size())
	}

	// At the cap with expired records, every expired one goes.
	c.Add(bridgeLifetime + 2*time.Second) // 0, 1 and overflow have expired
	e.put("after", &expRec{exp: c.Now().Add(time.Hour)})
	if e.size() != maxBridgeRecords-2 || recs["8"].destroyed || !recs["0"].destroyed {
		t.Errorf("eviction with expired records: size %d", e.size())
	}

	// Expiry: absent from the instant itself.
	e2 := newTestExpiring(c, 4)
	r := &expRec{exp: c.Now().Add(time.Minute)}
	e2.put("k", r)
	c.Add(time.Minute - time.Nanosecond)
	if _, ok := e2.peek("k"); !ok {
		t.Fatal("expired early")
	}
	c.Add(time.Nanosecond)
	if _, ok := e2.peek("k"); ok || e2.live("k") {
		t.Error("live at its expiry")
	}
	if _, ok := e2.take("k"); ok || !r.destroyed {
		t.Error("take returned an expired record, or did not destroy it")
	}

	// Replacement destroys the old record; each sees only live records;
	// prune drops the expired ones.
	old, live, gone := &expRec{exp: c.Now().Add(time.Hour)}, &expRec{exp: c.Now().Add(time.Hour)}, &expRec{exp: c.Now().Add(time.Second)}
	e2.put("a", old)
	e2.put("a", live)
	e2.put("b", gone)
	if !old.destroyed {
		t.Error("replacement did not destroy the old record")
	}
	c.Add(time.Second)
	seen := 0
	e2.each(func(*expRec) bool { seen++; return false })
	if seen != 1 {
		t.Errorf("each saw %d records, want 1", seen)
	}
	e2.prune()
	if e2.size() != 1 || !gone.destroyed || live.destroyed {
		t.Errorf("prune: size %d", e2.size())
	}
	if v, ok := e2.take("a"); !ok || v != live || live.destroyed {
		t.Error("take of a live record")
	}
}
