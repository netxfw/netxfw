package xdp

import (
	"sync"
	"testing"
)

func TestRuleValuePool(t *testing.T) {
	t.Run("acquire and release", func(t *testing.T) {
		v := acquireRuleValue()
		if v == nil {
			t.Fatal("acquireRuleValue returned nil")
		}

		v.Counter = 100
		v.ExpiresAt = 12345

		releaseRuleValue(v)

		v2 := acquireRuleValue()
		if v2.Counter != 0 {
			t.Errorf("pooled object not reset: got Counter=%d, want 0", v2.Counter)
		}
		if v2.ExpiresAt != 0 {
			t.Errorf("pooled object not reset: got ExpiresAt=%d, want 0", v2.ExpiresAt)
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := acquireRuleValue()
				v.Counter = 1
				releaseRuleValue(v)
			}()
		}
		wg.Wait()
	})
}

func TestIn6AddrPool(t *testing.T) {
	t.Run("acquire and release", func(t *testing.T) {
		v := acquireIn6Addr()
		if v == nil {
			t.Fatal("acquireIn6Addr returned nil")
		}

		for i := 0; i < 16; i++ {
			v.In6U.U6Addr8[i] = byte(i)
		}

		releaseIn6Addr(v)

		v2 := acquireIn6Addr()
		for i := 0; i < 16; i++ {
			if v2.In6U.U6Addr8[i] != 0 {
				t.Errorf("pooled object not reset at index %d: got %d, want 0", i, v2.In6U.U6Addr8[i])
			}
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := acquireIn6Addr()
				v.In6U.U6Addr8[0] = 1
				releaseIn6Addr(v)
			}()
		}
		wg.Wait()
	})
}

func TestRatelimitValuePool(t *testing.T) {
	t.Run("acquire and release", func(t *testing.T) {
		v := acquireRatelimitValue()
		if v == nil {
			t.Fatal("acquireRatelimitValue returned nil")
		}

		v.Rate = 1000
		v.Burst = 2000

		releaseRatelimitValue(v)

		v2 := acquireRatelimitValue()
		if v2.Rate != 0 {
			t.Errorf("pooled object not reset: got Rate=%d, want 0", v2.Rate)
		}
		if v2.Burst != 0 {
			t.Errorf("pooled object not reset: got Burst=%d, want 0", v2.Burst)
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := acquireRatelimitValue()
				v.Rate = 1
				releaseRatelimitValue(v)
			}()
		}
		wg.Wait()
	})
}

func TestLpmKeyPool(t *testing.T) {
	t.Run("acquire and release", func(t *testing.T) {
		v := acquireLpmKey()
		if v == nil {
			t.Fatal("acquireLpmKey returned nil")
		}

		v.Prefixlen = 24
		for i := 0; i < 16; i++ {
			v.Data.In6U.U6Addr8[i] = byte(i)
		}

		releaseLpmKey(v)

		v2 := acquireLpmKey()
		if v2.Prefixlen != 0 {
			t.Errorf("pooled object not reset: got Prefixlen=%d, want 0", v2.Prefixlen)
		}
		for i := 0; i < 16; i++ {
			if v2.Data.In6U.U6Addr8[i] != 0 {
				t.Errorf("pooled object not reset at index %d: got %d, want 0", i, v2.Data.In6U.U6Addr8[i])
			}
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := acquireLpmKey()
				v.Prefixlen = 1
				releaseLpmKey(v)
			}()
		}
		wg.Wait()
	})
}

func TestLpmIPPortKeyPool(t *testing.T) {
	t.Run("acquire and release", func(t *testing.T) {
		v := acquireLpmIPPortKey()
		if v == nil {
			t.Fatal("acquireLpmIPPortKey returned nil")
		}

		v.Prefixlen = 32
		v.Port = 8080
		for i := 0; i < 16; i++ {
			v.Ip.In6U.U6Addr8[i] = byte(i)
		}

		releaseLpmIPPortKey(v)

		v2 := acquireLpmIPPortKey()
		if v2.Prefixlen != 0 {
			t.Errorf("pooled object not reset: got Prefixlen=%d, want 0", v2.Prefixlen)
		}
		if v2.Port != 0 {
			t.Errorf("pooled object not reset: got Port=%d, want 0", v2.Port)
		}
		for i := 0; i < 16; i++ {
			if v2.Ip.In6U.U6Addr8[i] != 0 {
				t.Errorf("pooled object not reset at index %d: got %d, want 0", i, v2.Ip.In6U.U6Addr8[i])
			}
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := acquireLpmIPPortKey()
				v.Port = 1
				releaseLpmIPPortKey(v)
			}()
		}
		wg.Wait()
	})
}

func TestRuleValueSlicePool(t *testing.T) {
	t.Run("acquire and release", func(t *testing.T) {
		v := acquireRuleValueSlice()
		if v == nil {
			t.Fatal("acquireRuleValueSlice returned nil")
		}

		slice := *v
		for i := range slice {
			slice[i].Counter = uint64(i)
		}

		releaseRuleValueSlice(v)

		v2 := acquireRuleValueSlice()
		slice2 := *v2
		for i := range slice2 {
			if slice2[i].Counter != 0 {
				t.Errorf("pooled object not reset at index %d: got Counter=%d, want 0", i, slice2[i].Counter)
			}
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := acquireRuleValueSlice()
				(*v)[0].Counter = 1
				releaseRuleValueSlice(v)
			}()
		}
		wg.Wait()
	})
}

func TestPoolResetCorrectness(t *testing.T) {
	t.Run("rule value reset clears all fields", func(t *testing.T) {
		v := acquireRuleValue()
		v.Counter = 123
		v.ExpiresAt = 456
		releaseRuleValue(v)

		v2 := acquireRuleValue()
		if v2.Counter != 0 || v2.ExpiresAt != 0 {
			t.Errorf("rule value not properly reset: Counter=%d, ExpiresAt=%d", v2.Counter, v2.ExpiresAt)
		}
	})

	t.Run("in6 addr reset clears all bytes", func(t *testing.T) {
		v := acquireIn6Addr()
		for i := 0; i < 16; i++ {
			v.In6U.U6Addr8[i] = 0xFF
		}
		releaseIn6Addr(v)

		v2 := acquireIn6Addr()
		for i := 0; i < 16; i++ {
			if v2.In6U.U6Addr8[i] != 0 {
				t.Errorf("in6 addr not properly reset at index %d: got %d", i, v2.In6U.U6Addr8[i])
			}
		}
	})

	t.Run("lpm key reset clears all fields", func(t *testing.T) {
		v := acquireLpmKey()
		v.Prefixlen = 128
		for i := 0; i < 16; i++ {
			v.Data.In6U.U6Addr8[i] = 0xFF
		}
		releaseLpmKey(v)

		v2 := acquireLpmKey()
		if v2.Prefixlen != 0 {
			t.Errorf("lpm key Prefixlen not reset: got %d", v2.Prefixlen)
		}
		for i := 0; i < 16; i++ {
			if v2.Data.In6U.U6Addr8[i] != 0 {
				t.Errorf("lpm key Data not reset at index %d: got %d", i, v2.Data.In6U.U6Addr8[i])
			}
		}
	})

	t.Run("lpm ip port key reset clears all fields", func(t *testing.T) {
		v := acquireLpmIPPortKey()
		v.Prefixlen = 128
		v.Port = 65535
		for i := 0; i < 16; i++ {
			v.Ip.In6U.U6Addr8[i] = 0xFF
		}
		releaseLpmIPPortKey(v)

		v2 := acquireLpmIPPortKey()
		if v2.Prefixlen != 0 {
			t.Errorf("lpm ip port key Prefixlen not reset: got %d", v2.Prefixlen)
		}
		if v2.Port != 0 {
			t.Errorf("lpm ip port key Port not reset: got %d", v2.Port)
		}
		for i := 0; i < 16; i++ {
			if v2.Ip.In6U.U6Addr8[i] != 0 {
				t.Errorf("lpm ip port key Ip not reset at index %d: got %d", i, v2.Ip.In6U.U6Addr8[i])
			}
		}
	})
}

func BenchmarkPoolAcquireRelease(b *testing.B) {
	b.Run("RuleValue", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v := acquireRuleValue()
			releaseRuleValue(v)
		}
	})

	b.Run("In6Addr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v := acquireIn6Addr()
			releaseIn6Addr(v)
		}
	})

	b.Run("LpmKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v := acquireLpmKey()
			releaseLpmKey(v)
		}
	})

	b.Run("LpmIPPortKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v := acquireLpmIPPortKey()
			releaseLpmIPPortKey(v)
		}
	})

	b.Run("RuleValueSlice", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v := acquireRuleValueSlice()
			releaseRuleValueSlice(v)
		}
	})
}

func BenchmarkPoolParallel(b *testing.B) {
	b.Run("RuleValue", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				v := acquireRuleValue()
				releaseRuleValue(v)
			}
		})
	})

	b.Run("In6Addr", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				v := acquireIn6Addr()
				releaseIn6Addr(v)
			}
		})
	})

	b.Run("LpmKey", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				v := acquireLpmKey()
				releaseLpmKey(v)
			}
		})
	})
}
