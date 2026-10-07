package auth

import "sync/atomic"

type atomicBool struct{ v int32 }

func (a *atomicBool) set()      { atomic.StoreInt32(&a.v, 1) }
func (a *atomicBool) get() bool { return atomic.LoadInt32(&a.v) == 1 }
