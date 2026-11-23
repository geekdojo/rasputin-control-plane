package signinname

import (
	"fmt"
	"math"
)

// ifindex32 narrows an interface index to the int32 the kernel's ip_mreqn
// carries. An index below 1 names no interface and one above MaxInt32 cannot
// be represented, so both are refused rather than truncated onto some other
// link (F-995-11); the caller reports the refusal as a socket-open failure.
func ifindex32(ifindex int) (int32, error) {
	if ifindex < 1 || ifindex > math.MaxInt32 {
		return 0, fmt.Errorf("signinname: ifindex %d is outside 1..%d", ifindex, math.MaxInt32)
	}
	return int32(ifindex), nil
}
