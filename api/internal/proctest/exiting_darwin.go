package proctest

import "golang.org/x/sys/unix"

// From darwin's <sys/proc.h>; x/sys does not export them.
const (
	szomb  = 5      // p_stat: a zombie
	pWExit = 0x2000 // P_WEXIT in p_flag: working on exiting
)

// allExiting reports whether every process left in group pgid is a zombie or
// already exiting (or none is left), from the kernel's process table. darwin's
// kill(-pgid) answers EPERM for both states (F-966-17): measured by a probe
// that SIGKILLed a group member and re-sent the group SIGKILL while it died,
// which saw EPERM at p_stat SRUN with P_WEXIT set as well as at SZOMB. A live
// process this one may not signal is neither, so its EPERM stays an error.
func allExiting(pgid int) (bool, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		return false, err
	}
	for _, p := range procs {
		if p.Proc.P_stat != szomb && p.Proc.P_flag&pWExit == 0 {
			return false, nil
		}
	}
	return true, nil
}
