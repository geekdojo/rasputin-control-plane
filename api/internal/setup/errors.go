package setup

import "errors"

// ErrInstallNameEmpty is returned by Service.SetInstallName when the
// supplied value is blank after trimming.
var ErrInstallNameEmpty = errors.New("install name cannot be empty")

// ErrInvalidMode is returned by Service.SetMode when the supplied value is
// not one of the recognised deployment modes.
var ErrInvalidMode = errors.New("invalid deployment mode")

// ErrModeNeedsFirewallNode is returned by Service.SetMode when the operator
// picks a firewall-running mode (router or sub-segment) on an installation
// with no firewall-capable node registered. The handler maps it to 412 so the
// UI can prompt "power on your firewall node and refresh, or choose LAN peer."
var ErrModeNeedsFirewallNode = errors.New("this mode needs a firewall node, but none is registered")
