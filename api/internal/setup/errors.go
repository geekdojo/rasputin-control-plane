package setup

import "errors"

// ErrInstallNameEmpty is returned by Service.SetInstallName when the
// supplied value is blank after trimming.
var ErrInstallNameEmpty = errors.New("install name cannot be empty")
