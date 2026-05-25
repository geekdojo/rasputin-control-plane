// Package bmc bridges to the onboard BMC over I²C/serial/Redfish-lite.
// Provides power on/off/cycle, reset, and serial-over-LAN tunneled to the UI.
//
// See projects/rasputin/design/control-plane/architecture.md §7.2
// in the geekdojo-wiki.
package bmc
