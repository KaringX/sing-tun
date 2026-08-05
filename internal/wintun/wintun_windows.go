/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"runtime"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/windows"
)

type (
	Adapter struct {
		handle uintptr
	}
)

type loggerLevel int //karing

const ( //karing
	logInfo loggerLevel = iota
	logWarn
	logErr
)

var (
	modwintun                         = newLazyDLL("wintun.dll")
	procWintunCreateAdapter           = modwintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter             = modwintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter            = modwintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver            = modwintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID          = modwintun.NewProc("WintunGetAdapterLUID")
	procWintunGetRunningDriverVersion = modwintun.NewProc("WintunGetRunningDriverVersion")
	procWintunSetLogger               = modwintun.NewProc("WintunSetLogger") //karing
)

func closeAdapter(wintun *Adapter) {
	syscall.SyscallN(procWintunCloseAdapter.Addr(), wintun.handle)
}

var winTunLogErr string                           //karing
var winTunLogFunc func(level int, message string) //karing
func init() { //karing
	syscall.Syscall(procWintunSetLogger.Addr(), 1, windows.NewCallback(func(level loggerLevel, timestamp uint64, msg *uint16) int {
		if level >= logErr || winTunLogFunc != nil {
			message := "wintun: " + windows.UTF16PtrToString(msg)
			if level >= logErr {
				winTunLogErr = message
			}

			if winTunLogFunc != nil {
				winTunLogFunc(int(level), message)
			}
		}

		return 0
	}), 0, 0)
}

func SetLogFunc(log func(level int, message string)) { //karing
	winTunLogFunc = log
}

// CreateAdapter creates a Wintun adapter. name is the cosmetic name of the adapter.
// tunnelType represents the type of adapter and should be "Wintun". requestedGUID is
// the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random,
// and hence a new NLA entry is created for each new adapter.
func CreateAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (wintun *Adapter, err error) {
	err = procWintunCloseAdapter.Find()
	if err != nil {
		return
	}
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var tunnelType16 *uint16
	tunnelType16, err = windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return
	}
	winTunLogErr = "" //karing
	r0, _, e1 := syscall.SyscallN(procWintunCreateAdapter.Addr(), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(tunnelType16)), uintptr(unsafe.Pointer(requestedGUID)))
	if r0 == 0 {
		err = E.Cause(e1, winTunLogErr) //karing
		return
	}
	wintun = &Adapter{handle: r0}
	runtime.SetFinalizer(wintun, closeAdapter)
	return
}

// OpenAdapter opens an existing Wintun adapter by name.
func OpenAdapter(name string) (wintun *Adapter, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	winTunLogErr = "" //karing
	r0, _, e1 := syscall.SyscallN(procWintunOpenAdapter.Addr(), uintptr(unsafe.Pointer(name16)))
	if r0 == 0 {
		err = E.Cause(e1, winTunLogErr) //karing
		return
	}
	wintun = &Adapter{handle: r0}
	runtime.SetFinalizer(wintun, closeAdapter)
	return
}

// Close closes a Wintun adapter.
func (wintun *Adapter) Close() (err error) {
	runtime.SetFinalizer(wintun, nil)
	winTunLogErr = "" //karing
	r1, _, e1 := syscall.SyscallN(procWintunCloseAdapter.Addr(), wintun.handle)
	if r1 == 0 {
		err = E.Cause(e1, winTunLogErr) //karing
	}
	return
}

// Uninstall removes the driver from the system if no drivers are currently in use.
func Uninstall() (err error) {
	winTunLogErr = "" //karing
	r1, _, e1 := syscall.SyscallN(procWintunDeleteDriver.Addr())
	if r1 == 0 {
		err = E.Cause(e1, winTunLogErr) //karing
	}
	return
}

// RunningVersion returns the version of the running Wintun driver.
func RunningVersion() (version uint32, err error) {
	winTunLogErr = "" //karing
	r0, _, e1 := syscall.SyscallN(procWintunGetRunningDriverVersion.Addr())
	version = uint32(r0)
	if version == 0 {
		err = E.Cause(e1, winTunLogErr) //karing
	}
	return
}

// LUID returns the LUID of the adapter.
func (wintun *Adapter) LUID() (luid uint64) {
	syscall.SyscallN(procWintunGetAdapterLUID.Addr(), uintptr(wintun.handle), uintptr(unsafe.Pointer(&luid)))
	return
}
