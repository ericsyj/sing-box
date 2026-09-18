package main

import "golang.org/x/sys/windows"

func init() {
	_ = windows.SetProcessShutdownParameters(0x3FF, 0)
}
