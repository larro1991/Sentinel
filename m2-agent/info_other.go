//go:build !linux && !windows

package main

func platformMemDisk() (ramGB, diskGB uint64) {
	return 0, 0
}
