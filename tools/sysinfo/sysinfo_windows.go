//go:build windows

package sysinfo

import (
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryEx    = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceA = kernel32.NewProc("GetDiskFreeSpaceExA")
	procGetTickCount64    = kernel32.NewProc("GetTickCount64")
	ntdll                 = syscall.NewLazyDLL("ntdll.dll")
	procNtQuerySystemInfo = ntdll.NewProc("NtQuerySystemInformation")
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func getMemoryInfo() (total, available uint64, err error) {
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	ret, _, callErr := procGlobalMemoryEx.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return 0, 0, callErr
	}
	return ms.ullTotalPhys, ms.ullAvailPhys, nil
}

func getDiskInfo() ([]DiskInfo, error) {
	var disks []DiskInfo
	// 일반적인 드라이브 문자 확인
	for _, letter := range "CDEFGH" {
		path := string(letter) + ":\\"
		pathPtr, _ := syscall.BytePtrFromString(path)

		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		ret, _, _ := procGetDiskFreeSpaceA.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)
		if ret != 0 && totalBytes > 0 {
			disks = append(disks, DiskInfo{
				Path:  string(letter) + ":",
				Total: totalBytes,
				Free:  totalFreeBytes,
			})
		}
	}
	return disks, nil
}

// systemProcessorPerformanceInformation의 구조체
type sppi struct {
	IdleTime   int64 // 100ns units
	KernelTime int64
	UserTime   int64
	Reserved1  [2]int64
	Reserved2  uint32
}

func measureCPU(duration time.Duration) (float64, error) {
	numCPU := runtime.NumCPU()

	idle1, total1, err := getCPUTimes(numCPU)
	if err != nil {
		return 0, err
	}

	time.Sleep(duration)

	idle2, total2, err := getCPUTimes(numCPU)
	if err != nil {
		return 0, err
	}

	totalDelta := float64(total2 - total1)
	idleDelta := float64(idle2 - idle1)
	if totalDelta == 0 {
		return 0, nil
	}

	return (1 - idleDelta/totalDelta) * 100, nil
}

func getCPUTimes(numCPU int) (idle, total int64, err error) {
	bufSize := numCPU * int(unsafe.Sizeof(sppi{}))
	buf := make([]byte, bufSize)
	var retLen uint32

	// NtQuerySystemInformation, SystemProcessorPerformanceInformation = 8
	ret, _, _ := procNtQuerySystemInfo.Call(
		8,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if ret != 0 {
		return 0, 0, syscall.Errno(ret)
	}

	count := int(retLen) / int(unsafe.Sizeof(sppi{}))
	for i := 0; i < count; i++ {
		p := (*sppi)(unsafe.Pointer(&buf[i*int(unsafe.Sizeof(sppi{}))]))
		idle += p.IdleTime
		total += p.KernelTime + p.UserTime
	}
	return idle, total, nil
}

func getUptime() (time.Duration, error) {
	ret, _, err := procGetTickCount64.Call()
	if ret == 0 {
		return 0, err
	}
	return time.Duration(ret) * time.Millisecond, nil
}

func getHostnameOS() (string, error) {
	return os.Hostname()
}

func getLocale() string {
	// Windows: 환경변수 또는 시스템 로캘
	for _, key := range []string{"LANG", "LC_ALL", "LANGUAGE"} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	// PowerShell 없이 직접 레지스트리는 복잡하므로 GetUserDefaultLCID 사용
	proc := kernel32.NewProc("GetUserDefaultLocaleName")
	buf := make([]uint16, 85)
	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), 85)
	if ret > 0 {
		return syscall.UTF16ToString(buf)
	}
	return ""
}
