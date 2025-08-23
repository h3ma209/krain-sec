package resources

import (
	"fmt"
	"github.com/shirou/gopsutil/mem"
	"time"
)

func CheckMemory() []float64 {
	v, err := mem.VirtualMemory()
	if err != nil {

	}
	fmt.Printf("Memory: %f%%\n", v.UsedPercent)
	time.Sleep(time.Second)
	return []float64{v.UsedPercent}
}
