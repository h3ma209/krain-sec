package resources

import (
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"time"
)

func CheckCpu() []float64 {

	percentage, err := cpu.Percent(time.Second, false)
	if err != nil {

	}
	fmt.Printf("CPU: %f\n", percentage)
	return percentage

}
