package resources


func Resources(){
	go func(){
		for {
			CheckCpu()
			CheckMemory()
		}
	}()
}