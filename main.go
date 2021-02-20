package main

import (
	"fmt"
	"os"
)

func main() {
	if itemInArray("-h", os.Args) || itemInArray("--help", os.Args) {
		fmt.Println("A tool to get timestamp from time string")
		fmt.Println("")
		fmt.Println("Usage: " + os.Args[0] + " [Date] [Time]")
		fmt.Println("Example:")
		fmt.Println("  " + os.Args[0] + " 2021-02-01")
		fmt.Println("  " + os.Args[0] + " 2021-02-01 14:30:44")
		exit(0)
	}

	if err := try(func() {
		if len(os.Args) == 1 {
			fmt.Println(now())
		} else if len(os.Args) == 2 {
			fmt.Println(strptime("%Y-%m-%d", os.Args[1]))
		} else if len(os.Args) == 3 {
			fmt.Println(strptime("%Y-%m-%d %H:%M:%S", os.Args[1]+" "+os.Args[2]))
		} else {
			fmt.Println("Wrong number of parameters")
			exit(1)
		}
	}).Error; err != nil {
		fmt.Println("Error:", err)
		exit(1)
	}
}
