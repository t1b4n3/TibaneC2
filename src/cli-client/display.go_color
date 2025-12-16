package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ANSI color codes
const (
	ColorReset   = "\x1b[0m"
	ColorRed     = "\x1b[31m"
	ColorGreen   = "\x1b[32m"
	ColorYellow  = "\x1b[33m"
	ColorBlue    = "\x1b[34m"
	ColorCyan    = "\x1b[36m"
	ColorWhite   = "\x1b[37m"
)

const (
	widthID       = 8
	widthCommand  = 20
	widthResp     = 60
	widthStatus   = 12
	widthImplant  = 11
	widthOS       = 15
	widthIP       = 15
	widthArch     = 15
	widthHostname = 30
	widthLastSeen = 15
)

// ---------------- Helper functions ----------------

func wrap(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var line string
	for _, word := range words {
		if utf8.RuneCountInString(line+" "+word) > width {
			lines = append(lines, line)
			line = word
		} else {
			if line != "" {
				line += " "
			}
			line += word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func colorStatus(status string) string {
	if status == "0" {
		return ColorYellow + "Pending" + ColorReset
	}
	return ColorGreen + "Completed" + ColorReset
}

func colorCommand(cmd string) string {
	return ColorCyan + cmd + ColorReset
}

func colorResponse(resp string) string {
	return ColorWhite + resp + ColorReset
}

// Print a table row with optional word wrap
func printRow(fields []string, widths []int, wraps []bool) {
	maxLines := 1
	lines := make([][]string, len(fields))
	for i, f := range fields {
		if wraps[i] {
			lines[i] = wrap(f, widths[i])
		} else {
			lines[i] = []string{f}
		}
		if len(lines[i]) > maxLines {
			maxLines = len(lines[i])
		}
	}

	for j := 0; j < maxLines; j++ {
		for i := range fields {
			cell := ""
			if j < len(lines[i]) {
				cell = lines[i][j]
			}
			fmt.Printf("%-*s  ", widths[i], cell)
		}
		fmt.Println()
	}
}


// Print table header with blue color
func printHeader(headers []string, widths []int) {
	var sb strings.Builder
	for i, h := range headers {
		sb.WriteString(fmt.Sprintf("%-*s  ", widths[i], h))
	}
	headerStr := sb.String()
	fmt.Println(ColorBlue + headerStr + ColorReset)
	fmt.Println(strings.Repeat("=", len(headerStr)))
}

// ---------------- Exported Functions ----------------

//export DisplayTasksPerAgent
func DisplayTasksPerAgent(data *C.char) {
	jsonStr := C.GoString(data)
	var parsed map[string][]string
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		fmt.Println("\n[-] Invalid JSON input")
		return
	}

	headers := []string{"task_id", "command", "response", "status"}
	widths := []int{widthID, widthCommand, widthResp, widthStatus}
	printHeader(headers, widths)

	tasks := len(parsed["task_id"])
	for i := 0; i < tasks; i++ {
		status := colorStatus(parsed["status"][i])
		cmd := colorCommand(parsed["command"][i])
		resp := colorResponse(parsed["response"][i])
		printRow(
			[]string{parsed["task_id"][i], cmd, resp, status},
			widths,
			[]bool{false, true, true, false},
		)
		fmt.Println(strings.Repeat("-", sum(widths)+len(widths)*2))
	}
}

//export DisplayAllTasks
func DisplayAllTasks(data *C.char) {
	jsonStr := C.GoString(data)
	var parsed map[string][]string
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		fmt.Println("\n[-] Invalid JSON input")
		return
	}

	headers := []string{"task_id", "implant_id", "command", "response", "status"}
	widths := []int{7, widthImplant, 15, widthResp, 10}
	printHeader(headers, widths)

	tasks := len(parsed["task_id"])
	for i := 0; i < tasks; i++ {
		status := colorStatus(parsed["status"][i])
		cmd := colorCommand(parsed["command"][i])
		resp := colorResponse(parsed["response"][i])
		printRow(
			[]string{parsed["task_id"][i], parsed["implant_id"][i], cmd, resp, status},
			widths,
			[]bool{false, false, true, true, false},
		)
		fmt.Println(strings.Repeat("-", sum(widths)+len(widths)*2))
	}
}

//export DisplayAllAgents
func DisplayAllAgents(data *C.char) {
	jsonStr := C.GoString(data)
	var parsed map[string][]string
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		fmt.Println("Invalid JSON input")
		return
	}

	fmt.Println("\n[+] Displaying All Implants\n")
	headers := []string{"implant_id", "os", "ip", "arch", "hostname", "last_seen"}
	widths := []int{widthImplant, widthOS, widthIP, widthArch, widthHostname, widthLastSeen}
	printHeader(headers, widths)

	agents := len(parsed["implant_id"])
	for i := 0; i < agents; i++ {
		printRow(
			[]string{
				parsed["implant_id"][i],
				parsed["os"][i],
				parsed["ip"][i],
				parsed["arch"][i],
				parsed["hostname"][i],
				parsed["last_seen"][i],
			},
			widths,
			[]bool{false, false, false, false, false, false},
		)
		fmt.Println(strings.Repeat("-", sum(widths)+len(widths)*2))
	}
}

//export DisplayCommandResponse
func DisplayCommandResponse(data *C.char) {
	jsonStr := C.GoString(data)
	var parsed map[string][]string
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		fmt.Println("\n[-] Invalid JSON input")
		return
	}

	headers := []string{"Command", "Response"}
	widths := []int{40, 80}
	printHeader(headers, widths)

	maxTasks := len(parsed["command"])
	if len(parsed["response"]) > maxTasks {
		maxTasks = len(parsed["response"])
	}

	for i := 0; i < maxTasks; i++ {
		cmd := ""
		if i < len(parsed["command"]) {
			cmd = colorCommand(parsed["command"][i])
		}
		resp := ""
		if i < len(parsed["response"]) {
			resp = colorResponse(parsed["response"][i])
		}
		printRow(
			[]string{cmd, resp},
			widths,
			[]bool{true, true},
		)
		fmt.Println(strings.Repeat("-", sum(widths)+len(widths)*2))
	}
}

// helper to sum ints
func sum(nums []int) int {
	total := 0
	for _, n := range nums {
		total += n
	}
	return total
}

func main() {}
