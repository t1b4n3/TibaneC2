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

const (
	widthID       = 8
	widthCommand  = 20
	widthResp     = 60
	widthStatus   = 12
	widthImplant  = 11
	widthOS       = 15
	widthIP       = 15
	widthMAC      = 15
	widthArch     = 15
	widthHostname = 15
	widthLastSeen = 15
)

// Word-wrap a string to fit within width
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

//export DisplayTasksPerAgent
func DisplayTasksPerAgent(data *C.char) {
	jsonStr := C.GoString(data)

	var parsed map[string][]string
	err := json.Unmarshal([]byte(jsonStr), &parsed)
	if err != nil {
		fmt.Println("\n[-] Invalid JSON input")
		return
	}

	header := fmt.Sprintf(
		"%-*s  %-*s  %-*s  %-*s",
		widthID, "task_id",
		widthCommand, "command",
		widthResp, "response",
		widthStatus, "status",
	)

	separator := strings.Repeat("=", len(header))
	fmt.Println(header)
	fmt.Println(separator)

	tasks := len(parsed["task_id"])
	for i := 0; i < tasks; i++ {
		id := parsed["task_id"][i]
		cmd := parsed["command"][i]
		resp := parsed["response"][i]
		status := parsed["status"][i]

		// Convert status to readable form
		statusText := "Pending"
		if status != "0" {
			statusText = "Completed"
		}

		respLines := wrap(resp, widthResp)
		cmdLines := wrap(cmd, widthCommand)

		maxLines := len(respLines)
		if len(cmdLines) > maxLines {
			maxLines = len(cmdLines)
		}

		for j := 0; j < maxLines; j++ {
			var idField, cmdField, respField, statusField string
			if j == 0 {
				idField = id
				statusField = statusText
			}
			if j < len(cmdLines) {
				cmdField = cmdLines[j]
			}
			if j < len(respLines) {
				respField = respLines[j]
			}
			fmt.Printf(
				"%-*s  %-*s  %-*s  %-*s\n",
				widthID, idField,
				widthCommand, cmdField,
				widthResp, respField,
				widthStatus, statusField,
			)
		}
		fmt.Println(strings.Repeat("-", len(header)))
	}
}

//export DisplayAllTasks
func DisplayAllTasks(data *C.char) {
	jsonStr := C.GoString(data)

	var parsed map[string][]string
	err := json.Unmarshal([]byte(jsonStr), &parsed)
	if err != nil {
		fmt.Println("\n[-] Invalid JSON input")
		return
	}

	header := fmt.Sprintf(
		"%-*s  %-*s  %-*s  %-*s  %-*s",
		7, "task_id",
		widthImplant, "implant_id",
		15, "command",
		widthResp, "response",
		10, "status",
	)

	separator := strings.Repeat("=", len(header))
	fmt.Println(header)
	fmt.Println(separator)

	tasks := len(parsed["task_id"])
	for i := 0; i < tasks; i++ {
		id := parsed["task_id"][i]
		implant := parsed["implant_id"][i]
		cmd := parsed["command"][i]
		resp := parsed["response"][i]
		status := parsed["status"][i]

		// Convert status to readable form
		statusText := "Pending"
		if status != "0" {
			statusText = "Completed"
		}

		respLines := wrap(resp, widthResp)
		cmdLines := wrap(cmd, 15)

		maxLines := len(respLines)
		if len(cmdLines) > maxLines {
			maxLines = len(cmdLines)
		}

		for j := 0; j < maxLines; j++ {
			var idField, implantField, cmdField, respField, statusField string
			if j == 0 {
				idField = id
				implantField = implant
				statusField = statusText
			}
			if j < len(cmdLines) {
				cmdField = cmdLines[j]
			}
			if j < len(respLines) {
				respField = respLines[j]
			}
			fmt.Printf(
				"%-*s  %-*s  %-*s  %-*s  %-*s\n",
				7, idField,
				widthImplant, implantField,
				15, cmdField,
				widthResp, respField,
				10, statusField,
			)
		}
		fmt.Println(strings.Repeat("-", len(header)))
	}
}

//export DisplayAllAgents
func DisplayAllAgents(data *C.char) {
	jsonStr := C.GoString(data)

	var parsed map[string][]string
	err := json.Unmarshal([]byte(jsonStr), &parsed)
	if err != nil {
		fmt.Println("Invalid JSON input")
		return
	}

	fmt.Println("\n[+] Displaying All Implants\n")

	header := fmt.Sprintf(
		"%-*s  %-*s  %-*s  %-*s  %-*s  %-*s ",
		widthImplant, "implant_id",
		widthOS, "os",
		widthIP, "ip",
		widthArch, "arch",
		widthHostname, "hostname",
		widthLastSeen, "last_seen",
	)

	separator := strings.Repeat("=", len(header))
	fmt.Println(header)
	fmt.Println(separator)

	agents := len(parsed["implant_id"])
	for i := 0; i < agents; i++ {
		id := parsed["implant_id"][i]
		os := parsed["os"][i]
		ip := parsed["ip"][i]
		arch := parsed["arch"][i]
		hostname := parsed["hostname"][i]
		lastSeen := parsed["last_seen"][i]

		fmt.Printf(
			"%-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
			widthImplant, id,
			widthOS, os,
			widthIP, ip,
			widthArch, arch,
			widthHostname, hostname,
			widthLastSeen, lastSeen,
		)
		fmt.Println(strings.Repeat("-", len(header)))
	}
}


// display 
//export DisplayCommandResponse
func DisplayCommandResponse(data *C.char) {
    jsonStr := C.GoString(data)

    var parsed map[string][]string
    err := json.Unmarshal([]byte(jsonStr), &parsed)
    if err != nil {
        fmt.Println("\n[-] Invalid JSON input")
        return
    }

    const (
        widthCommand = 40
        widthResp    = 80
    )

    // Header
    header := fmt.Sprintf("%-*s  %-*s", widthCommand, "Command", widthResp, "Response")
    separator := strings.Repeat("=", len(header))
    fmt.Println(header)
    fmt.Println(separator)

    // Check if we have the expected fields
    if parsed["command"] == nil || parsed["response"] == nil {
        fmt.Println("JSON missing required fields (command and/or response)")
        return
    }

    // Find the maximum length of either array
    maxTasks := len(parsed["command"])
    if len(parsed["response"]) > maxTasks {
        maxTasks = len(parsed["response"])
    }

    // Display each command/response pair
    for i := 0; i < maxTasks; i++ {
        cmd := ""
        if i < len(parsed["command"]) {
            cmd = parsed["command"][i]
        }

        resp := ""
        if i < len(parsed["response"]) {
            resp = parsed["response"][i]
        }

        cmdLines := wrap(cmd, widthCommand)
        respLines := wrap(resp, widthResp)

        maxLines := len(cmdLines)
        if len(respLines) > maxLines {
            maxLines = len(respLines)
        }

        for j := 0; j < maxLines; j++ {
            var cmdField, respField string
            if j < len(cmdLines) {
                cmdField = cmdLines[j]
            }
            if j < len(respLines) {
                respField = respLines[j]
            }
            fmt.Printf("%-*s  %-*s\n", widthCommand, cmdField, widthResp, respField)
        }
        fmt.Println(strings.Repeat("-", len(header)))
    }
}

func main() {}