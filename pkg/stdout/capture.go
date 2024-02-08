/*
 * Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package stdout

import (
	"bufio"
	"context"
	"log"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"
)

func Capture(ctx context.Context, inner func() error) error {
	r, _, cleanup := mustHijackStdOut()
	scanner := bufio.NewScanner(r)
	go func() {
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			logEntry := scanner.Text()
			parsedLogEntry := parseLogEntry(logEntry)
			if parsedLogEntry.IsRawString {
				logrus.StandardLogger().Out.Write([]byte(parsedLogEntry.Message + "\n"))
				continue
			}
			logrus.WithField("dcgm_level", parsedLogEntry.Level).Info(parsedLogEntry.Message)
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading from pipe: %v", err)
		}
	}()

	defer func() {
		cleanup()
	}()

	// Call function here
	return inner()
}

func mustHijackStdOut() (r *os.File, o *os.File, cleanup func()) {

	var w *os.File
	// Clone Stdout to origStdout.
	origStdout, err := syscall.Dup(syscall.Stdout)
	if err != nil {
		panic(err)
	}

	r, w, err = os.Pipe()
	if err != nil {
		panic(err)
	}

	// Clone the pipe's writer to the actual Stdout descriptor; from this point
	// on, writes to Stdout will go to w.
	if err = syscall.Dup2(int(w.Fd()), syscall.Stdout); err != nil {
		panic(err)
	}

	// Write log entries to the original stdout
	o = os.NewFile(uintptr(origStdout), "/dev/tty")

	cleanup = func() {
		w.Close()
		syscall.Close(syscall.Stdout)
		// Restore original Stdout.
		syscall.Dup2(origStdout, syscall.Stdout)
		syscall.Close(origStdout)
	}

	return
}
