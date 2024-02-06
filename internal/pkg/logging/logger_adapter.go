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

package logging

import (
	"github.com/go-kit/log"
	"github.com/sirupsen/logrus"
)

// LogrusAdapter is an adapter that allows logrus Logger to be used as a go-kit/log Logger.
type LogrusAdapter struct {
	Logger *logrus.Logger
}

// NewLogrusAdapter creates a new LogrusAdapter with the provided logrus.Logger.
func NewLogrusAdapter(logger *logrus.Logger) log.Logger {
	return &LogrusAdapter{
		Logger: logger,
	}
}

// Log implements the go-kit/log Logger interface.
func (a *LogrusAdapter) Log(keyvals ...interface{}) error {
	if len(keyvals)%2 != 0 {
		keyvals = append(keyvals, "MISSING")
	}

	fields := logrus.Fields{}
	for i := 0; i < len(keyvals); i += 2 {
		key, ok := keyvals[i].(string)
		if !ok {
			// If the key is not a string, use a default key
			key = "missing_key"
		}
		fields[key] = keyvals[i+1]
	}

	a.Logger.WithFields(fields).Info("Log message")

	return nil
}
