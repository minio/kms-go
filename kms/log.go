// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"time"

	pb "github.com/minio/kms-go/kms/protobuf"
)

// StackFrame contains the resolved file and line number
// of a function call.
type StackFrame struct {
	// Function is the package path-qualified function name containing the
	// source line. If non-empty, this string uniquely identifies a single
	// function in the program. This may be the empty string if not known.
	Function string

	// File and Line are the file name and line number (1-based) of the source
	// line. These may be the empty string and zero, respectively, if not known.
	File string
	Line int
}

// MarshalPB converts the StackFrame into its protobuf representation.
func (s *StackFrame) MarshalPB(v *pb.LogRecord_StackFrame) error {
	v.Function = s.Function
	v.File = s.File
	v.Line = uint32(s.Line)
	return nil
}

// UnmarshalPB initializes the StackFrame from its protobuf representation.
func (s *StackFrame) UnmarshalPB(v *pb.LogRecord_StackFrame) error {
	s.Function = v.Function
	s.File = v.File
	s.Line = int(v.Line)
	return nil
}

// LogRecord is a structure representing a KMS server log record.
type LogRecord struct {
	Level   slog.Level // The log level of the record.
	Message string     // The log message.
	Time    time.Time  // The time at which the record was created.

	// Trace is stack trace of function calls. Its first frame
	// is the location at which this record was created and
	// subsequent frames represent function calls higher up the
	// call stack.
	//
	// If empty, no stack trace has been captured.
	Trace []StackFrame
}

// MarshalPB converts the LogRecord into its protobuf representation.
func (r *LogRecord) MarshalPB(v *pb.LogRecord) error {
	v.Level = int32(r.Level)
	v.Message = r.Message
	v.Time = pb.Time(r.Time)

	if len(r.Trace) > 0 {
		v.Trace = make([]*pb.LogRecord_StackFrame, 0, len(r.Trace))
		for _, frame := range r.Trace {
			v.Trace = append(v.Trace, &pb.LogRecord_StackFrame{
				Function: frame.Function,
				File:     frame.File,
				Line:     uint32(frame.Line),
			})
		}
	}
	return nil
}

// UnmarshalPB initializes the LogRecord from its protobuf representation.
func (r *LogRecord) UnmarshalPB(v *pb.LogRecord) error {
	r.Level = slog.Level(v.Level)
	r.Message = v.Message
	r.Time = v.Time.AsTime()
	r.Trace = nil

	if len(v.Trace) > 0 {
		r.Trace = make([]StackFrame, 0, len(v.Trace))
		for _, frame := range v.Trace {
			r.Trace = append(r.Trace, StackFrame{
				Function: frame.Function,
				File:     frame.File,
				Line:     int(frame.Line),
			})
		}
	}
	return nil
}

// readLogRecord reads a length-encoded protobuf log record
// into buf and unmarshales it into rec. It returns the first
// error encountered while reading from r.
func readLogRecord(r io.Reader, buf []byte, rec *LogRecord) error {
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}

	msgLen := binary.BigEndian.Uint32(buf)
	if uint64(len(buf)) < uint64(msgLen) {
		return errors.New("kms: log record too large")
	}

	if _, err := io.ReadFull(r, buf[:msgLen]); err != nil {
		return err
	}
	return pb.Unmarshal(buf[:msgLen], rec)
}
