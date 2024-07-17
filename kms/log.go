// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kms

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/netip"
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

// LogRecord is a structure representing a KMS log event.
type LogRecord struct {
	// The log level of the event.
	Level slog.Level

	// The log message.
	Message string

	// The time at which the event was produced.
	Time time.Time

	// The stack trace at the time the event was recorded.
	// Its first frame is the location at which this event
	// was produced and subsequent frames represent function
	// calls higher up the call stack.
	//
	// If empty, no stack trace has been captured.
	Trace []StackFrame

	// If non-empty, HTTP method of the request that caused
	// this event.
	Method string

	// If non-empty, URL path of the request that caused
	// this event.
	Path string

	// If non-empty, identity of the request that caused
	// this event.
	Identity Identity

	// If valid, IP address of the client sending the
	// request that caused this event.
	IP netip.Addr
}

// MarshalPB converts the LogRecord into its protobuf representation.
func (r *LogRecord) MarshalPB(v *pb.LogRecord) error {
	v.Level = int32(r.Level)
	v.Message = r.Message
	v.Time = pb.Time(r.Time)

	if len(r.Trace) > 0 {
		v.Trace = make([]*pb.LogRecord_StackFrame, 0, len(r.Trace))
		for _, t := range r.Trace {
			v.Trace = append(v.Trace, &pb.LogRecord_StackFrame{
				Function: t.Function,
				File:     t.File,
				Line:     uint32(t.Line),
			})
		}
	}
	if r.Method != "" || r.Path != "" || r.Identity != "" || r.IP.IsValid() {
		v.Req = &pb.LogRecord_Request{
			Method:   r.Method,
			Path:     r.Path,
			Identity: r.Identity.String(),
			IP:       r.IP.String(),
		}
	}
	return nil
}

// UnmarshalPB initializes the LogRecord from its protobuf representation.
func (r *LogRecord) UnmarshalPB(v *pb.LogRecord) error {
	var ip netip.Addr
	if v.Req != nil {
		var err error
		if ip, err = netip.ParseAddr(v.Req.IP); err != nil {
			return err
		}
	}

	r.Level = slog.Level(v.Level)
	r.Message = v.Message
	r.Time = v.Time.AsTime()

	r.Trace = make([]StackFrame, 0, len(v.Trace))
	for _, t := range v.GetTrace() {
		r.Trace = append(r.Trace, StackFrame{
			Function: t.Function,
			File:     t.File,
			Line:     int(t.Line),
		})
	}

	r.Method = v.Req.GetMethod()
	r.Path = v.Req.GetPath()
	r.Identity = Identity(v.Req.GetIdentity())
	r.IP = ip
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
