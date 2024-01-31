// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cmds

import (
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"

	pb "github.com/minio/kms-go/kms/protobuf"
	"google.golang.org/protobuf/proto"
)

type DecodeError struct {
	Cmd  Command
	Len  int
	Data []byte
	Type reflect.Type

	errMsg string
}

func (e *DecodeError) Error() string {
	if e.Cmd == 0 && len(e.Data) == 0 {
		return fmt.Sprintf("cmds: failed to decode command into value of type %s: %s", e.Type, e.errMsg)
	}
	if len(e.Data) == 0 {
		return fmt.Sprintf("cmds: failed to decode command %s into value of type %s: %s", e.Cmd, e.Type, e.errMsg)
	}
	return fmt.Sprintf("cmds: failed to decode command %s with %v into value of type %s: %s", e.Cmd, e.Data, e.Type, e.errMsg)
}

func Decode[M any, P pb.Pointer[M], T pb.Unmarshaler[P]](b []byte, cmd Command, v T) ([]byte, error) {
	var m M
	var p P = &m
	b, err := DecodePB(b, cmd, p)
	if err != nil {
		return nil, err
	}
	if err = v.UnmarshalPB(p); err != nil {
		return nil, err
	}
	return b, nil
}

func DecodePB(b []byte, cmd Command, v proto.Message) ([]byte, error) {
	if len(b) < 6 {
		return nil, &DecodeError{
			Cmd:    cmd,
			Type:   reflect.TypeOf(v),
			Data:   slices.Clone(b),
			errMsg: "invalid command format",
		}
	}
	if c := binary.BigEndian.Uint16(b); c != uint16(cmd) {
		return nil, &DecodeError{
			Cmd:    cmd,
			Type:   reflect.TypeOf(v),
			Data:   slices.Clone(b[:6]),
			errMsg: "received command " + Command(c).String(),
		}
	}

	n := binary.BigEndian.Uint32(b[2:])
	if v == nil {
		if n != 0 {
			return nil, &DecodeError{
				Cmd:    cmd,
				Type:   reflect.TypeOf(v),
				Data:   slices.Clone(b[:6]),
				errMsg: "invalid command arguments",
			}
		}
		return b[6:], nil
	}

	if len(b) < int(n)+6 {
		return nil, &DecodeError{
			Cmd:    cmd,
			Type:   reflect.TypeOf(v),
			Data:   slices.Clone(b),
			errMsg: "invalid length for received arguments",
		}
	}
	if err := proto.Unmarshal(b[6:6+int(n)], v); err != nil {
		return nil, err
	}
	return b[6+int(n):], nil
}
