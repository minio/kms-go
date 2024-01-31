// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cmds

import (
	"encoding/binary"

	pb "github.com/minio/kms-go/kms/protobuf"
	"google.golang.org/protobuf/proto"
)

func Encode[M any, P pb.Pointer[M], T pb.Marshaler[P]](b []byte, cmd Command, v T) ([]byte, error) {
	var m M
	var p P = &m
	if err := v.MarshalPB(p); err != nil {
		return nil, err
	}
	return EncodePB(b, cmd, p)
}

func EncodePB(b []byte, cmd Command, msg proto.Message) ([]byte, error) {
	s := len(b)

	b = binary.BigEndian.AppendUint16(b, uint16(cmd))
	b = append(b, 0, 0, 0, 0) // Write zero as placeholder until we know the protobuf size

	if msg != nil {
		var err error
		b, err = proto.MarshalOptions{}.MarshalAppend(b, msg)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(b[s+2:], uint32(len(b)-(s+6)))
	}
	return b, nil
}
