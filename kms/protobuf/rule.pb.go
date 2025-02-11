// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Generate the Go protobuf code by running the protobuf compiler
// from the repository root:
//
//   $ protoc -I=./kms/protobuf --go_out=. ./kms/protobuf/*.proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.29.3
// source: rule.proto

package protobuf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Rule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Rule) Reset() {
	*x = Rule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rule_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Rule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Rule) ProtoMessage() {}

func (x *Rule) ProtoReflect() protoreflect.Message {
	mi := &file_rule_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Rule.ProtoReflect.Descriptor instead.
func (*Rule) Descriptor() ([]byte, []int) {
	return file_rule_proto_rawDescGZIP(), []int{0}
}

type RuleSet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Rules map[string]*Rule `protobuf:"bytes,1,rep,name=Rules,json=rules,proto3" json:"Rules,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *RuleSet) Reset() {
	*x = RuleSet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rule_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RuleSet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleSet) ProtoMessage() {}

func (x *RuleSet) ProtoReflect() protoreflect.Message {
	mi := &file_rule_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleSet.ProtoReflect.Descriptor instead.
func (*RuleSet) Descriptor() ([]byte, []int) {
	return file_rule_proto_rawDescGZIP(), []int{1}
}

func (x *RuleSet) GetRules() map[string]*Rule {
	if x != nil {
		return x.Rules
	}
	return nil
}

var File_rule_proto protoreflect.FileDescriptor

var file_rule_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x72, 0x75, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6d, 0x69,
	0x6e, 0x69, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x22, 0x06, 0x0a, 0x04, 0x52, 0x75, 0x6c, 0x65, 0x22,
	0x89, 0x01, 0x0a, 0x07, 0x52, 0x75, 0x6c, 0x65, 0x53, 0x65, 0x74, 0x12, 0x33, 0x0a, 0x05, 0x52,
	0x75, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x6d, 0x69, 0x6e,
	0x69, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x53, 0x65, 0x74, 0x2e, 0x52,
	0x75, 0x6c, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x72, 0x75, 0x6c, 0x65, 0x73,
	0x1a, 0x49, 0x0a, 0x0a, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x25, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x6d, 0x69, 0x6e, 0x69, 0x6f, 0x2e, 0x6b, 0x6d, 0x73, 0x2e, 0x52, 0x75, 0x6c, 0x65,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x0e, 0x5a, 0x0c, 0x6b,
	0x6d, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_rule_proto_rawDescOnce sync.Once
	file_rule_proto_rawDescData = file_rule_proto_rawDesc
)

func file_rule_proto_rawDescGZIP() []byte {
	file_rule_proto_rawDescOnce.Do(func() {
		file_rule_proto_rawDescData = protoimpl.X.CompressGZIP(file_rule_proto_rawDescData)
	})
	return file_rule_proto_rawDescData
}

var file_rule_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_rule_proto_goTypes = []interface{}{
	(*Rule)(nil),    // 0: minio.kms.Rule
	(*RuleSet)(nil), // 1: minio.kms.RuleSet
	nil,             // 2: minio.kms.RuleSet.RulesEntry
}
var file_rule_proto_depIdxs = []int32{
	2, // 0: minio.kms.RuleSet.Rules:type_name -> minio.kms.RuleSet.RulesEntry
	0, // 1: minio.kms.RuleSet.RulesEntry.value:type_name -> minio.kms.Rule
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_rule_proto_init() }
func file_rule_proto_init() {
	if File_rule_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rule_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Rule); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_rule_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RuleSet); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_rule_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_rule_proto_goTypes,
		DependencyIndexes: file_rule_proto_depIdxs,
		MessageInfos:      file_rule_proto_msgTypes,
	}.Build()
	File_rule_proto = out.File
	file_rule_proto_rawDesc = nil
	file_rule_proto_goTypes = nil
	file_rule_proto_depIdxs = nil
}
