// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.21.4
// source: tkeygen.proto

package keygen

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

// Represents a BROADCAST message sent during Round 1 of the TSS keygen protocol.
type TKgRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash           []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	PolyCommitment []byte `protobuf:"bytes,2,opt,name=poly_commitment,json=polyCommitment,proto3" json:"poly_commitment,omitempty"`
}

func (x *TKgRound1Message) Reset() {
	*x = TKgRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tkeygen_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TKgRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TKgRound1Message) ProtoMessage() {}

func (x *TKgRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_tkeygen_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TKgRound1Message.ProtoReflect.Descriptor instead.
func (*TKgRound1Message) Descriptor() ([]byte, []int) {
	return file_tkeygen_proto_rawDescGZIP(), []int{0}
}

func (x *TKgRound1Message) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

func (x *TKgRound1Message) GetPolyCommitment() []byte {
	if x != nil {
		return x.PolyCommitment
	}
	return nil
}

// Represents a BROADCAST message sent to each party during Round 2 of the TSS keygen protocol.
type TKgRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ssid          []byte   `protobuf:"bytes,1,opt,name=ssid,proto3" json:"ssid,omitempty"`
	Srid          []byte   `protobuf:"bytes,2,opt,name=srid,proto3" json:"srid,omitempty"`
	PolyG         [][]byte `protobuf:"bytes,3,rep,name=poly_g,json=polyG,proto3" json:"poly_g,omitempty"`
	SchCommitment []byte   `protobuf:"bytes,4,opt,name=sch_commitment,json=schCommitment,proto3" json:"sch_commitment,omitempty"`
	U             []byte   `protobuf:"bytes,5,opt,name=u,proto3" json:"u,omitempty"`
	ChainCode     []byte   `protobuf:"bytes,6,opt,name=chain_code,json=chainCode,proto3" json:"chain_code,omitempty"`
}

func (x *TKgRound2Message1) Reset() {
	*x = TKgRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tkeygen_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TKgRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TKgRound2Message1) ProtoMessage() {}

func (x *TKgRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_tkeygen_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TKgRound2Message1.ProtoReflect.Descriptor instead.
func (*TKgRound2Message1) Descriptor() ([]byte, []int) {
	return file_tkeygen_proto_rawDescGZIP(), []int{1}
}

func (x *TKgRound2Message1) GetSsid() []byte {
	if x != nil {
		return x.Ssid
	}
	return nil
}

func (x *TKgRound2Message1) GetSrid() []byte {
	if x != nil {
		return x.Srid
	}
	return nil
}

func (x *TKgRound2Message1) GetPolyG() [][]byte {
	if x != nil {
		return x.PolyG
	}
	return nil
}

func (x *TKgRound2Message1) GetSchCommitment() []byte {
	if x != nil {
		return x.SchCommitment
	}
	return nil
}

func (x *TKgRound2Message1) GetU() []byte {
	if x != nil {
		return x.U
	}
	return nil
}

func (x *TKgRound2Message1) GetChainCode() []byte {
	if x != nil {
		return x.ChainCode
	}
	return nil
}

// Represents a P2P message sent to all parties during Round 2 of the TSS signing protocol.
type TKgRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share []byte `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *TKgRound2Message2) Reset() {
	*x = TKgRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tkeygen_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TKgRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TKgRound2Message2) ProtoMessage() {}

func (x *TKgRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_tkeygen_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TKgRound2Message2.ProtoReflect.Descriptor instead.
func (*TKgRound2Message2) Descriptor() ([]byte, []int) {
	return file_tkeygen_proto_rawDescGZIP(), []int{2}
}

func (x *TKgRound2Message2) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

// Represents a BROADCAST message sent during Round 3 of the EDDSA TSS keygen protocol.
type TKgRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SchProof []byte `protobuf:"bytes,1,opt,name=sch_proof,json=schProof,proto3" json:"sch_proof,omitempty"`
}

func (x *TKgRound3Message) Reset() {
	*x = TKgRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tkeygen_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TKgRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TKgRound3Message) ProtoMessage() {}

func (x *TKgRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_tkeygen_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TKgRound3Message.ProtoReflect.Descriptor instead.
func (*TKgRound3Message) Descriptor() ([]byte, []int) {
	return file_tkeygen_proto_rawDescGZIP(), []int{3}
}

func (x *TKgRound3Message) GetSchProof() []byte {
	if x != nil {
		return x.SchProof
	}
	return nil
}

var File_tkeygen_proto protoreflect.FileDescriptor

var file_tkeygen_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x74, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x17, 0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c,
	0x64, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x22, 0x4f, 0x0a, 0x10, 0x54, 0x4b, 0x67, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68,
	0x12, 0x27, 0x0a, 0x0f, 0x70, 0x6f, 0x6c, 0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x70, 0x6f, 0x6c, 0x79, 0x43,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0xa6, 0x01, 0x0a, 0x11, 0x54, 0x4b,
	0x67, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12,
	0x12, 0x0a, 0x04, 0x73, 0x73, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73,
	0x73, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x72, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x04, 0x73, 0x72, 0x69, 0x64, 0x12, 0x15, 0x0a, 0x06, 0x70, 0x6f, 0x6c, 0x79, 0x5f,
	0x67, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x05, 0x70, 0x6f, 0x6c, 0x79, 0x47, 0x12, 0x25,
	0x0a, 0x0e, 0x73, 0x63, 0x68, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0d, 0x73, 0x63, 0x68, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x0c, 0x0a, 0x01, 0x75, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x01, 0x75, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x43, 0x6f,
	0x64, 0x65, 0x22, 0x29, 0x0a, 0x11, 0x54, 0x4b, 0x67, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x22, 0x2f, 0x0a,
	0x10, 0x54, 0x4b, 0x67, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x63, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x73, 0x63, 0x68, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x12,
	0x5a, 0x10, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x2f, 0x6b, 0x65, 0x79, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tkeygen_proto_rawDescOnce sync.Once
	file_tkeygen_proto_rawDescData = file_tkeygen_proto_rawDesc
)

func file_tkeygen_proto_rawDescGZIP() []byte {
	file_tkeygen_proto_rawDescOnce.Do(func() {
		file_tkeygen_proto_rawDescData = protoimpl.X.CompressGZIP(file_tkeygen_proto_rawDescData)
	})
	return file_tkeygen_proto_rawDescData
}

var file_tkeygen_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_tkeygen_proto_goTypes = []interface{}{
	(*TKgRound1Message)(nil),  // 0: tsslib.threshold.keygen.TKgRound1Message
	(*TKgRound2Message1)(nil), // 1: tsslib.threshold.keygen.TKgRound2Message1
	(*TKgRound2Message2)(nil), // 2: tsslib.threshold.keygen.TKgRound2Message2
	(*TKgRound3Message)(nil),  // 3: tsslib.threshold.keygen.TKgRound3Message
}
var file_tkeygen_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_tkeygen_proto_init() }
func file_tkeygen_proto_init() {
	if File_tkeygen_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_tkeygen_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TKgRound1Message); i {
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
		file_tkeygen_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TKgRound2Message1); i {
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
		file_tkeygen_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TKgRound2Message2); i {
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
		file_tkeygen_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TKgRound3Message); i {
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
			RawDescriptor: file_tkeygen_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_tkeygen_proto_goTypes,
		DependencyIndexes: file_tkeygen_proto_depIdxs,
		MessageInfos:      file_tkeygen_proto_msgTypes,
	}.Build()
	File_tkeygen_proto = out.File
	file_tkeygen_proto_rawDesc = nil
	file_tkeygen_proto_goTypes = nil
	file_tkeygen_proto_depIdxs = nil
}
