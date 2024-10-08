// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v3.21.4
// source: keygen.proto

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

// Represents a BROADCAST message sent during Round 1 of the EDDSA TSS keygen protocol.
type KGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Commitment []byte `protobuf:"bytes,1,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *KGRound1Message) Reset() {
	*x = KGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keygen_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound1Message) ProtoMessage() {}

func (x *KGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_keygen_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound1Message.ProtoReflect.Descriptor instead.
func (*KGRound1Message) Descriptor() ([]byte, []int) {
	return file_keygen_proto_rawDescGZIP(), []int{0}
}

func (x *KGRound1Message) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

// Represents a BROADCAST message sent to each party during Round 2 of the EDDSA TSS keygen protocol.
type KGRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ssid        []byte `protobuf:"bytes,1,opt,name=ssid,proto3" json:"ssid,omitempty"`
	PartyIndex  int32  `protobuf:"varint,2,opt,name=party_index,json=partyIndex,proto3" json:"party_index,omitempty"`
	Srid        []byte `protobuf:"bytes,3,opt,name=srid,proto3" json:"srid,omitempty"`
	PublicXX    []byte `protobuf:"bytes,4,opt,name=public_x_x,json=publicXX,proto3" json:"public_x_x,omitempty"`
	PublicXY    []byte `protobuf:"bytes,5,opt,name=public_x_y,json=publicXY,proto3" json:"public_x_y,omitempty"`
	CommitmentX []byte `protobuf:"bytes,6,opt,name=commitment_x,json=commitmentX,proto3" json:"commitment_x,omitempty"`
	CommitmentY []byte `protobuf:"bytes,7,opt,name=commitment_y,json=commitmentY,proto3" json:"commitment_y,omitempty"`
	U           []byte `protobuf:"bytes,8,opt,name=u,proto3" json:"u,omitempty"`
	ChainCode   []byte `protobuf:"bytes,9,opt,name=chain_code,json=chainCode,proto3" json:"chain_code,omitempty"`
}

func (x *KGRound2Message) Reset() {
	*x = KGRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keygen_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound2Message) ProtoMessage() {}

func (x *KGRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_keygen_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound2Message.ProtoReflect.Descriptor instead.
func (*KGRound2Message) Descriptor() ([]byte, []int) {
	return file_keygen_proto_rawDescGZIP(), []int{1}
}

func (x *KGRound2Message) GetSsid() []byte {
	if x != nil {
		return x.Ssid
	}
	return nil
}

func (x *KGRound2Message) GetPartyIndex() int32 {
	if x != nil {
		return x.PartyIndex
	}
	return 0
}

func (x *KGRound2Message) GetSrid() []byte {
	if x != nil {
		return x.Srid
	}
	return nil
}

func (x *KGRound2Message) GetPublicXX() []byte {
	if x != nil {
		return x.PublicXX
	}
	return nil
}

func (x *KGRound2Message) GetPublicXY() []byte {
	if x != nil {
		return x.PublicXY
	}
	return nil
}

func (x *KGRound2Message) GetCommitmentX() []byte {
	if x != nil {
		return x.CommitmentX
	}
	return nil
}

func (x *KGRound2Message) GetCommitmentY() []byte {
	if x != nil {
		return x.CommitmentY
	}
	return nil
}

func (x *KGRound2Message) GetU() []byte {
	if x != nil {
		return x.U
	}
	return nil
}

func (x *KGRound2Message) GetChainCode() []byte {
	if x != nil {
		return x.ChainCode
	}
	return nil
}

// Represents a BROADCAST message sent during Round 3 of the EDDSA TSS keygen protocol.
type KGRound3Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SchProof []byte `protobuf:"bytes,1,opt,name=sch_proof,json=schProof,proto3" json:"sch_proof,omitempty"`
}

func (x *KGRound3Message) Reset() {
	*x = KGRound3Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_keygen_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KGRound3Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KGRound3Message) ProtoMessage() {}

func (x *KGRound3Message) ProtoReflect() protoreflect.Message {
	mi := &file_keygen_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KGRound3Message.ProtoReflect.Descriptor instead.
func (*KGRound3Message) Descriptor() ([]byte, []int) {
	return file_keygen_proto_rawDescGZIP(), []int{2}
}

func (x *KGRound3Message) GetSchProof() []byte {
	if x != nil {
		return x.SchProof
	}
	return nil
}

var File_keygen_proto protoreflect.FileDescriptor

var file_keygen_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1b,
	0x74, 0x73, 0x73, 0x6c, 0x69, 0x62, 0x2e, 0x6e, 0x6f, 0x6e, 0x5f, 0x74, 0x68, 0x72, 0x65, 0x73,
	0x68, 0x6f, 0x6c, 0x64, 0x2e, 0x6b, 0x65, 0x79, 0x67, 0x65, 0x6e, 0x22, 0x31, 0x0a, 0x0f, 0x4b,
	0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e,
	0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x89,
	0x02, 0x0a, 0x0f, 0x4b, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x73, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x73, 0x73, 0x69, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x61, 0x72, 0x74, 0x79, 0x5f,
	0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0a, 0x70, 0x61, 0x72,
	0x74, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x72, 0x69, 0x64, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x73, 0x72, 0x69, 0x64, 0x12, 0x1c, 0x0a, 0x0a, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x78, 0x5f, 0x78, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x08, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x58, 0x58, 0x12, 0x1c, 0x0a, 0x0a, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x5f, 0x78, 0x5f, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x58, 0x59, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x78, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x63,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x58, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x6f,
	0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x59, 0x12, 0x0c, 0x0a,
	0x01, 0x75, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x75, 0x12, 0x1d, 0x0a, 0x0a, 0x63,
	0x68, 0x61, 0x69, 0x6e, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x43, 0x6f, 0x64, 0x65, 0x22, 0x2e, 0x0a, 0x0f, 0x4b, 0x47,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1b, 0x0a,
	0x09, 0x73, 0x63, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x08, 0x73, 0x63, 0x68, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x42, 0x16, 0x5a, 0x14, 0x6e, 0x6f,
	0x6e, 0x5f, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x2f, 0x6b, 0x65, 0x79, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_keygen_proto_rawDescOnce sync.Once
	file_keygen_proto_rawDescData = file_keygen_proto_rawDesc
)

func file_keygen_proto_rawDescGZIP() []byte {
	file_keygen_proto_rawDescOnce.Do(func() {
		file_keygen_proto_rawDescData = protoimpl.X.CompressGZIP(file_keygen_proto_rawDescData)
	})
	return file_keygen_proto_rawDescData
}

var file_keygen_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_keygen_proto_goTypes = []interface{}{
	(*KGRound1Message)(nil), // 0: tsslib.non_threshold.keygen.KGRound1Message
	(*KGRound2Message)(nil), // 1: tsslib.non_threshold.keygen.KGRound2Message
	(*KGRound3Message)(nil), // 2: tsslib.non_threshold.keygen.KGRound3Message
}
var file_keygen_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_keygen_proto_init() }
func file_keygen_proto_init() {
	if File_keygen_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_keygen_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound1Message); i {
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
		file_keygen_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound2Message); i {
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
		file_keygen_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KGRound3Message); i {
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
			RawDescriptor: file_keygen_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_keygen_proto_goTypes,
		DependencyIndexes: file_keygen_proto_depIdxs,
		MessageInfos:      file_keygen_proto_msgTypes,
	}.Build()
	File_keygen_proto = out.File
	file_keygen_proto_rawDesc = nil
	file_keygen_proto_goTypes = nil
	file_keygen_proto_depIdxs = nil
}
