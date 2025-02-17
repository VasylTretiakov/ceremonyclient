// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.12
// source: data.proto

package protobufs

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	DataService_GetCompressedSyncFrames_FullMethodName       = "/quilibrium.node.data.pb.DataService/GetCompressedSyncFrames"
	DataService_NegotiateCompressedSyncFrames_FullMethodName = "/quilibrium.node.data.pb.DataService/NegotiateCompressedSyncFrames"
	DataService_GetPublicChannel_FullMethodName              = "/quilibrium.node.data.pb.DataService/GetPublicChannel"
	DataService_GetDataFrame_FullMethodName                  = "/quilibrium.node.data.pb.DataService/GetDataFrame"
	DataService_HandlePreMidnightMint_FullMethodName         = "/quilibrium.node.data.pb.DataService/HandlePreMidnightMint"
	DataService_GetPreMidnightMintStatus_FullMethodName      = "/quilibrium.node.data.pb.DataService/GetPreMidnightMintStatus"
)

// DataServiceClient is the client API for DataService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type DataServiceClient interface {
	GetCompressedSyncFrames(ctx context.Context, in *ClockFramesRequest, opts ...grpc.CallOption) (DataService_GetCompressedSyncFramesClient, error)
	NegotiateCompressedSyncFrames(ctx context.Context, opts ...grpc.CallOption) (DataService_NegotiateCompressedSyncFramesClient, error)
	GetPublicChannel(ctx context.Context, opts ...grpc.CallOption) (DataService_GetPublicChannelClient, error)
	GetDataFrame(ctx context.Context, in *GetDataFrameRequest, opts ...grpc.CallOption) (*DataFrameResponse, error)
	HandlePreMidnightMint(ctx context.Context, in *MintCoinRequest, opts ...grpc.CallOption) (*PreMidnightMintResponse, error)
	GetPreMidnightMintStatus(ctx context.Context, in *PreMidnightMintStatusRequest, opts ...grpc.CallOption) (*PreMidnightMintResponse, error)
}

type dataServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDataServiceClient(cc grpc.ClientConnInterface) DataServiceClient {
	return &dataServiceClient{cc}
}

func (c *dataServiceClient) GetCompressedSyncFrames(ctx context.Context, in *ClockFramesRequest, opts ...grpc.CallOption) (DataService_GetCompressedSyncFramesClient, error) {
	stream, err := c.cc.NewStream(ctx, &DataService_ServiceDesc.Streams[0], DataService_GetCompressedSyncFrames_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &dataServiceGetCompressedSyncFramesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type DataService_GetCompressedSyncFramesClient interface {
	Recv() (*DataCompressedSync, error)
	grpc.ClientStream
}

type dataServiceGetCompressedSyncFramesClient struct {
	grpc.ClientStream
}

func (x *dataServiceGetCompressedSyncFramesClient) Recv() (*DataCompressedSync, error) {
	m := new(DataCompressedSync)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *dataServiceClient) NegotiateCompressedSyncFrames(ctx context.Context, opts ...grpc.CallOption) (DataService_NegotiateCompressedSyncFramesClient, error) {
	stream, err := c.cc.NewStream(ctx, &DataService_ServiceDesc.Streams[1], DataService_NegotiateCompressedSyncFrames_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &dataServiceNegotiateCompressedSyncFramesClient{stream}
	return x, nil
}

type DataService_NegotiateCompressedSyncFramesClient interface {
	Send(*DataCompressedSyncRequestMessage) error
	Recv() (*DataCompressedSyncResponseMessage, error)
	grpc.ClientStream
}

type dataServiceNegotiateCompressedSyncFramesClient struct {
	grpc.ClientStream
}

func (x *dataServiceNegotiateCompressedSyncFramesClient) Send(m *DataCompressedSyncRequestMessage) error {
	return x.ClientStream.SendMsg(m)
}

func (x *dataServiceNegotiateCompressedSyncFramesClient) Recv() (*DataCompressedSyncResponseMessage, error) {
	m := new(DataCompressedSyncResponseMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *dataServiceClient) GetPublicChannel(ctx context.Context, opts ...grpc.CallOption) (DataService_GetPublicChannelClient, error) {
	stream, err := c.cc.NewStream(ctx, &DataService_ServiceDesc.Streams[2], DataService_GetPublicChannel_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &dataServiceGetPublicChannelClient{stream}
	return x, nil
}

type DataService_GetPublicChannelClient interface {
	Send(*P2PChannelEnvelope) error
	Recv() (*P2PChannelEnvelope, error)
	grpc.ClientStream
}

type dataServiceGetPublicChannelClient struct {
	grpc.ClientStream
}

func (x *dataServiceGetPublicChannelClient) Send(m *P2PChannelEnvelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *dataServiceGetPublicChannelClient) Recv() (*P2PChannelEnvelope, error) {
	m := new(P2PChannelEnvelope)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *dataServiceClient) GetDataFrame(ctx context.Context, in *GetDataFrameRequest, opts ...grpc.CallOption) (*DataFrameResponse, error) {
	out := new(DataFrameResponse)
	err := c.cc.Invoke(ctx, DataService_GetDataFrame_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dataServiceClient) HandlePreMidnightMint(ctx context.Context, in *MintCoinRequest, opts ...grpc.CallOption) (*PreMidnightMintResponse, error) {
	out := new(PreMidnightMintResponse)
	err := c.cc.Invoke(ctx, DataService_HandlePreMidnightMint_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *dataServiceClient) GetPreMidnightMintStatus(ctx context.Context, in *PreMidnightMintStatusRequest, opts ...grpc.CallOption) (*PreMidnightMintResponse, error) {
	out := new(PreMidnightMintResponse)
	err := c.cc.Invoke(ctx, DataService_GetPreMidnightMintStatus_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DataServiceServer is the server API for DataService service.
// All implementations must embed UnimplementedDataServiceServer
// for forward compatibility
type DataServiceServer interface {
	GetCompressedSyncFrames(*ClockFramesRequest, DataService_GetCompressedSyncFramesServer) error
	NegotiateCompressedSyncFrames(DataService_NegotiateCompressedSyncFramesServer) error
	GetPublicChannel(DataService_GetPublicChannelServer) error
	GetDataFrame(context.Context, *GetDataFrameRequest) (*DataFrameResponse, error)
	HandlePreMidnightMint(context.Context, *MintCoinRequest) (*PreMidnightMintResponse, error)
	GetPreMidnightMintStatus(context.Context, *PreMidnightMintStatusRequest) (*PreMidnightMintResponse, error)
	mustEmbedUnimplementedDataServiceServer()
}

// UnimplementedDataServiceServer must be embedded to have forward compatible implementations.
type UnimplementedDataServiceServer struct {
}

func (UnimplementedDataServiceServer) GetCompressedSyncFrames(*ClockFramesRequest, DataService_GetCompressedSyncFramesServer) error {
	return status.Errorf(codes.Unimplemented, "method GetCompressedSyncFrames not implemented")
}
func (UnimplementedDataServiceServer) NegotiateCompressedSyncFrames(DataService_NegotiateCompressedSyncFramesServer) error {
	return status.Errorf(codes.Unimplemented, "method NegotiateCompressedSyncFrames not implemented")
}
func (UnimplementedDataServiceServer) GetPublicChannel(DataService_GetPublicChannelServer) error {
	return status.Errorf(codes.Unimplemented, "method GetPublicChannel not implemented")
}
func (UnimplementedDataServiceServer) GetDataFrame(context.Context, *GetDataFrameRequest) (*DataFrameResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDataFrame not implemented")
}
func (UnimplementedDataServiceServer) HandlePreMidnightMint(context.Context, *MintCoinRequest) (*PreMidnightMintResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HandlePreMidnightMint not implemented")
}
func (UnimplementedDataServiceServer) GetPreMidnightMintStatus(context.Context, *PreMidnightMintStatusRequest) (*PreMidnightMintResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPreMidnightMintStatus not implemented")
}
func (UnimplementedDataServiceServer) mustEmbedUnimplementedDataServiceServer() {}

// UnsafeDataServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to DataServiceServer will
// result in compilation errors.
type UnsafeDataServiceServer interface {
	mustEmbedUnimplementedDataServiceServer()
}

func RegisterDataServiceServer(s grpc.ServiceRegistrar, srv DataServiceServer) {
	s.RegisterService(&DataService_ServiceDesc, srv)
}

func _DataService_GetCompressedSyncFrames_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ClockFramesRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(DataServiceServer).GetCompressedSyncFrames(m, &dataServiceGetCompressedSyncFramesServer{stream})
}

type DataService_GetCompressedSyncFramesServer interface {
	Send(*DataCompressedSync) error
	grpc.ServerStream
}

type dataServiceGetCompressedSyncFramesServer struct {
	grpc.ServerStream
}

func (x *dataServiceGetCompressedSyncFramesServer) Send(m *DataCompressedSync) error {
	return x.ServerStream.SendMsg(m)
}

func _DataService_NegotiateCompressedSyncFrames_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DataServiceServer).NegotiateCompressedSyncFrames(&dataServiceNegotiateCompressedSyncFramesServer{stream})
}

type DataService_NegotiateCompressedSyncFramesServer interface {
	Send(*DataCompressedSyncResponseMessage) error
	Recv() (*DataCompressedSyncRequestMessage, error)
	grpc.ServerStream
}

type dataServiceNegotiateCompressedSyncFramesServer struct {
	grpc.ServerStream
}

func (x *dataServiceNegotiateCompressedSyncFramesServer) Send(m *DataCompressedSyncResponseMessage) error {
	return x.ServerStream.SendMsg(m)
}

func (x *dataServiceNegotiateCompressedSyncFramesServer) Recv() (*DataCompressedSyncRequestMessage, error) {
	m := new(DataCompressedSyncRequestMessage)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _DataService_GetPublicChannel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DataServiceServer).GetPublicChannel(&dataServiceGetPublicChannelServer{stream})
}

type DataService_GetPublicChannelServer interface {
	Send(*P2PChannelEnvelope) error
	Recv() (*P2PChannelEnvelope, error)
	grpc.ServerStream
}

type dataServiceGetPublicChannelServer struct {
	grpc.ServerStream
}

func (x *dataServiceGetPublicChannelServer) Send(m *P2PChannelEnvelope) error {
	return x.ServerStream.SendMsg(m)
}

func (x *dataServiceGetPublicChannelServer) Recv() (*P2PChannelEnvelope, error) {
	m := new(P2PChannelEnvelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _DataService_GetDataFrame_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDataFrameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DataServiceServer).GetDataFrame(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DataService_GetDataFrame_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DataServiceServer).GetDataFrame(ctx, req.(*GetDataFrameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DataService_HandlePreMidnightMint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MintCoinRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DataServiceServer).HandlePreMidnightMint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DataService_HandlePreMidnightMint_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DataServiceServer).HandlePreMidnightMint(ctx, req.(*MintCoinRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DataService_GetPreMidnightMintStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PreMidnightMintStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DataServiceServer).GetPreMidnightMintStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DataService_GetPreMidnightMintStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DataServiceServer).GetPreMidnightMintStatus(ctx, req.(*PreMidnightMintStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// DataService_ServiceDesc is the grpc.ServiceDesc for DataService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var DataService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "quilibrium.node.data.pb.DataService",
	HandlerType: (*DataServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetDataFrame",
			Handler:    _DataService_GetDataFrame_Handler,
		},
		{
			MethodName: "HandlePreMidnightMint",
			Handler:    _DataService_HandlePreMidnightMint_Handler,
		},
		{
			MethodName: "GetPreMidnightMintStatus",
			Handler:    _DataService_GetPreMidnightMintStatus_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetCompressedSyncFrames",
			Handler:       _DataService_GetCompressedSyncFrames_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "NegotiateCompressedSyncFrames",
			Handler:       _DataService_NegotiateCompressedSyncFrames_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "GetPublicChannel",
			Handler:       _DataService_GetPublicChannel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "data.proto",
}

const (
	DataIPCService_CalculateChallengeProof_FullMethodName = "/quilibrium.node.data.pb.DataIPCService/CalculateChallengeProof"
)

// DataIPCServiceClient is the client API for DataIPCService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type DataIPCServiceClient interface {
	CalculateChallengeProof(ctx context.Context, in *ChallengeProofRequest, opts ...grpc.CallOption) (*ChallengeProofResponse, error)
}

type dataIPCServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDataIPCServiceClient(cc grpc.ClientConnInterface) DataIPCServiceClient {
	return &dataIPCServiceClient{cc}
}

func (c *dataIPCServiceClient) CalculateChallengeProof(ctx context.Context, in *ChallengeProofRequest, opts ...grpc.CallOption) (*ChallengeProofResponse, error) {
	out := new(ChallengeProofResponse)
	err := c.cc.Invoke(ctx, DataIPCService_CalculateChallengeProof_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DataIPCServiceServer is the server API for DataIPCService service.
// All implementations must embed UnimplementedDataIPCServiceServer
// for forward compatibility
type DataIPCServiceServer interface {
	CalculateChallengeProof(context.Context, *ChallengeProofRequest) (*ChallengeProofResponse, error)
	mustEmbedUnimplementedDataIPCServiceServer()
}

// UnimplementedDataIPCServiceServer must be embedded to have forward compatible implementations.
type UnimplementedDataIPCServiceServer struct {
}

func (UnimplementedDataIPCServiceServer) CalculateChallengeProof(context.Context, *ChallengeProofRequest) (*ChallengeProofResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CalculateChallengeProof not implemented")
}
func (UnimplementedDataIPCServiceServer) mustEmbedUnimplementedDataIPCServiceServer() {}

// UnsafeDataIPCServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to DataIPCServiceServer will
// result in compilation errors.
type UnsafeDataIPCServiceServer interface {
	mustEmbedUnimplementedDataIPCServiceServer()
}

func RegisterDataIPCServiceServer(s grpc.ServiceRegistrar, srv DataIPCServiceServer) {
	s.RegisterService(&DataIPCService_ServiceDesc, srv)
}

func _DataIPCService_CalculateChallengeProof_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChallengeProofRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DataIPCServiceServer).CalculateChallengeProof(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: DataIPCService_CalculateChallengeProof_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DataIPCServiceServer).CalculateChallengeProof(ctx, req.(*ChallengeProofRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// DataIPCService_ServiceDesc is the grpc.ServiceDesc for DataIPCService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var DataIPCService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "quilibrium.node.data.pb.DataIPCService",
	HandlerType: (*DataIPCServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CalculateChallengeProof",
			Handler:    _DataIPCService_CalculateChallengeProof_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "data.proto",
}
