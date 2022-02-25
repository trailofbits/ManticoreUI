package muicore;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.44.1)",
    comments = "Source: MUICore.proto")
@io.grpc.stub.annotations.GrpcGenerated
public final class ManticoreUIGrpc {

  private ManticoreUIGrpc() {}

  public static final String SERVICE_NAME = "muicore.ManticoreUI";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.TerminateResponse> getTerminateMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Terminate",
      requestType = muicore.MUICore.ManticoreInstance.class,
      responseType = muicore.MUICore.TerminateResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.TerminateResponse> getTerminateMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance, muicore.MUICore.TerminateResponse> getTerminateMethod;
    if ((getTerminateMethod = ManticoreUIGrpc.getTerminateMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getTerminateMethod = ManticoreUIGrpc.getTerminateMethod) == null) {
          ManticoreUIGrpc.getTerminateMethod = getTerminateMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.ManticoreInstance, muicore.MUICore.TerminateResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Terminate"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.TerminateResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("Terminate"))
              .build();
        }
      }
    }
    return getTerminateMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.CLIArguments,
      muicore.MUICore.ManticoreInstance> getStartMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "Start",
      requestType = muicore.MUICore.CLIArguments.class,
      responseType = muicore.MUICore.ManticoreInstance.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.CLIArguments,
      muicore.MUICore.ManticoreInstance> getStartMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.CLIArguments, muicore.MUICore.ManticoreInstance> getStartMethod;
    if ((getStartMethod = ManticoreUIGrpc.getStartMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getStartMethod = ManticoreUIGrpc.getStartMethod) == null) {
          ManticoreUIGrpc.getStartMethod = getStartMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.CLIArguments, muicore.MUICore.ManticoreInstance>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "Start"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.CLIArguments.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("Start"))
              .build();
        }
      }
    }
    return getStartMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.AddressRequest,
      muicore.MUICore.TargetResponse> getTargetAddressMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "TargetAddress",
      requestType = muicore.MUICore.AddressRequest.class,
      responseType = muicore.MUICore.TargetResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.AddressRequest,
      muicore.MUICore.TargetResponse> getTargetAddressMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.AddressRequest, muicore.MUICore.TargetResponse> getTargetAddressMethod;
    if ((getTargetAddressMethod = ManticoreUIGrpc.getTargetAddressMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getTargetAddressMethod = ManticoreUIGrpc.getTargetAddressMethod) == null) {
          ManticoreUIGrpc.getTargetAddressMethod = getTargetAddressMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.AddressRequest, muicore.MUICore.TargetResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "TargetAddress"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.AddressRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.TargetResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("TargetAddress"))
              .build();
        }
      }
    }
    return getTargetAddressMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.MUIStateList> getGetStateListMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetStateList",
      requestType = muicore.MUICore.ManticoreInstance.class,
      responseType = muicore.MUICore.MUIStateList.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.MUIStateList> getGetStateListMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance, muicore.MUICore.MUIStateList> getGetStateListMethod;
    if ((getGetStateListMethod = ManticoreUIGrpc.getGetStateListMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getGetStateListMethod = ManticoreUIGrpc.getGetStateListMethod) == null) {
          ManticoreUIGrpc.getGetStateListMethod = getGetStateListMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.ManticoreInstance, muicore.MUICore.MUIStateList>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetStateList"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.MUIStateList.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("GetStateList"))
              .build();
        }
      }
    }
    return getGetStateListMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.MUIMessageList> getGetMessageListMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "GetMessageList",
      requestType = muicore.MUICore.ManticoreInstance.class,
      responseType = muicore.MUICore.MUIMessageList.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.MUIMessageList> getGetMessageListMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance, muicore.MUICore.MUIMessageList> getGetMessageListMethod;
    if ((getGetMessageListMethod = ManticoreUIGrpc.getGetMessageListMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getGetMessageListMethod = ManticoreUIGrpc.getGetMessageListMethod) == null) {
          ManticoreUIGrpc.getGetMessageListMethod = getGetMessageListMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.ManticoreInstance, muicore.MUICore.MUIMessageList>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "GetMessageList"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.MUIMessageList.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("GetMessageList"))
              .build();
        }
      }
    }
    return getGetMessageListMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.ManticoreRunningStatus> getCheckManticoreRunningMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "CheckManticoreRunning",
      requestType = muicore.MUICore.ManticoreInstance.class,
      responseType = muicore.MUICore.ManticoreRunningStatus.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance,
      muicore.MUICore.ManticoreRunningStatus> getCheckManticoreRunningMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.ManticoreInstance, muicore.MUICore.ManticoreRunningStatus> getCheckManticoreRunningMethod;
    if ((getCheckManticoreRunningMethod = ManticoreUIGrpc.getCheckManticoreRunningMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getCheckManticoreRunningMethod = ManticoreUIGrpc.getCheckManticoreRunningMethod) == null) {
          ManticoreUIGrpc.getCheckManticoreRunningMethod = getCheckManticoreRunningMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.ManticoreInstance, muicore.MUICore.ManticoreRunningStatus>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "CheckManticoreRunning"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreRunningStatus.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("CheckManticoreRunning"))
              .build();
        }
      }
    }
    return getCheckManticoreRunningMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static ManticoreUIStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ManticoreUIStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ManticoreUIStub>() {
        @java.lang.Override
        public ManticoreUIStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ManticoreUIStub(channel, callOptions);
        }
      };
    return ManticoreUIStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static ManticoreUIBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ManticoreUIBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ManticoreUIBlockingStub>() {
        @java.lang.Override
        public ManticoreUIBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ManticoreUIBlockingStub(channel, callOptions);
        }
      };
    return ManticoreUIBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static ManticoreUIFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<ManticoreUIFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<ManticoreUIFutureStub>() {
        @java.lang.Override
        public ManticoreUIFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new ManticoreUIFutureStub(channel, callOptions);
        }
      };
    return ManticoreUIFutureStub.newStub(factory, channel);
  }

  /**
   */
  public static abstract class ManticoreUIImplBase implements io.grpc.BindableService {

    /**
     */
    public void terminate(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.TerminateResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getTerminateMethod(), responseObserver);
    }

    /**
     */
    public void start(muicore.MUICore.CLIArguments request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getStartMethod(), responseObserver);
    }

    /**
     */
    public void targetAddress(muicore.MUICore.AddressRequest request,
        io.grpc.stub.StreamObserver<muicore.MUICore.TargetResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getTargetAddressMethod(), responseObserver);
    }

    /**
     */
    public void getStateList(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.MUIStateList> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetStateListMethod(), responseObserver);
    }

    /**
     */
    public void getMessageList(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.MUIMessageList> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getGetMessageListMethod(), responseObserver);
    }

    /**
     */
    public void checkManticoreRunning(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreRunningStatus> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getCheckManticoreRunningMethod(), responseObserver);
    }

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            getTerminateMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.ManticoreInstance,
                muicore.MUICore.TerminateResponse>(
                  this, METHODID_TERMINATE)))
          .addMethod(
            getStartMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.CLIArguments,
                muicore.MUICore.ManticoreInstance>(
                  this, METHODID_START)))
          .addMethod(
            getTargetAddressMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.AddressRequest,
                muicore.MUICore.TargetResponse>(
                  this, METHODID_TARGET_ADDRESS)))
          .addMethod(
            getGetStateListMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.ManticoreInstance,
                muicore.MUICore.MUIStateList>(
                  this, METHODID_GET_STATE_LIST)))
          .addMethod(
            getGetMessageListMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.ManticoreInstance,
                muicore.MUICore.MUIMessageList>(
                  this, METHODID_GET_MESSAGE_LIST)))
          .addMethod(
            getCheckManticoreRunningMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.ManticoreInstance,
                muicore.MUICore.ManticoreRunningStatus>(
                  this, METHODID_CHECK_MANTICORE_RUNNING)))
          .build();
    }
  }

  /**
   */
  public static final class ManticoreUIStub extends io.grpc.stub.AbstractAsyncStub<ManticoreUIStub> {
    private ManticoreUIStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ManticoreUIStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ManticoreUIStub(channel, callOptions);
    }

    /**
     */
    public void terminate(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.TerminateResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getTerminateMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void start(muicore.MUICore.CLIArguments request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getStartMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void targetAddress(muicore.MUICore.AddressRequest request,
        io.grpc.stub.StreamObserver<muicore.MUICore.TargetResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getTargetAddressMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getStateList(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.MUIStateList> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetStateListMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void getMessageList(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.MUIMessageList> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getGetMessageListMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void checkManticoreRunning(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreRunningStatus> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getCheckManticoreRunningMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   */
  public static final class ManticoreUIBlockingStub extends io.grpc.stub.AbstractBlockingStub<ManticoreUIBlockingStub> {
    private ManticoreUIBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ManticoreUIBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ManticoreUIBlockingStub(channel, callOptions);
    }

    /**
     */
    public muicore.MUICore.TerminateResponse terminate(muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getTerminateMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.ManticoreInstance start(muicore.MUICore.CLIArguments request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getStartMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.TargetResponse targetAddress(muicore.MUICore.AddressRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getTargetAddressMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.MUIStateList getStateList(muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetStateListMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.MUIMessageList getMessageList(muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getGetMessageListMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.ManticoreRunningStatus checkManticoreRunning(muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getCheckManticoreRunningMethod(), getCallOptions(), request);
    }
  }

  /**
   */
  public static final class ManticoreUIFutureStub extends io.grpc.stub.AbstractFutureStub<ManticoreUIFutureStub> {
    private ManticoreUIFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ManticoreUIFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new ManticoreUIFutureStub(channel, callOptions);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.TerminateResponse> terminate(
        muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getTerminateMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.ManticoreInstance> start(
        muicore.MUICore.CLIArguments request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getStartMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.TargetResponse> targetAddress(
        muicore.MUICore.AddressRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getTargetAddressMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.MUIStateList> getStateList(
        muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetStateListMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.MUIMessageList> getMessageList(
        muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getGetMessageListMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.ManticoreRunningStatus> checkManticoreRunning(
        muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getCheckManticoreRunningMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_TERMINATE = 0;
  private static final int METHODID_START = 1;
  private static final int METHODID_TARGET_ADDRESS = 2;
  private static final int METHODID_GET_STATE_LIST = 3;
  private static final int METHODID_GET_MESSAGE_LIST = 4;
  private static final int METHODID_CHECK_MANTICORE_RUNNING = 5;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final ManticoreUIImplBase serviceImpl;
    private final int methodId;

    MethodHandlers(ManticoreUIImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_TERMINATE:
          serviceImpl.terminate((muicore.MUICore.ManticoreInstance) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.TerminateResponse>) responseObserver);
          break;
        case METHODID_START:
          serviceImpl.start((muicore.MUICore.CLIArguments) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance>) responseObserver);
          break;
        case METHODID_TARGET_ADDRESS:
          serviceImpl.targetAddress((muicore.MUICore.AddressRequest) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.TargetResponse>) responseObserver);
          break;
        case METHODID_GET_STATE_LIST:
          serviceImpl.getStateList((muicore.MUICore.ManticoreInstance) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.MUIStateList>) responseObserver);
          break;
        case METHODID_GET_MESSAGE_LIST:
          serviceImpl.getMessageList((muicore.MUICore.ManticoreInstance) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.MUIMessageList>) responseObserver);
          break;
        case METHODID_CHECK_MANTICORE_RUNNING:
          serviceImpl.checkManticoreRunning((muicore.MUICore.ManticoreInstance) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreRunningStatus>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  private static abstract class ManticoreUIBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    ManticoreUIBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return muicore.MUICore.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("ManticoreUI");
    }
  }

  private static final class ManticoreUIFileDescriptorSupplier
      extends ManticoreUIBaseDescriptorSupplier {
    ManticoreUIFileDescriptorSupplier() {}
  }

  private static final class ManticoreUIMethodDescriptorSupplier
      extends ManticoreUIBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final String methodName;

    ManticoreUIMethodDescriptorSupplier(String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (ManticoreUIGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new ManticoreUIFileDescriptorSupplier())
              .addMethod(getTerminateMethod())
              .addMethod(getStartMethod())
              .addMethod(getTargetAddressMethod())
              .addMethod(getGetStateListMethod())
              .addMethod(getGetMessageListMethod())
              .addMethod(getCheckManticoreRunningMethod())
              .build();
        }
      }
    }
    return result;
  }
}
