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
  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.NativeArguments,
      muicore.MUICore.ManticoreInstance> getStartNativeMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "StartNative",
      requestType = muicore.MUICore.NativeArguments.class,
      responseType = muicore.MUICore.ManticoreInstance.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.NativeArguments,
      muicore.MUICore.ManticoreInstance> getStartNativeMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.NativeArguments, muicore.MUICore.ManticoreInstance> getStartNativeMethod;
    if ((getStartNativeMethod = ManticoreUIGrpc.getStartNativeMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getStartNativeMethod = ManticoreUIGrpc.getStartNativeMethod) == null) {
          ManticoreUIGrpc.getStartNativeMethod = getStartNativeMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.NativeArguments, muicore.MUICore.ManticoreInstance>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "StartNative"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.NativeArguments.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("StartNative"))
              .build();
        }
      }
    }
    return getStartNativeMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.EVMArguments,
      muicore.MUICore.ManticoreInstance> getStartEVMMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "StartEVM",
      requestType = muicore.MUICore.EVMArguments.class,
      responseType = muicore.MUICore.ManticoreInstance.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.EVMArguments,
      muicore.MUICore.ManticoreInstance> getStartEVMMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.EVMArguments, muicore.MUICore.ManticoreInstance> getStartEVMMethod;
    if ((getStartEVMMethod = ManticoreUIGrpc.getStartEVMMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getStartEVMMethod = ManticoreUIGrpc.getStartEVMMethod) == null) {
          ManticoreUIGrpc.getStartEVMMethod = getStartEVMMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.EVMArguments, muicore.MUICore.ManticoreInstance>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "StartEVM"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.EVMArguments.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ManticoreInstance.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("StartEVM"))
              .build();
        }
      }
    }
    return getStartEVMMethod;
  }

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

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.StopServerRequest,
      muicore.MUICore.StopServerResponse> getStopServerMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "StopServer",
      requestType = muicore.MUICore.StopServerRequest.class,
      responseType = muicore.MUICore.StopServerResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.StopServerRequest,
      muicore.MUICore.StopServerResponse> getStopServerMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.StopServerRequest, muicore.MUICore.StopServerResponse> getStopServerMethod;
    if ((getStopServerMethod = ManticoreUIGrpc.getStopServerMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getStopServerMethod = ManticoreUIGrpc.getStopServerMethod) == null) {
          ManticoreUIGrpc.getStopServerMethod = getStopServerMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.StopServerRequest, muicore.MUICore.StopServerResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "StopServer"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.StopServerRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.StopServerResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("StopServer"))
              .build();
        }
      }
    }
    return getStopServerMethod;
  }

  private static volatile io.grpc.MethodDescriptor<muicore.MUICore.ControlStateRequest,
      muicore.MUICore.ControlStateResponse> getControlStateMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ControlState",
      requestType = muicore.MUICore.ControlStateRequest.class,
      responseType = muicore.MUICore.ControlStateResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<muicore.MUICore.ControlStateRequest,
      muicore.MUICore.ControlStateResponse> getControlStateMethod() {
    io.grpc.MethodDescriptor<muicore.MUICore.ControlStateRequest, muicore.MUICore.ControlStateResponse> getControlStateMethod;
    if ((getControlStateMethod = ManticoreUIGrpc.getControlStateMethod) == null) {
      synchronized (ManticoreUIGrpc.class) {
        if ((getControlStateMethod = ManticoreUIGrpc.getControlStateMethod) == null) {
          ManticoreUIGrpc.getControlStateMethod = getControlStateMethod =
              io.grpc.MethodDescriptor.<muicore.MUICore.ControlStateRequest, muicore.MUICore.ControlStateResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ControlState"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ControlStateRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  muicore.MUICore.ControlStateResponse.getDefaultInstance()))
              .setSchemaDescriptor(new ManticoreUIMethodDescriptorSupplier("ControlState"))
              .build();
        }
      }
    }
    return getControlStateMethod;
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
    public void startNative(muicore.MUICore.NativeArguments request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getStartNativeMethod(), responseObserver);
    }

    /**
     */
    public void startEVM(muicore.MUICore.EVMArguments request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getStartEVMMethod(), responseObserver);
    }

    /**
     */
    public void terminate(muicore.MUICore.ManticoreInstance request,
        io.grpc.stub.StreamObserver<muicore.MUICore.TerminateResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getTerminateMethod(), responseObserver);
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

    /**
     */
    public void stopServer(muicore.MUICore.StopServerRequest request,
        io.grpc.stub.StreamObserver<muicore.MUICore.StopServerResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getStopServerMethod(), responseObserver);
    }

    /**
     */
    public void controlState(muicore.MUICore.ControlStateRequest request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ControlStateResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getControlStateMethod(), responseObserver);
    }

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            getStartNativeMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.NativeArguments,
                muicore.MUICore.ManticoreInstance>(
                  this, METHODID_START_NATIVE)))
          .addMethod(
            getStartEVMMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.EVMArguments,
                muicore.MUICore.ManticoreInstance>(
                  this, METHODID_START_EVM)))
          .addMethod(
            getTerminateMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.ManticoreInstance,
                muicore.MUICore.TerminateResponse>(
                  this, METHODID_TERMINATE)))
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
          .addMethod(
            getStopServerMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.StopServerRequest,
                muicore.MUICore.StopServerResponse>(
                  this, METHODID_STOP_SERVER)))
          .addMethod(
            getControlStateMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                muicore.MUICore.ControlStateRequest,
                muicore.MUICore.ControlStateResponse>(
                  this, METHODID_CONTROL_STATE)))
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
    public void startNative(muicore.MUICore.NativeArguments request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getStartNativeMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void startEVM(muicore.MUICore.EVMArguments request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getStartEVMMethod(), getCallOptions()), request, responseObserver);
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

    /**
     */
    public void stopServer(muicore.MUICore.StopServerRequest request,
        io.grpc.stub.StreamObserver<muicore.MUICore.StopServerResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getStopServerMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void controlState(muicore.MUICore.ControlStateRequest request,
        io.grpc.stub.StreamObserver<muicore.MUICore.ControlStateResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getControlStateMethod(), getCallOptions()), request, responseObserver);
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
    public muicore.MUICore.ManticoreInstance startNative(muicore.MUICore.NativeArguments request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getStartNativeMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.ManticoreInstance startEVM(muicore.MUICore.EVMArguments request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getStartEVMMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.TerminateResponse terminate(muicore.MUICore.ManticoreInstance request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getTerminateMethod(), getCallOptions(), request);
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

    /**
     */
    public muicore.MUICore.StopServerResponse stopServer(muicore.MUICore.StopServerRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getStopServerMethod(), getCallOptions(), request);
    }

    /**
     */
    public muicore.MUICore.ControlStateResponse controlState(muicore.MUICore.ControlStateRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getControlStateMethod(), getCallOptions(), request);
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
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.ManticoreInstance> startNative(
        muicore.MUICore.NativeArguments request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getStartNativeMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.ManticoreInstance> startEVM(
        muicore.MUICore.EVMArguments request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getStartEVMMethod(), getCallOptions()), request);
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

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.StopServerResponse> stopServer(
        muicore.MUICore.StopServerRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getStopServerMethod(), getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<muicore.MUICore.ControlStateResponse> controlState(
        muicore.MUICore.ControlStateRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getControlStateMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_START_NATIVE = 0;
  private static final int METHODID_START_EVM = 1;
  private static final int METHODID_TERMINATE = 2;
  private static final int METHODID_GET_STATE_LIST = 3;
  private static final int METHODID_GET_MESSAGE_LIST = 4;
  private static final int METHODID_CHECK_MANTICORE_RUNNING = 5;
  private static final int METHODID_STOP_SERVER = 6;
  private static final int METHODID_CONTROL_STATE = 7;

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
        case METHODID_START_NATIVE:
          serviceImpl.startNative((muicore.MUICore.NativeArguments) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance>) responseObserver);
          break;
        case METHODID_START_EVM:
          serviceImpl.startEVM((muicore.MUICore.EVMArguments) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.ManticoreInstance>) responseObserver);
          break;
        case METHODID_TERMINATE:
          serviceImpl.terminate((muicore.MUICore.ManticoreInstance) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.TerminateResponse>) responseObserver);
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
        case METHODID_STOP_SERVER:
          serviceImpl.stopServer((muicore.MUICore.StopServerRequest) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.StopServerResponse>) responseObserver);
          break;
        case METHODID_CONTROL_STATE:
          serviceImpl.controlState((muicore.MUICore.ControlStateRequest) request,
              (io.grpc.stub.StreamObserver<muicore.MUICore.ControlStateResponse>) responseObserver);
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
              .addMethod(getStartNativeMethod())
              .addMethod(getStartEVMMethod())
              .addMethod(getTerminateMethod())
              .addMethod(getGetStateListMethod())
              .addMethod(getGetMessageListMethod())
              .addMethod(getCheckManticoreRunningMethod())
              .addMethod(getStopServerMethod())
              .addMethod(getControlStateMethod())
              .build();
        }
      }
    }
    return result;
  }
}
