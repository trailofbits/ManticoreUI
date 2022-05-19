from subprocess import Popen
from threading import Thread
from typing import Dict, List, Optional
import json
import time

from binaryninja import BinaryView

import grpc
from muicore.MUICore_pb2_grpc import ManticoreUIStub
from muicore.MUICore_pb2 import (
    ManticoreInstance,
    MUIMessageList,
    MUILogMessage,
    MUIStateList,
    MUIState,
)


class MUIConnection:
    def __init__(self) -> None:
        self.grpc_server_process: Optional[Popen] = None
        self.client_stub: Optional[ManticoreUIStub] = None

    def ensure_server_process(self) -> None:
        if (
            not isinstance(self.grpc_server_process, Popen)
            or self.grpc_server_process.poll() is None
        ):
            self.initialize_server_process()

    def ensure_client_stub(self) -> None:
        if not isinstance(self.client_stub, ManticoreUIStub):
            self.initialize_client_stub()

    def initialize_server_process(self) -> None:
        self.mui_grpc_server_process = Popen("muicore")

    def initialize_client_stub(self) -> None:
        print("Initializing fresh Manticore server client stub")
        self.client_stub = ManticoreUIStub(
            grpc.insecure_channel(
                "localhost:50010",
                options=[
                    (
                        "grpc.service_config",
                        json.dumps(
                            {
                                "methodConfig": [
                                    {
                                        "name": [{"service": "muicore.ManticoreUI"}],
                                        "retryPolicy": {
                                            "maxAttempts": 5,
                                            "initialBackoff": "1s",
                                            "maxBackoff": "10s",
                                            "backoffMultiplier": 2,
                                            "retryableStatusCodes": ["UNAVAILABLE"],
                                        },
                                    }
                                ]
                            }
                        ),
                    )
                ],
            )
        )

    def fetch_messages_and_states(self, mcore_instance: ManticoreInstance) -> None:
        self.ensure_server_process()
        self.ensure_client_stub()

        def fetcher(mcore_instance: ManticoreInstance):
            while True:
                try:
                    status = self.client_stub.CheckManticoreRunning(mcore_instance)
                    if not status.is_running:
                        break

                    message_list: MUIMessageList = self.client_stub.GetMessageList(mcore_instance)
                    state_lists = self.client_stub.GetStateList(mcore_instance)

                    for log_message in message_list.messages:
                        print(log_message.content)

                except grpc.RpcError as e:
                    print(e)
                    break
                time.sleep(3)

        mthread = Thread(target=fetcher, args=(mcore_instance,), daemon=True)
        mthread.name = "mui-binja-" + mcore_instance.uuid
        mthread.start()
