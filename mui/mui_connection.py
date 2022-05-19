from subprocess import Popen
from threading import Thread
from typing import Dict, List, Optional
import json
import time

from binaryninja import BinaryView

from mui.dockwidgets import widget
from mui.dockwidgets.state_list_widget import StateListWidget

import grpc
from muicore.MUICore_pb2_grpc import ManticoreUIStub
from muicore.MUICore_pb2 import (
    ManticoreInstance,
    MUIMessageList,
    MUIStateList,
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
            self.initialise_server_process()

    def ensure_client_stub(self) -> None:
        if not isinstance(self.client_stub, ManticoreUIStub):
            self.initialise_client_stub()

    def initialise_server_process(self) -> None:
        self.grpc_server_process = Popen("muicore")

    def initialise_client_stub(self) -> None:
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

    def fetch_messages_and_states(
        self, mcore_instance: ManticoreInstance, state_widget: StateListWidget
    ) -> None:
        def fetcher(mcore_instance: ManticoreInstance):

            while True:
                try:
                    self.ensure_server_process()
                    self.ensure_client_stub()

                    assert isinstance(self.client_stub, ManticoreUIStub)

                    message_list: MUIMessageList = self.client_stub.GetMessageList(mcore_instance)
                    state_lists: MUIStateList = self.client_stub.GetStateList(mcore_instance)

                    state_widget.refresh_state_list(
                        state_lists.active_states,
                        state_lists.waiting_states,
                        state_lists.forked_states,
                        state_lists.errored_states,
                        state_lists.complete_states,
                    )
                    for log_message in message_list.messages:
                        print(log_message.content)

                    status = self.client_stub.CheckManticoreRunning(mcore_instance)
                    if not status.is_running:
                        break

                except grpc.RpcError as e:
                    print(e)
                    break

                time.sleep(1)

        mthread = Thread(target=fetcher, args=(mcore_instance,), daemon=True)
        mthread.name = "mui-binja-" + mcore_instance.uuid
        mthread.start()
