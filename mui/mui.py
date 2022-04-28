import os
import random
import string
import tempfile
import subprocess
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog
from binaryninja import (
    PluginCommand,
    BinaryView,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    Settings,
    get_open_filename_input,
    Architecture,
    SettingsScope,
    BinaryViewType,
    core_ui_enabled,
)
from binaryninjaui import DockHandler, UIContext
from crytic_compile import CryticCompile

from mui.constants import (
    BINJA_EVM_RUN_SETTINGS_PREFIX,
    BINJA_NATIVE_RUN_SETTINGS_PREFIX,
)
from mui.dockwidgets import widget
from mui.dockwidgets.code_dialog import CodeDialog
from mui.dockwidgets.library_dialog import LibraryDialog
from mui.dockwidgets.run_dialog import RunDialog
from mui.dockwidgets.function_model_dialog import FunctionModelDialog
from mui.dockwidgets.global_hook_dialog import GlobalHookDialog
from mui.dockwidgets.state_graph_widget import StateGraphWidget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.dockwidgets.hook_list_widget import HookListWidget
from mui.hook_manager import NativeHookManager
from mui.notification import UINotification
from mui.settings import MUISettings
from mui.utils import (
    highlight_instr,
    clear_highlight,
    function_model_analysis_cb,
    create_client_stub,
)

from mui.server_utils.MUICore_pb2_grpc import ManticoreUIStub
from mui.server_utils.MUICore_pb2 import NativeArguments, EVMArguments, ManticoreInstance

settings = Settings()

BinaryView.set_default_session_data("mui_hook_mgr", None)
BinaryView.set_default_session_data("mui_find", set())
BinaryView.set_default_session_data("mui_avoid", set())
BinaryView.set_default_session_data("mui_custom_hooks", dict())
BinaryView.set_default_session_data("mui_global_hooks", dict())
BinaryView.set_default_session_data("mui_is_running", False)
BinaryView.set_default_session_data("mui_state", None)
BinaryView.set_default_session_data("mui_evm_source", None)
BinaryView.set_default_session_data("mui_addr_offset", None)
BinaryView.set_default_session_data("server_manticore_instances", set())
BinaryView.set_default_session_data("mui_libs", set())


def find_instr(bv: BinaryView, addr: int):
    """This command handler adds a given address to the find list and highlights it green in the UI"""
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr
    mgr.add_find_hook(addr)


def rm_find_instr(bv: BinaryView, addr: int):
    """This command handler removes a given address from the find list and undoes the highlights"""
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr
    mgr.del_find_hook(addr)


def avoid_instr(bv: BinaryView, addr: int):
    """This command handler adds a given address to the avoid list and highlights it red in the UI"""
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr
    mgr.add_avoid_hook(addr)


def rm_avoid_instr(bv: BinaryView, addr: int):
    """This command handler removes a given address from the avoid list and undoes the highlights"""
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr
    mgr.del_avoid_hook(addr)


def solve(bv: BinaryView):
    """This command handler starts manticore in a background thread"""

    if (
        "EVM" in [x.name for x in list(Architecture)]
        and bv.arch == Architecture["EVM"]
        and bv.session_data.mui_evm_source is not None
    ):
        # set default workspace url

        workspace_url = settings.get_string(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}workspace_url", bv)
        if workspace_url == "":

            random_dir_name = "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
            workspace_url = str(
                Path(
                    bv.session_data.mui_evm_source.parent.resolve(),
                    random_dir_name,
                )
            )
            settings.set_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}workspace_url",
                workspace_url,
                view=bv,
                scope=SettingsScope.SettingsResourceScope,
            )

        dialog = RunDialog(
            DockHandler.getActiveDockHandler().parent(), bv, BINJA_EVM_RUN_SETTINGS_PREFIX
        )

        if dialog.exec() == QDialog.Accepted:
            if notif.mui_grpc_server_process == None:
                notif.mui_grpc_server_process = subprocess.Popen(
                    [Path(__file__).resolve().parent.parent / "muicore_server"]
                )
            if not isinstance(notif.mui_client_stub, ManticoreUIStub):
                notif.mui_client_stub = create_client_stub()
            mcore_instance = notif.mui_client_stub.StartEVM(
                EVMArguments(contract_path=bv.file.original_filename)
            )
            bv.session_data.server_manticore_instances.add(mcore_instance.uuid)
            print("Manticore instance created on the server with uuid=" + mcore_instance.uuid)
            bv.session_data.mui_is_running = True

    else:
        dialog = RunDialog(
            DockHandler.getActiveDockHandler().parent(), bv, BINJA_NATIVE_RUN_SETTINGS_PREFIX
        )

        if dialog.exec() == QDialog.Accepted:
            if notif.mui_grpc_server_process == None:
                notif.mui_grpc_server_process = subprocess.Popen(
                    [Path(__file__).resolve().parent.parent / "muicore_server"]
                )
            if not isinstance(notif.mui_client_stub, ManticoreUIStub):
                notif.mui_client_stub = create_client_stub()
            mcore_instance = notif.mui_client_stub.StartNative(
                NativeArguments(program_path=bv.file.original_filename)
            )
            bv.session_data.server_manticore_instances.add(mcore_instance.uuid)
            print("Manticore instance created on the server with uuid=" + mcore_instance.uuid)
            bv.session_data.mui_is_running = True


def edit_custom_hook(bv: BinaryView, addr: int):
    dialog = CodeDialog(DockHandler.getActiveDockHandler().parent(), bv)
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr

    if mgr.has_custom_hook(addr):
        dialog.set_text(mgr.get_custom_hook(addr))

    result: QDialog.DialogCode = dialog.exec()

    if result == QDialog.Accepted:
        code = dialog.text()
        if not code:
            # delete the hook if empty input is provided
            if mgr.has_custom_hook(addr):
                mgr.del_custom_hook(addr)
        else:
            mgr.add_custom_hook(addr, code)


def edit_global_hook(bv: BinaryView):
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr
    dialog = GlobalHookDialog(DockHandler.getActiveDockHandler().parent(), bv, mgr)
    dialog.exec()


def add_function_model(bv: BinaryView, addr: int) -> None:
    mgr: NativeHookManager = bv.session_data.mui_hook_mgr
    dialog = FunctionModelDialog(DockHandler.getActiveDockHandler().parent(), bv)
    result: QDialog.DialogCode = dialog.exec()

    if result == QDialog.Accepted:
        fname = dialog.get_selected_model()
        if not fname:
            return

        code = "\n".join(
            [
                f"from manticore.native.models import {fname}",
                "global bv,m,addr",
                "def hook(state):",
                f"    print('{fname} function model')",
                f"    state.invoke_model({fname})",
                "m.hook(addr)(hook)",
            ]
        )
        mgr.add_custom_hook(addr, code)


def manage_shared_libs(bv) -> None:
    dialog = LibraryDialog(DockHandler.getActiveDockHandler().parent(), bv)
    dialog.exec()


def load_evm(bv: BinaryView):
    filename = get_open_filename_input("filename:", "*.sol").decode()
    if filename is None:
        return

    filename = Path(filename)

    # workaround to prevent CryticCompile errors
    os.chdir(filename.parent.resolve())

    output = CryticCompile(
        filename.name,
        solc_solcs_bin=settings.get_string(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}solc_path", bv),
    )

    for compilation_unit in output.compilation_units.values():
        for name in compilation_unit.contracts_names:
            print(f"Contract {compilation_unit}")
            print(compilation_unit.bytecode_init(name))
            print(compilation_unit.bytecode_runtime(name))
            srcmap_runtime = compilation_unit.srcmap_runtime(name)

            with tempfile.NamedTemporaryFile("w+b", suffix=".evm") as temp:
                temp.write(bytes.fromhex(compilation_unit.bytecode_runtime(name)))
                temp.flush()

                # b = BinaryViewType['EVM'].open(temp.name)
                ctx = UIContext.activeContext()
                ctx.openFilename(temp.name)
                bv = ctx.getCurrentViewFrame().getCurrentBinaryView()

                bv.session_data["mui_evm_source"] = filename


def stop_manticore(bv: BinaryView):
    """Stops the current running manticore instance"""
    if not isinstance(notif.mui_client_stub, ManticoreUIStub):
        notif.mui_client_stub = create_client_stub()
    res = notif.mui_client_stub.Terminate(
        ManticoreInstance(uuid=bv.session_data.server_manticore_instances.pop())
    )
    if res.success:
        print("Manticore stopped by user.")
    else:
        print("Manticore failed to terminate.")
    bv.session_data.mui_is_running = False


def avoid_instr_is_valid(bv: BinaryView, addr: int):
    """checks if avoid_instr is valid for a given address"""
    if bv.session_data.mui_hook_mgr:
        return not bv.session_data.mui_hook_mgr.has_avoid_hook(addr)
    else:
        return True


def find_instr_is_valid(bv: BinaryView, addr: int):
    """checks if find_instr is valid for a given address"""
    if bv.session_data.mui_hook_mgr:
        return not bv.session_data.mui_hook_mgr.has_find_hook(addr)
    else:
        return True


def solve_is_valid(bv: BinaryView):
    """checks if solve is valid for a given binary view"""
    return not bv.session_data.mui_is_running


PluginCommand.register_for_address(
    "MUI \\ Find Path to This Instruction",
    "When solving, find a path that gets to this instruction",
    find_instr,
    find_instr_is_valid,
)
PluginCommand.register_for_address(
    "MUI \\ Remove Instruction from Find List",
    "When solving, DO NOT find paths that reach this instruction",
    rm_find_instr,
    lambda bv, addr: not find_instr_is_valid(bv, addr),
)
PluginCommand.register_for_address(
    "MUI \\ Avoid This Instruction",
    "When solving, avoid paths that reach this instruction",
    avoid_instr,
    avoid_instr_is_valid,
)
PluginCommand.register_for_address(
    "MUI \\ Remove Instruction from Avoid List",
    "When solving, DO NOT avoid paths that reach this instruction",
    rm_avoid_instr,
    lambda bv, addr: not avoid_instr_is_valid(bv, addr),
)
PluginCommand.register(
    "MUI \\ Solve With Manticore",
    "Attempt to solve for a path that satisfies the constraints given",
    solve,
    solve_is_valid,
)
PluginCommand.register(
    "MUI \\ Stop Manticore",
    "Stop the running manticore instance",
    stop_manticore,
    lambda bv: not solve_is_valid(bv),
)
PluginCommand.register_for_address(
    "MUI \\ Add/Edit Custom Hook", "Add/edit a custom hook at the current address", edit_custom_hook
)
PluginCommand.register_for_address(
    "MUI \\ Add Function Model",
    "Add a function model to replace native function implementation",
    add_function_model,
)
PluginCommand.register(
    "MUI \\ Load Ethereum Contract", "Load a solidity ethereum contract", load_evm
)

PluginCommand.register(
    "MUI \\ Add/Edit Global Hook",
    "Add/edit a custom hook that applies to all instructions",
    edit_global_hook,
)
PluginCommand.register(
    "MUI \\ Manage Shared Library BNDBs",
    "Manage shared library bndbs to extract hooks from",
    manage_shared_libs,
)

if core_ui_enabled():
    widget.register_dockwidget(
        StateListWidget, StateListWidget.NAME, Qt.RightDockWidgetArea, Qt.Vertical, True
    )

    widget.register_dockwidget(
        HookListWidget, HookListWidget.NAME, Qt.RightDockWidgetArea, Qt.Vertical, True
    )

    widget.register_dockwidget(
        StateGraphWidget, StateGraphWidget.NAME, Qt.TopDockWidgetArea, Qt.Vertical, True
    )

# Register MUI settings
MUISettings.register()

# Register notification as a global so it doesn't get destructed
notif = UINotification()

# Register analysis completion callback
BinaryViewType.add_binaryview_initial_analysis_completion_event(function_model_analysis_cb)
