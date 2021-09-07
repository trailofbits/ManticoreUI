import json
import os
import random
import string
import tempfile
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog
from binaryninja import (
    PluginCommand,
    BinaryView,
    HighlightStandardColor,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    Settings,
    get_open_filename_input,
    Architecture,
    SettingsScope,
)
from binaryninjaui import DockHandler, UIContext
from crytic_compile import CryticCompile

from mui.constants import (
    BINJA_HOOK_SETTINGS_PREFIX,
    BINJA_SETTINGS_GROUP,
    BINJA_RUN_SETTINGS_PREFIX,
    BINJA_EVM_RUN_SETTINGS_PREFIX,
)
from mui.dockwidgets import widget
from mui.dockwidgets.code_dialog import CodeDialog
from mui.dockwidgets.evm_run_dialog import EVMRunDialog
from mui.dockwidgets.native_run_dialog import NativeRunDialog
from mui.dockwidgets.state_graph_widget import StateGraphWidget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.manticore_evm_runner import ManticoreEVMRunner
from mui.manticore_native_runnner import ManticoreNativeRunner
from mui.notification import UINotification
from mui.utils import highlight_instr, clear_highlight

settings = Settings()

BinaryView.set_default_session_data("mui_find", set())
BinaryView.set_default_session_data("mui_avoid", set())
BinaryView.set_default_session_data("mui_custom_hooks", dict())
BinaryView.set_default_session_data("mui_is_running", False)
BinaryView.set_default_session_data("mui_state", None)
BinaryView.set_default_session_data("mui_evm_source", None)


def find_instr(bv: BinaryView, addr: int):
    """This command handler adds a given address to the find list and highlights it green in the UI"""

    # Highlight the instruction in green
    highlight_instr(bv, addr, HighlightStandardColor.GreenHighlightColor)

    # Add the instruction to the list associated with the current view
    bv.session_data.mui_find.add(addr)


def rm_find_instr(bv: BinaryView, addr: int):
    """This command handler removes a given address from the find list and undoes the highlights"""

    # Remove instruction highlight
    clear_highlight(bv, addr)

    # Remove the instruction to the list associated with the current view
    bv.session_data.mui_find.remove(addr)


def avoid_instr(bv: BinaryView, addr: int):
    """This command handler adds a given address to the avoid list and highlights it red in the UI"""

    # Highlight the instruction in red
    highlight_instr(bv, addr, HighlightStandardColor.RedHighlightColor)

    # Add the instruction to the list associated with the current view
    bv.session_data.mui_avoid.add(addr)


def rm_avoid_instr(bv: BinaryView, addr: int):
    """This command handler removes a given address from the avoid list and undoes the highlights"""

    # Remove instruction highlight
    clear_highlight(bv, addr)

    # Remove the instruction to the list associated with the current view
    bv.session_data.mui_avoid.remove(addr)


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

        dialog = EVMRunDialog(DockHandler.getActiveDockHandler().parent(), bv)

        if dialog.exec() == QDialog.Accepted:
            bv.session_data.mui_is_running = True
            s = ManticoreEVMRunner(bv.session_data.mui_evm_source, bv)
            s.start()

    else:
        if len(bv.session_data.mui_find) == 0 and len(bv.session_data.mui_custom_hooks.keys()) == 0:
            show_message_box(
                "Manticore Solve",
                "You have not specified a goal instruction or custom hook.\n\n"
                + 'Please right click on the goal instruction and select "Find Path to This Instruction" to '
                + "continue.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon,
            )
            return

        dialog = NativeRunDialog(DockHandler.getActiveDockHandler().parent(), bv)

        if dialog.exec() == QDialog.Accepted:
            # Start a solver thread for the path associated with the view
            bv.session_data.mui_is_running = True
            s = ManticoreNativeRunner(bv.session_data.mui_find, bv.session_data.mui_avoid, bv)
            s.start()


def edit_custom_hook(bv: BinaryView, addr: int):
    dialog = CodeDialog(DockHandler.getActiveDockHandler().parent(), bv)

    if addr in bv.session_data.mui_custom_hooks:
        dialog.set_text(bv.session_data.mui_custom_hooks[addr])

    result: QDialog.DialogCode = dialog.exec()

    if result == QDialog.Accepted:

        if len(dialog.text()) == 0:
            # delete the hook if empty input is provided
            if addr in bv.session_data.mui_custom_hooks:
                clear_highlight(bv, addr)
                del bv.session_data.mui_custom_hooks[addr]

        else:
            # add/edit the hook if input is non-empty
            highlight_instr(bv, addr, HighlightStandardColor.BlueHighlightColor)
            bv.session_data.mui_custom_hooks[addr] = dialog.text()


def load_evm(bv: BinaryView):
    filename = get_open_filename_input("filename:", "*.sol").decode()
    if filename is None:
        return

    print(filename)
    filename = Path(filename)

    os.chdir(filename.parent.resolve())
    output = CryticCompile(filename.name)

    for compilation_unit in output.compilation_units.values():
        for name in compilation_unit.contracts_names:
            print(f"Contract {compilation_unit}")
            print(compilation_unit.bytecode_init(name))
            print(compilation_unit.bytecode_runtime(name))
            srcmap_runtime = compilation_unit.srcmap_runtime(name)
            print(srcmap_runtime)
            with tempfile.NamedTemporaryFile("w+b", suffix=".evm") as temp:
                temp.write(bytes.fromhex(compilation_unit.bytecode_runtime(name)))
                temp.flush()

                # b = BinaryViewType['EVM'].open(temp.name)
                ctx = UIContext.activeContext()
                ctx.openFilename(temp.name)
                bv = ctx.getCurrentViewFrame().getCurrentBinaryView()

                print(bv)
                bv.session_data["mui_evm_source"] = filename

    print(output)


def stop_manticore(bv: BinaryView):
    """Stops the current running manticore instance"""
    bv.session_data.mui_is_running = False


def avoid_instr_is_valid(bv: BinaryView, addr: int):
    """checks if avoid_instr is valid for a given address"""
    return addr not in bv.session_data.mui_avoid


def find_instr_is_valid(bv: BinaryView, addr: int):
    """checks if find_instr is valid for a given address"""
    return addr not in bv.session_data.mui_find


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

PluginCommand.register(
    "MUI \\ Load Ethereum Contract", "Load a solidity ethereum contract", load_evm
)

widget.register_dockwidget(
    StateListWidget, StateListWidget.NAME, Qt.RightDockWidgetArea, Qt.Vertical, True
)

widget.register_dockwidget(
    StateGraphWidget, StateGraphWidget.NAME, Qt.TopDockWidgetArea, Qt.Vertical, True
)


if not settings.contains(f"{BINJA_RUN_SETTINGS_PREFIX}argv"):
    settings.register_group(BINJA_SETTINGS_GROUP, "MUI Settings")
    settings.register_setting(
        f"{BINJA_RUN_SETTINGS_PREFIX}argv",
        json.dumps(
            {
                "title": "Argument variables",
                "description": "Argv to use for manticore",
                "type": "array",
                "elementType": "string",
                "default": [],
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_RUN_SETTINGS_PREFIX}workspaceURL",
        json.dumps(
            {
                "title": "Workspace URL",
                "description": "Workspace URL to use for manticore",
                "type": "string",
                "default": "mem:",
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_RUN_SETTINGS_PREFIX}stdinSize",
        json.dumps(
            {
                "title": "Stdin Size",
                "description": "Stdin size to use for manticore",
                "type": "number",
                "default": 256,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_RUN_SETTINGS_PREFIX}concreteStart",
        json.dumps(
            {
                "title": "Concrete Start",
                "description": "Initial concrete data for the input symbolic buffer",
                "type": "string",
                "default": "",
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_RUN_SETTINGS_PREFIX}env",
        json.dumps(
            {
                "title": "Environment Variables",
                "description": "Environment variables for manticore",
                "type": "array",
                "elementType": "string",
                "default": [],
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_RUN_SETTINGS_PREFIX}symbolicFiles",
        json.dumps(
            {
                "title": "Symbolic Files",
                "description": "Symbolic files for manticore",
                "type": "array",
                "elementType": "string",
                "default": [],
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_HOOK_SETTINGS_PREFIX}avoid",
        json.dumps(
            {
                "title": "Avoid Hooks",
                "description": "Addresses to attach avoid hooks",
                "type": "string",
                "default": json.dumps([]),
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_HOOK_SETTINGS_PREFIX}find",
        json.dumps(
            {
                "title": "Find Hooks",
                "description": "Addresses to attach find hooks",
                "type": "string",
                "default": json.dumps([]),
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_HOOK_SETTINGS_PREFIX}custom",
        json.dumps(
            {
                "title": "Custom Hooks",
                "description": "Addresses and python code for custom hooks",
                "type": "string",
                "default": json.dumps({}),
            }
        ),
    )

    # EVM run settings
    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}workspace_url",
        json.dumps(
            {
                "title": "workspace_url",
                "description": "Location for the manticore workspace",
                "type": "string",
                "default": "",
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}contract_name",
        json.dumps(
            {
                "title": "contract_name",
                "description": "The target contract name defined in the source code",
                "type": "string",
                "default": "",
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txlimit",
        json.dumps(
            {
                "title": "txlimit",
                "description": "Maximum number of symbolic transactions to run (negative integer means no limit)",
                "type": "number",
                "default": -1,
                "minValue": -2147483648,
                "maxValue": 2147483647,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}thorough_mode",
        json.dumps(
            {
                "title": "thorough_mode",
                "description": "Configure Manticore for more exhaustive exploration. Evaluate gas, generate testcases for dead states, explore constant functions, and run a small suite of detectors.",
                "type": "boolean",
                "default": True,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}exclude_all",
        json.dumps(
            {
                "title": "exclude_all",
                "description": "Excludes all detectors",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}detectors_to_exclude",
        json.dumps(
            {
                "title": "detectors_to_exclude",
                "description": "List of detectors that should be excluded",
                "type": "array",
                "elementType": "string",
                "default": [],
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txnocoverage",
        json.dumps(
            {
                "title": "txnocoverage",
                "description": "Do not use coverage as stopping criteria",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txnoether",
        json.dumps(
            {
                "title": "txnoether",
                "description": "Do not attempt to send ether to contract",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txaccount",
        json.dumps(
            {
                "title": "txaccount",
                "description": 'Account used as caller in the symbolic transactions, either "attacker" or "owner" or "combo1" (uses both)',
                "type": "string",
                "default": "attacker",
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txpreconstrain",
        json.dumps(
            {
                "title": "txpreconstrain",
                "description": "Constrain human transactions to avoid exceptions in the contract function dispatcher",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}no_testcases",
        json.dumps(
            {
                "title": "no_testcases",
                "description": "Do not generate testcases for discovered states when analysis finishes",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}only_alive_testcases",
        json.dumps(
            {
                "title": "only_alive_testcases",
                "description": "Do not generate testcases for invalid/throwing states when analysis finishes",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}skip_reverts",
        json.dumps(
            {
                "title": "skip_reverts",
                "description": "Skip REVERTs",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}explore_balance",
        json.dumps(
            {
                "title": "explore_balance",
                "description": "Discard all transactions that results in states where the underlying EVM storage did not change",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}verbose_trace",
        json.dumps(
            {
                "title": "verbose_trace",
                "description": "Dump an extra verbose trace for each state",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}limit_loops",
        json.dumps(
            {
                "title": "limit_loops",
                "description": "Limit loops depth",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}profile",
        json.dumps(
            {
                "title": "profile",
                "description": "Use profiler",
                "type": "boolean",
                "default": False,
            }
        ),
    )

    settings.register_setting(
        f"{BINJA_EVM_RUN_SETTINGS_PREFIX}avoid_constant",
        json.dumps(
            {
                "title": "avoid_constant",
                "description": "Avoid exploring constant functions for human transactions",
                "type": "boolean",
                "default": False,
            }
        ),
    )

# Register as a global so it doesn't get destructed
notif = UINotification()
