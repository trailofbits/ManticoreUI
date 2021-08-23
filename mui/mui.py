import json
import tempfile
from time import sleep
from typing import Set, Callable, Dict

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog
from binaryninja import (
    PluginCommand,
    BinaryView,
    BackgroundTaskThread,
    HighlightStandardColor,
    HighlightColor,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    Settings,
)
from binaryninjaui import DockHandler
from manticore.core.plugin import StateDescriptor
from manticore.core.state import StateBase
from manticore.native import Manticore

from mui.constants import (
    BINJA_HOOK_SETTINGS_PREFIX,
    BINJA_SETTINGS_GROUP,
    BINJA_RUN_SETTINGS_PREFIX,
)
from mui.dockwidgets import widget
from mui.dockwidgets.code_dialog import CodeDialog
from mui.dockwidgets.run_dialog import RunDialog
from mui.dockwidgets.state_graph_widget import StateGraphWidget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.introspect_plugin import MUIIntrospectionPlugin
from mui.notification import UINotification
from mui.utils import MUIState, highlight_instr, clear_highlight

BinaryView.set_default_session_data("mui_find", set())
BinaryView.set_default_session_data("mui_avoid", set())
BinaryView.set_default_session_data("mui_custom_hooks", dict())
BinaryView.set_default_session_data("mui_is_running", False)
BinaryView.set_default_session_data("mui_state", None)


class ManticoreRunner(BackgroundTaskThread):
    def __init__(self, find: Set[int], avoid: Set[int], view: BinaryView):
        BackgroundTaskThread.__init__(self, "Solving with Manticore...", True)
        self.find = tuple(find)
        self.avoid = tuple(avoid)
        self.view = view

        # Write the binary to disk so that the Manticore API can read it
        self.binary = tempfile.NamedTemporaryFile()
        self.binary.write(view.file.raw.read(0, len(view.file.raw)))
        self.binary.flush()

    def run(self):
        """Initializes manticore, adds the necessary hooks, and runs it"""

        try:
            bv = self.view

            # set up state and clear UI
            state_widget: StateListWidget = widget.get_dockwidget(self.view, StateListWidget.NAME)

            if bv.session_data.mui_state is None:
                bv.session_data.mui_state = MUIState(bv)
                state_widget.listen_to(bv.session_data.mui_state)

            bv.session_data.mui_state.notify_states_changed({})

            settings = Settings()

            m = Manticore.linux(
                self.binary.name,
                workspace_url=settings.get_string(f"{BINJA_RUN_SETTINGS_PREFIX}workspaceURL", bv),
                argv=settings.get_string_list(f"{BINJA_RUN_SETTINGS_PREFIX}argv", bv).copy(),
                stdin_size=settings.get_integer(f"{BINJA_RUN_SETTINGS_PREFIX}stdinSize", bv),
                concrete_start=settings.get_string(f"{BINJA_RUN_SETTINGS_PREFIX}concreteStart", bv),
                envp={
                    key: val
                    for key, val in [
                        env.split("=")
                        for env in settings.get_string_list(f"{BINJA_RUN_SETTINGS_PREFIX}env", bv)
                    ]
                },
                introspection_plugin_type=MUIIntrospectionPlugin,
            )

            @m.init
            def init(state):
                for file in settings.get_string_list(
                    f"{BINJA_RUN_SETTINGS_PREFIX}symbolicFiles", bv
                ):
                    state.platform.add_symbolic_file(file)

            def avoid_f(state: StateBase):
                state.abandon()

            for addr in self.avoid:
                m.hook(addr)(avoid_f)

            def find_f(state: StateBase):
                bufs = state.solve_one_n_batched(state.input_symbols)
                for symbol, buf in zip(state.input_symbols, bufs):
                    print(f"{symbol.name}: {buf!r}\n")

                with m.locked_context() as context:
                    m.kill()
                state.abandon()

            for addr in self.find:
                m.hook(addr)(find_f)

            for addr, func in bv.session_data.mui_custom_hooks.items():
                exec(func, {"addr": addr, "bv": bv, "m": m})

            def run_every(callee: Callable, duration: int = 3) -> Callable:
                """
                Returns a function that calls <callee> every <duration> seconds
                """

                def inner(
                    thread,
                ):  # Takes `thread` as argument, which is provided by the daemon thread API
                    while thread.manticore.is_running():
                        # Pass Manticore's state descriptor dict to the callee
                        callee(thread.manticore.introspect())
                        sleep(duration)

                return inner

            m.register_daemon(run_every(bv.session_data.mui_state.notify_states_changed, 1))

            def check_termination(_):
                """Check if the user wants to termninate manticore"""
                if bv.session_data.mui_is_running == False:
                    print("Manticore terminated by user!")
                    with m.locked_context() as context:
                        m.kill()

            m.register_daemon(run_every(check_termination, 1))

            m.run()
            bv.session_data.mui_state.notify_states_changed(m.introspect())
            print("Manticore finished")
        finally:
            bv.session_data.mui_is_running = False


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

    dialog = RunDialog(DockHandler.getActiveDockHandler().parent(), bv)
    result: QDialog.DialogCode = dialog.exec()

    if result == QDialog.Accepted:
        # Start a solver thread for the path associated with the view
        bv.session_data.mui_is_running = True
        s = ManticoreRunner(bv.session_data.mui_find, bv.session_data.mui_avoid, bv)
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

widget.register_dockwidget(
    StateListWidget, StateListWidget.NAME, Qt.RightDockWidgetArea, Qt.Vertical, True
)

widget.register_dockwidget(
    StateGraphWidget, StateGraphWidget.NAME, Qt.TopDockWidgetArea, Qt.Vertical, True
)

settings = Settings()
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


# Register as a global so it doesn't get destructed
notif = UINotification()
