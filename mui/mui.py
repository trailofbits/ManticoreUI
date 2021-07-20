import tempfile
from time import sleep
from typing import Set, Callable, Dict

from PySide6.QtCore import Qt
from binaryninja import (
    PluginCommand,
    BinaryView,
    BackgroundTaskThread,
    HighlightStandardColor,
    HighlightColor,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
)
from manticore.core.plugin import StateDescriptor
from manticore.core.state import StateBase
from manticore.native import Manticore

from mui.dockwidgets import widget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.introspect_plugin import MUIIntrospectionPlugin

BinaryView.set_default_session_data("mui_find", set())
BinaryView.set_default_session_data("mui_avoid", set())


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

        # clear state UI
        state_widget: StateListWidget = widget.get_dockwidget(self.view, StateListWidget.NAME)
        state_widget.notifyStatesChanged({})

        m = Manticore.linux(
            self.binary.name, workspace_url="mem:", introspection_plugin_type=MUIIntrospectionPlugin
        )

        def avoid_f(state: StateBase):
            state.abandon()

        for addr in self.avoid:
            m.hook(addr)(avoid_f)

        def find_f(state: StateBase):
            bufs = state.solve_one_n_batched(state.input_symbols)
            for symbol, buf in zip(state.input_symbols, bufs):
                print(f"{symbol.name}: {buf!r}\n")
            m.kill()

        for addr in self.find:
            m.hook(addr)(find_f)

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

        def update_ui(states: Dict[int, StateDescriptor]):
            """Updates the StateListWidget to reflect current progress"""
            state_widget: StateListWidget = widget.get_dockwidget(self.view, StateListWidget.NAME)
            state_widget.notifyStatesChanged(states)

        m.register_daemon(run_every(update_ui, 1))
        m.run()
        update_ui(m.introspect())
        print("Manticore finished")


def find_instr(bv: BinaryView, addr: int):
    """This command handler adds a given address to the find list and highlights it green in the UI"""

    # Highlight the instruction in green
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(
            HighlightColor(HighlightStandardColor.GreenHighlightColor, alpha=128)
        )
        block.function.set_auto_instr_highlight(addr, HighlightStandardColor.GreenHighlightColor)

    # Add the instruction to the list associated with the current view
    bv.session_data.mui_find.add(addr)


def avoid_instr(bv: BinaryView, addr: int):
    """This command handler adds a given address to the avoid list and highlights it red in the UI"""

    # Highlight the instruction in red
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(
            HighlightColor(HighlightStandardColor.RedHighlightColor, alpha=128)
        )
        block.function.set_auto_instr_highlight(addr, HighlightStandardColor.RedHighlightColor)

    # Add the instruction to the list associated with the current view
    bv.session_data.mui_avoid.add(addr)


def solve(bv: BinaryView):
    """This command handler starts manticore in a background thread"""

    if len(bv.session_data.mui_find) == 0:
        show_message_box(
            "Manticore Solve",
            "You have not specified a goal instruction.\n\n"
            + 'Please right click on the goal instruction and select "Find Path to This Instruction" to '
            + "continue.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    # Start a solver thread for the path associated with the view
    s = ManticoreRunner(bv.session_data.mui_find, bv.session_data.mui_avoid, bv)
    s.start()


PluginCommand.register_for_address(
    "MUI \\ Find Path to This Instruction",
    "When solving, find a path that gets to this instruction",
    find_instr,
)
PluginCommand.register_for_address(
    "MUI \\ Avoid This Instruction",
    "When solving, avoid paths that reach this instruction",
    avoid_instr,
)
PluginCommand.register(
    "MUI \\ Solve With Manticore",
    "Attempt to solve for a path that satisfies the constraints given",
    solve,
)

widget.register_dockwidget(
    StateListWidget, StateListWidget.NAME, Qt.RightDockWidgetArea, Qt.Vertical, True
)
