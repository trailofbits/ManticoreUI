import os
import typing
from pathlib import Path
from datetime import datetime
from inspect import getmembers, isfunction
from dataclasses import dataclass

from binaryninja import (
    BinaryView,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    HighlightStandardColor,
    HighlightColor,
)
from manticore.core.plugin import StateDescriptor
from manticore.core.state import StateBase, TerminateState
from manticore.native import models, Manticore


class MUIState:
    def __init__(self, bv: BinaryView, m: Manticore, filename: str):
        self.bv = bv
        self.m = m
        self.filename = filename
        self.states: typing.Dict[int, StateDescriptor] = {}
        self.state_change_listeners: typing.List[
            typing.Callable[
                [typing.Dict[int, StateDescriptor], typing.Dict[int, StateDescriptor]], None
            ]
        ] = []
        self.paused_states: typing.Set[int] = set()
        self.state_callbacks: typing.Dict[int, typing.Set[typing.Callable]] = dict()
        self.state_trace: typing.Dict[int, typing.Set[int]] = dict()
        self.module_mappings: typing.Dict[str, typing.Any] = dict()
        self._current_highlight_trace: typing.Tuple[typing.Optional[int], typing.List[int]] = (
            None,
            [],
        )

    def get_state(self, state_id: int) -> typing.Optional[StateDescriptor]:
        """Get the state descriptor for a given id"""
        if state_id in self.states:
            return self.states[state_id]
        else:
            return None

    def get_state_address(self, state_id: int) -> typing.Optional[int]:
        """Get the current instruction address of a given state"""
        state = self.get_state(state_id)

        if state is None:
            return None

        if isinstance(state.pc, int):
            return state.pc
        elif isinstance(state.last_pc, int):
            # use last_pc as a fallback
            return state.last_pc
        else:
            return None

    def navigate_to_state(self, state_id: int) -> None:
        """Navigate to the current instruction of a given state"""
        addr = self.get_state_address(state_id)

        if addr is not None:
            self.bv.navigate(self.bv.view, addr)
        else:
            show_message_box(
                "[MUI] No instruction information available",
                f"State {state_id} doesn't contain any instruction information.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon,
            )

    def on_state_change(
        self,
        callback: typing.Callable[
            [typing.Dict[int, StateDescriptor], typing.Dict[int, StateDescriptor]], None
        ],
    ) -> None:
        """Register an event listener for state changes"""
        self.state_change_listeners.append(callback)

    def notify_states_changed(self, new_states: typing.Dict[int, StateDescriptor]) -> None:
        """Updates internal states and invokes listeners"""
        old_states = self.states

        for callback in self.state_change_listeners:
            callback(old_states, new_states)

        self.states = new_states

    def state_callback_hook(self, state: StateBase) -> None:
        """Global hook that calls any callbacks that are tied to specific states"""
        callbacks = self.state_callbacks.get(state.id, set())
        for callback in callbacks:
            callback(state)

    def state_pause_hook(self, state: StateBase) -> None:
        """Global manticore hook that pauses the state (runs once and self-removes)"""
        self._unregister_state_callback(state.id, self.state_pause_hook)
        raise TerminateState("Pausing state")

    def state_kill_hook(self, state: StateBase) -> None:
        """Global manticore hook that kills the state (runs once and self-removes)"""
        self._unregister_state_callback(state.id, self.state_kill_hook)
        state.abandon()

    def _register_state_callback(self, state_id: int, callback: typing.Callable) -> None:
        """Registers a callback to be called by a specific state"""
        callbacks = self.state_callbacks.get(state_id, set())
        callbacks.add(callback)
        self.state_callbacks[state_id] = callbacks

    def _unregister_state_callback(self, state_id: int, callback: typing.Callable) -> None:
        """Registers a callback to be called by a specific state"""
        callbacks = self.state_callbacks.get(state_id, set())
        if callback in callbacks:
            callbacks.remove(callback)

    def pause_state(self, state_id: int) -> None:
        bv = self.bv
        m = self.m
        # Only pause when running
        if bv.session_data.mui_is_running and m:
            # Add dummy busy state to prevent manticore from finishing
            if not self.paused_states:
                with m._lock:
                    m._busy_states.append(-1)
                    m._lock.notify_all()
            self._register_state_callback(state_id, self.state_pause_hook)
            self.paused_states.add(state_id)

    def resume_state(self, state_id: int) -> None:
        bv = self.bv
        m = self.m
        # Only resume when running
        if bv.session_data.mui_is_running and m:
            self.paused_states.remove(state_id)
            with m._lock:
                m._revive_state(state_id)
                # Remove dummy busy state if no more paused states
                if not self.paused_states:
                    m._busy_states.remove(-1)
                m._lock.notify_all()

    def kill_state(self, state_id: int) -> None:
        bv = self.bv
        m = self.m
        # Only kill when running
        if bv.session_data.mui_is_running and m:
            if state_id in self.paused_states:
                self.paused_states.remove(state_id)
                if not self.paused_states:
                    with m._lock:
                        m._busy_states.remove(-1)
                        m._lock.notify_all()
            else:
                self._register_state_callback(state_id, self.state_kill_hook)

    def set_trace(self, state_id: int, trace: typing.Set[int]) -> None:
        self.state_trace[state_id] = trace

    def clear_highlight_trace(self) -> None:
        """Remove old highlight of execution trace (if any)"""
        if self._current_highlight_trace[0]:
            for block_addr in self._current_highlight_trace[1]:
                clear_highlight_block(self.bv, block_addr)
        self._current_highlight_trace = (None, [])

    def highlight_trace(self, state_id: int) -> None:
        """Highlights the execution trace of a state"""
        self.clear_highlight_trace()

        # Highlight blocks in current binary
        self._current_highlight_trace = (state_id, [])
        trace = self.state_trace.get(state_id, set())
        module_map = self.module_mappings.get(self.filename, None)

        if not trace:
            print(
                f"No trace data found for state {state_id}. Did you enable tracing in run options?"
            )
            return

        if module_map:
            for block_addr in trace:
                if module_map.start <= block_addr and block_addr < module_map.end:
                    addr = block_addr - module_map.start + self.bv.start
                    highlight_block(
                        self.bv,
                        addr,
                        HighlightStandardColor.OrangeHighlightColor,
                    )
                    self._current_highlight_trace[1].append(addr)

    def current_highlight_state(self) -> typing.Optional[int]:
        """Returns the state_id of the current state with trace highlighting"""
        return self._current_highlight_trace[0]


def highlight_instr(bv: BinaryView, addr: int, color: HighlightStandardColor) -> None:
    """Highlight instruction at a given address"""
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(color, alpha=128))
        block.function.set_auto_instr_highlight(addr, color)


def highlight_block(bv: BinaryView, addr: int, color: HighlightStandardColor) -> None:
    """Highlight all instructions in block containing a given address"""
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(color, alpha=128))
        for line in block.disassembly_text:
            block.function.set_auto_instr_highlight(line.address, color)


def clear_highlight(bv: BinaryView, addr: int) -> None:
    """Remove instruction highlight"""
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
        block.function.set_auto_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)


def clear_highlight_block(bv: BinaryView, addr: int) -> None:
    """Removes highlight from all instructions in block containing a given address"""
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
        for line in block.disassembly_text:
            block.function.set_auto_instr_highlight(
                line.address, HighlightStandardColor.NoHighlightColor
            )


def get_default_solc_path():
    """Attempt to find the path for the solc binary"""

    possible_paths = [Path(x) for x in os.environ["PATH"].split(":")]
    possible_paths.extend([Path(os.path.expanduser("~"), ".local/bin").resolve()])

    for path in possible_paths:
        if Path(path, "solc").is_file():
            return str(Path(path, "solc"))

    return ""


def print_timestamp(*args, **kw):
    """Print with timestamp prefixed (local timezone)"""
    timestamp = datetime.now().astimezone()
    print(f"[{timestamp}]", *args, **kw)


@dataclass
class MUIFunctionModel:
    name: str
    func: typing.Callable


def get_function_models() -> typing.List[MUIFunctionModel]:
    """
    Returns available function models
    ref: https://github.com/trailofbits/manticore/blob/master/docs/native.rst#function-models
    """

    # Functions only
    functions = filter(lambda x: isfunction(x[1]), getmembers(models))
    func_models = [MUIFunctionModel(name, func) for name, func in functions]

    # Manually remove non-function model functions
    def is_model(model: MUIFunctionModel) -> bool:
        blacklist = set(["isvariadic", "variadic", "must_be_NULL", "cannot_be_NULL", "can_be_NULL"])
        if model.func.__module__ != "manticore.native.models":
            return False
        # Functions starting with '_' assumed to be private
        if model.name.startswith("_"):
            return False
        if model.name in blacklist:
            return False
        return True

    func_models = list(filter(is_model, func_models))

    return func_models


def function_model_analysis_cb(bv: BinaryView) -> None:
    """
    Callback when initial analysis completed.
    Tries to match functions with same name as available function models
    """
    models = get_function_models()
    model_names = [model.name for model in models]
    matches = set()
    for func in bv.functions:
        for name in model_names:
            if name.startswith(func.name):
                matches.add(func)

    if matches:
        banner = "\n"
        banner += "###################################\n"
        banner += "# MUI Function Model Analysis     #\n"
        banner += "#                                 #\n"
        banner += f"# {len(matches):02d} function(s) match:           #\n"
        for func in matches:
            s = f"# * {func.start:08x}, {func.name}"
            banner += s.ljust(34, " ") + "#\n"
        banner += "###################################\n"
        banner += "-> Use 'Add Function Model' to hook these functions"

        print(banner)
