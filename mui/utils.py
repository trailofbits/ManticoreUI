import typing
from binaryninja import (
    BinaryView,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    HighlightStandardColor,
    HighlightColor,
)
from manticore.core.plugin import StateDescriptor


class MUIState:
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.states: typing.Dict[int, StateDescriptor] = {}
        self.state_change_listeners: typing.List[
            typing.Callable[
                [typing.Dict[int, StateDescriptor], typing.Dict[int, StateDescriptor]], None
            ]
        ] = []

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


def highlight_instr(bv: BinaryView, addr: int, color: HighlightStandardColor) -> None:
    """Highlight instruction at a given address"""
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(color, alpha=128))
        block.function.set_auto_instr_highlight(addr, color)


def clear_highlight(bv: BinaryView, addr: int) -> None:
    """Remove instruction highlight"""
    blocks = bv.get_basic_blocks_at(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
        block.function.set_auto_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
