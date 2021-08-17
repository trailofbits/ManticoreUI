from dataclasses import field
from typing import Final, Dict
import typing

from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QLabel, QWidget, QDockWidget
from binaryninja import FlowGraph, FlowGraphNode, EdgePenStyle, ThemeColor, EdgeStyle, BranchType
from binaryninja.binaryview import BinaryView
from binaryninjaui import ViewFrame, DockContextHandler, FlowGraphWidget
from manticore.core.plugin import StateDescriptor

from mui.utils import MUIState


class StateGraphWidget(QWidget, DockContextHandler):

    NAME: Final[str] = "Manticore State Graph Explorer"

    def __init__(self, name: str, parent: ViewFrame, bv: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = bv

        vlayout = QVBoxLayout()

        self.flow_graph = MUIFlowGraphWidget(None, bv)
        vlayout.addWidget(self.flow_graph)
        # flow_graph.setGraph(graph)

        self.setLayout(vlayout)

        # self.setFloating(True)

    def update_graph(self, state_id: int) -> None:
        """Update graph to display a certain state"""

        mui_state: MUIState = self.bv.session_data.mui_state

        graph = FlowGraph()

        curr_state = mui_state.get_state(state_id)

        if curr_state is None:
            return

        curr = FlowGraphNode(graph)
        curr.lines = self._get_lines(state_id)
        graph.append(curr)

        while curr_state.parent is not None:
            prev_state = mui_state.get_state(curr_state.parent)

            if prev_state is None:
                break

            prev = FlowGraphNode(graph)
            prev.lines = self._get_lines(prev_state.state_id)
            graph.append(prev)

            prev.add_outgoing_edge(BranchType.UnconditionalBranch, curr)

            curr = prev
            curr_state = prev_state

        self.flow_graph.setGraph(graph)
        # print(graph_widget.flow_graph.setGraph(graph))

    def _get_lines(self, state_id: int) -> typing.List:
        mui_state: MUIState = self.bv.session_data.mui_state

        addr = mui_state.get_state_address(state_id)
        if addr is None:
            return [f"State {state_id}"]
        else:
            return [
                f"State {state_id}",
                [
                    line
                    for line in self.bv.get_basic_blocks_at(addr)[0].get_disassembly_text()
                    if line.address == addr
                ][0],
            ]


class MUIFlowGraphWidget(FlowGraphWidget):
    def __init__(self, parent: QWidget, view: BinaryView, graph: FlowGraph = None):

        super().__init__(parent, view, graph)

        self.bv = view

    def mouseDoubleClickEvent(self, mouse_event: QMouseEvent):
        node = self.getNodeForMouseEvent(mouse_event)

        if node is not None:
            state_id = int(str(node.lines[0]).split(" ")[-1])
            print(state_id)

            self.bv.session_data.mui_state.navigate_to_state(state_id)
