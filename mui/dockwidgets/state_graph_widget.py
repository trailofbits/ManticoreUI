from typing import Final, List, Optional
from PySide6.QtGui import QMouseEvent, QShortcut, QKeySequence, Qt
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QLabel, QWidget, QDockWidget
from binaryninja import FlowGraph, FlowGraphNode, EdgePenStyle, ThemeColor, EdgeStyle, BranchType
from binaryninja.binaryview import BinaryView
from binaryninjaui import ViewFrame, DockContextHandler, FlowGraphWidget
from manticore.core.plugin import StateDescriptor
from mui.utils import MUIStateData, navigate_to_state


class StateGraphWidget(QWidget, DockContextHandler):

    NAME: Final[str] = "Manticore State Graph Explorer"

    def __init__(self, name: str, parent: ViewFrame, bv: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = bv
        self.expand_graph: bool = False
        self.selected_state: Optional[MUIStateData] = None

        vlayout = QVBoxLayout()

        self.flow_graph = MUIFlowGraphWidget(None, bv)
        vlayout.addWidget(self.flow_graph)

        shortcut = QShortcut(QKeySequence("Tab"), self.flow_graph, context=Qt.WidgetShortcut)
        shortcut.activated.connect(self.on_tab)

        self.setLayout(vlayout)

    def on_tab(self) -> None:
        """Toggle expand_graph"""
        self.expand_graph = not self.expand_graph
        if self.selected_state is not None:
            self.update_graph(self.selected_state)

    def update_graph(self, state_data: MUIStateData) -> None:
        """Update graph to display a certain state"""
        self.selected_state = state_data
        curr_state = state_data
        graph = FlowGraph()

        if state_data is None:
            return

        curr = FlowGraphNode(graph)
        curr.lines = self._get_lines(state_data)
        graph.append(curr)
        while isinstance(curr_state.parent_id, int):

            prev_state = self.bv.session_data.mui_states.get(curr_state.parent_id)

            if prev_state is None or prev_state.id == curr_state.id:
                break

            prev = FlowGraphNode(graph)
            prev.lines = self._get_lines(prev_state)
            graph.append(prev)

            prev.add_outgoing_edge(BranchType.UnconditionalBranch, curr)

            if self.expand_graph:
                for each_id in prev_state.children_ids:
                    if each_id != curr_state.id:
                        each = self.bv.session_data.mui_states.get(each_id)
                        child = FlowGraphNode(graph)
                        child.lines = self._get_lines(each)
                        graph.append(child)
                        prev.add_outgoing_edge(BranchType.FalseBranch, child)

            curr = prev
            curr_state = prev_state

        self.flow_graph.setGraph(graph)
        # print(graph_widget.flow_graph.setGraph(graph))

    def _get_lines(self, state_data: MUIStateData) -> List:
        addr = state_data.pc
        if addr is None or len(self.bv.get_basic_blocks_at(addr)) < 1:
            return [f"State {state_data.id}", "???"]
        else:
            return [
                f"State {state_data.id}",
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

            navigate_to_state(self.bv, self.bv.session_data.mui_states.get(state_id))
