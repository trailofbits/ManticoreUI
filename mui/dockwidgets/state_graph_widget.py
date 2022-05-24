import typing
from PySide6.QtGui import QMouseEvent, QShortcut, QKeySequence, Qt
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QLabel, QWidget, QDockWidget
from binaryninja import FlowGraph, FlowGraphNode, EdgePenStyle, ThemeColor, EdgeStyle, BranchType
from binaryninja.binaryview import BinaryView
from binaryninjaui import ViewFrame, DockContextHandler, FlowGraphWidget
from manticore.core.plugin import StateDescriptor
from mui.utils import MUIStateData


class StateGraphWidget(QWidget, DockContextHandler):

    NAME: typing.Final[str] = "Manticore State Graph Explorer"

    def __init__(self, name: str, parent: ViewFrame, bv: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = bv
        self.expand_graph: bool = False
        self.curr_id: typing.Optional[int] = None

        vlayout = QVBoxLayout()

        self.flow_graph = MUIFlowGraphWidget(None, bv)
        vlayout.addWidget(self.flow_graph)

        shortcut = QShortcut(QKeySequence("Tab"), self.flow_graph, context=Qt.WidgetShortcut)
        shortcut.activated.connect(self.on_tab)

        self.setLayout(vlayout)

    def on_tab(self) -> None:
        """Toggle expand_graph"""
        self.expand_graph = not self.expand_graph
        if self.curr_id is not None:
            self.update_graph(self.curr_id)

    def update_graph(self, state_data: MUIStateData) -> None:
        """Update graph to display a certain state"""

        self.curr_id = state_id

        mui_state = self.bv.session_data.mui_state

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

            if self.expand_graph:
                for each in prev_state.children:
                    if each != curr_state.state_id:
                        child = FlowGraphNode(graph)
                        child.lines = self._get_lines(each)
                        graph.append(child)
                        prev.add_outgoing_edge(BranchType.FalseBranch, child)

            curr = prev
            curr_state = prev_state

        self.flow_graph.setGraph(graph)
        # print(graph_widget.flow_graph.setGraph(graph))

    def _get_lines(self, state_id: int) -> typing.List:
        mui_state = self.bv.session_data.mui_state

        addr = mui_state.get_state_address(state_id)
        if addr is None or len(self.bv.get_basic_blocks_at(addr)) < 1:
            return [f"State {state_id}", "???"]
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

            self.bv.session_data.mui_state.navigate_to_state(state_id)
