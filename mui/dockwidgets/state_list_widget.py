from typing import Dict, Final, List, Optional

from PySide6 import QtCore
from PySide6.QtCore import Slot, Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidgetItem, QTreeWidget
from binaryninja import BinaryView
from binaryninjaui import DockContextHandler, ViewFrame
from manticore.core.plugin import StateDescriptor
from manticore.utils.enums import StateStatus, StateLists

from mui.dockwidgets import widget
from mui.dockwidgets.state_graph_widget import StateGraphWidget
from mui.utils import MUIStateData, navigate_to_state

from muicore.MUICore_pb2 import MUIState


class StateListWidget(QWidget, DockContextHandler):

    NAME: Final[str] = "Manticore State"

    # column used for state name
    STATE_NAME_COLUMN: Final[int] = 0

    # role used to store state id on qt items
    STATE_DATA_ROLE: Final[int] = Qt.UserRole

    def __init__(self, name: str, parent: ViewFrame, data: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = data

        tree_widget = QTreeWidget()
        tree_widget.setColumnCount(1)
        tree_widget.headerItem().setText(0, "State List")
        self.tree_widget = tree_widget
        tree_widget.itemClicked.connect(self.on_select)
        tree_widget.itemDoubleClicked.connect(self.on_doubleclick)

        self._initialize_headers()

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        self.setLayout(layout)

        self.selected_state_id: Optional[int] = None

    def _initialize_headers(self):
        self.active_states = QTreeWidgetItem(None, ["Active"])
        self.waiting_states = QTreeWidgetItem(None, ["Waiting"])
        self.forked_states = QTreeWidgetItem(None, ["Forked"])
        self.complete_states = QTreeWidgetItem(None, ["Complete"])
        self.error_states = QTreeWidgetItem(None, ["Errored"])

        self.state_lists = [
            self.active_states,
            self.waiting_states,
            self.forked_states,
            self.complete_states,
            self.error_states,
        ]
        self.tree_widget.insertTopLevelItems(0, self.state_lists)
        for state_list in self.state_lists:
            self.tree_widget.expandItem(state_list)

    @Slot(QTreeWidgetItem, int)
    def on_select(self, item: QTreeWidgetItem, col: int):
        """Persist selected tree item across refreshes if it is a state"""

        item_data: Optional[MUIStateData] = item.data(
            StateListWidget.STATE_NAME_COLUMN, StateListWidget.STATE_DATA_ROLE
        )

        # do nothing on non-state items
        if item_data is None:
            return

        self.selected_state_id = item_data.id

    @Slot(QTreeWidgetItem, int)
    def on_doubleclick(self, item: QTreeWidgetItem, col: int):
        """Jump to the current PC of a given state when double clicked"""

        item_data: Optional[MUIStateData] = item.data(
            StateListWidget.STATE_NAME_COLUMN, StateListWidget.STATE_DATA_ROLE
        )

        # do nothing on non-state items
        if item_data is None:
            return

        graph_widget: StateGraphWidget = widget.get_dockwidget(self.bv, StateGraphWidget.NAME)
        graph_widget.update_graph(item_data)

        navigate_to_state(self.bv, item_data)

    def refresh_state_list(
        self,
        active: List[MUIState],
        waiting: List[MUIState],
        forked: List[MUIState],
        errored: List[MUIState],
        complete: List[MUIState],
    ):
        self.tree_widget.clear()
        self._initialize_headers()

        sl_map = {
            self.active_states: active,
            self.waiting_states: waiting,
            self.forked_states: forked,
            self.error_states: errored,
            self.complete_states: complete,
        }

        self.bv.session_data.mui_states = {}

        for widget, states in sl_map.items():
            for state in states:
                item = QTreeWidgetItem(widget, [f"State {state.state_id}"])
                self.bv.session_data.mui_states[state.state_id] = MUIStateData(
                    state.state_id,
                    state.pc if state.pc else None,
                    state.parent_id if state.parent_id != -1 else None,
                    set(state.children_ids),
                )
                item.setData(
                    StateListWidget.STATE_NAME_COLUMN,
                    StateListWidget.STATE_DATA_ROLE,
                    self.bv.session_data.mui_states[state.state_id],
                )
                if self.selected_state_id == state.state_id:
                    item.setSelected(True)

        self._refresh_list_counts()

    def _refresh_list_counts(self):
        """Refreshes all the state counts"""
        total_count = 0

        # update count for each individual list
        for state_list in self.state_lists:
            child_count = state_list.childCount()
            state_list.setText(0, f'{state_list.text(0).split(" ")[0]} ({child_count})')

            total_count += child_count

        header_item = self.tree_widget.headerItem()

        title_without_count = header_item.text(0)
        # strip previous count from title
        if title_without_count[-1] == ")":
            title_without_count = title_without_count[: title_without_count.rfind("(") - 1]

        header_item.setText(0, f"{title_without_count} ({total_count})")
