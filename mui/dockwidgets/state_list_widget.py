from typing import Dict, Final, Optional

from PySide6 import QtCore
from PySide6.QtCore import Slot, Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidgetItem, QTreeWidget
from binaryninja import BinaryView
from binaryninjaui import DockContextHandler, ViewFrame
from manticore.core.plugin import StateDescriptor
from manticore.utils.enums import StateStatus, StateLists

from mui.dockwidgets import widget
from mui.dockwidgets.state_graph_widget import StateGraphWidget
from mui.utils import MUIState


class StateListWidget(QWidget, DockContextHandler):

    NAME: Final[str] = "Manticore State"

    # column used for state name
    STATE_NAME_COLUMN: Final[int] = 0

    # role used to store state id on qt items
    STATE_ID_ROLE: Final[int] = Qt.UserRole

    def __init__(self, name: str, parent: ViewFrame, data: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = data

        tree_widget = QTreeWidget()
        tree_widget.setColumnCount(1)
        tree_widget.headerItem().setText(0, "State List")
        self.tree_widget = tree_widget
        tree_widget.itemDoubleClicked.connect(self.on_click)

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
        tree_widget.insertTopLevelItems(0, self.state_lists)
        for state_list in self.state_lists:
            tree_widget.expandItem(state_list)

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        self.setLayout(layout)

        self.state_items: Dict[int, QTreeWidgetItem] = {}

    @Slot(QTreeWidgetItem, int)
    def on_click(self, item: QTreeWidgetItem, col: int):
        """Jump to the current PC of a given state when double clicked"""

        item_id = item.data(StateListWidget.STATE_NAME_COLUMN, StateListWidget.STATE_ID_ROLE)

        # do nothing on non-state items
        if item_id is None:
            return

        # print(self.bv.session_data.mui_state.get_state(item_id))
        graph_widget: StateGraphWidget = widget.get_dockwidget(self.bv, StateGraphWidget.NAME)
        graph_widget.update_graph(item_id)

        self.bv.session_data.mui_state.navigate_to_state(item_id)

    def listen_to(self, mui_state: MUIState):
        """Register this widget with a MUI State object and set up event listeners"""
        mui_state.on_state_change(self.on_state_change)

    def on_state_change(
        self, old_states: Dict[int, StateDescriptor], new_states: Dict[int, StateDescriptor]
    ):
        """Updates the UI to reflect new_states, clears everything if an empty dict is provided"""
        # add/update new states
        for state_id, state in new_states.items():
            if state_id in self.state_items:
                item = self.state_items[state_id]
                self._update_item(item, state)
            else:
                item = self._create_item(state)
                self.state_items[state_id] = item

        # remove old states
        for removed_state_id in set(old_states.keys()) - set(new_states.keys()):
            item = self.state_items[removed_state_id]
            item.parent().removeChild(item)
            del self.state_items[removed_state_id]

        # update list counts
        self._refresh_list_counts()

    def _get_state_list(self, state: StateDescriptor) -> QTreeWidgetItem:
        """Get the corresponding state list for a given state"""

        if state.status == StateStatus.running:
            return self.active_states
        elif state.status in [StateStatus.waiting_for_worker, StateStatus.waiting_for_solver]:
            return self.waiting_states
        elif state.status == StateStatus.destroyed:
            return self.forked_states
        elif state.status == StateStatus.stopped:
            # Only want killed states in the errored list
            if state.state_list == StateLists.killed:
                return self.error_states
            else:
                return self.complete_states
        else:
            raise ValueError(f"Unknown status {state.status}")

    def _update_item(self, item: QTreeWidgetItem, state: StateDescriptor):
        """Updates a single item based on its new state"""
        switch_to_list = self._get_state_list(state)

        if switch_to_list is not item.parent():
            item.parent().removeChild(item)
            switch_to_list.addChild(item)

    def _create_item(self, state: StateDescriptor) -> QTreeWidgetItem:
        """Creates a new item that represents a given state"""

        parent = self._get_state_list(state)
        item = QTreeWidgetItem(parent, [f"State {state.state_id}"])
        item.setData(
            StateListWidget.STATE_NAME_COLUMN, StateListWidget.STATE_ID_ROLE, state.state_id
        )
        return item

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
