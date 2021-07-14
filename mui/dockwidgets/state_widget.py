from typing import Dict, Optional

from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidgetItem, QTreeWidget
from binaryninjaui import DockContextHandler
from manticore.core.plugin import StateDescriptor
from manticore.utils.enums import StateStatus


class StateWidget(QWidget, DockContextHandler):
    def __init__(self, name, parent, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        tree_widget = QTreeWidget()
        tree_widget.setColumnCount(1)
        tree_widget.headerItem().setHidden(True)
        self.tree_widget = tree_widget

        self.active_states = QTreeWidgetItem(None, ["Active"])
        self.waiting_states = QTreeWidgetItem(None, ["Waiting"])
        self.complete_states = QTreeWidgetItem(None, ["Complete"])
        self.error_states = QTreeWidgetItem(None, ["Errored"])

        state_lists = [
            self.active_states,
            self.waiting_states,
            self.complete_states,
            self.error_states,
        ]
        tree_widget.insertTopLevelItems(0, state_lists)
        for state_list in state_lists:
            tree_widget.expandItem(state_list)

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        self.setLayout(layout)

        self.state_status_mapping = [
            (self.active_states, [StateStatus.running]),
            (self.waiting_states, [StateStatus.waiting_for_worker, StateStatus.waiting_for_solver]),
            (self.complete_states, [StateStatus.stopped]),
            (self.error_states, [StateStatus.destroyed]),
        ]

        self.states: Dict[int, StateDescriptor] = {}
        self.state_items: Dict[int, QTreeWidgetItem] = {}

    def notifyStatesChanged(self, new_states: Dict[int, StateDescriptor]):
        old_states = self.states

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

        # update the states reference
        self.states = new_states

    def _update_item(self, item: QTreeWidgetItem, state: StateDescriptor):
        switch_to_list = None

        for state_list, status_list in self.state_status_mapping:
            if state.status in status_list and item.parent() is not state_list:
                switch_to_list = state_list
                break

        if switch_to_list is not None:
            item.parent().removeChild(item)
            switch_to_list.addChild(item)

    def _create_item(self, state: StateDescriptor) -> QTreeWidgetItem:
        for state_list, status_list in self.state_status_mapping:
            if state.status in status_list:
                return QTreeWidgetItem(state_list, [f"State {state.state_id}"])

        raise ValueError(f"Unknown status {state.status}")
