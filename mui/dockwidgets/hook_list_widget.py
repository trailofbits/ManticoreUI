from time import sleep
from enum import Enum
from typing import Dict, Final, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidgetItem, QTreeWidget
from binaryninja import BinaryView, BinaryViewEvent, BinaryViewEventType, BinaryViewType
from binaryninjaui import DockContextHandler, ViewFrame

class HookType(Enum):
    FIND = 0
    AVOID = 1
    CUSTOM = 2

class HookListWidget(QWidget, DockContextHandler):

    NAME: Final[str] = "Manticore Hooks"

    # column used for hook address
    HOOK_ADDR_COLUMN: Final[int] = 0

    HOOK_ROLE: Final[int] = Qt.UserRole

    def __init__(self, name: str, parent: ViewFrame, data: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = data

        tree_widget = QTreeWidget()
        tree_widget.setColumnCount(1)
        tree_widget.headerItem().setText(0, "Hook List")
        self.tree_widget = tree_widget

        self.find_hooks = QTreeWidgetItem(None, ["Find"])
        self.avoid_hooks = QTreeWidgetItem(None, ["Avoid"])
        self.custom_hooks = QTreeWidgetItem(None, ["Custom"])

        self.hook_lists = [
            self.find_hooks,
            self.avoid_hooks,
            self.custom_hooks,
        ]

        tree_widget.insertTopLevelItems(0, self.hook_lists)
        for hook_list in self.hook_lists:
            tree_widget.expandItem(hook_list)

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        self.setLayout(layout)

        self.hook_items : Dict[Tuple[HookType, int], QTreeWidgetItem] = {}
    
    def add_hook(self, hook_type: HookType, addr: int):
        """Add a hook to its corresponding hook list"""
        parent = None
        if hook_type == HookType.FIND:
            parent = self.find_hooks
        elif hook_type == HookType.AVOID:
            parent = self.avoid_hooks
        elif hook_type == HookType.CUSTOM:
            parent = self.custom_hooks
        else:
            raise Exception('Invalid hook type') 
        
        item = QTreeWidgetItem(parent, [f"{addr:08x}"])
        item.setData(self.HOOK_ADDR_COLUMN, self.HOOK_ROLE, addr)
        self.hook_items[(hook_type, addr)] = item
    
    def remove_hook(self, hook_type: HookType, addr: int):
        """Remove a hook from its corresponding hook list"""
        item = self.hook_items[(hook_type, addr)]
        item.parent().removeChild(item)
    
    def _load_existing_hooks(self):
        """Load existing hooks from session data"""
        for addr in self.bv.session_data.mui_find:
            self.add_hook(HookType.FIND, addr)

        for addr in self.bv.session_data.mui_avoid:
            self.add_hook(HookType.AVOID, addr)

        for addr in self.bv.session_data.mui_custom_hooks.keys():
            self.add_hook(HookType.CUSTOM, addr)