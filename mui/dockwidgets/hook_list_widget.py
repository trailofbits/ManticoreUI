from enum import Enum
from typing import Dict, Final, Tuple

from PySide6.QtCore import Qt, Slot, QEvent
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTreeWidgetItem, QTreeWidget, QMenu
from binaryninja import BinaryView
from binaryninjaui import DockContextHandler, ViewFrame

from mui.utils import clear_highlight


class HookType(Enum):
    FIND = 0
    AVOID = 1
    CUSTOM = 2
    GLOBAL = 3


class HookListWidget(QWidget, DockContextHandler):

    NAME: Final[str] = "Manticore Hooks"

    # columns used for hook address/name
    HOOK_ADDR_COLUMN: Final[int] = 0
    HOOK_NAME_COLUMN: Final[int] = 1

    HOOK_ROLE: Final[int] = Qt.UserRole

    def __init__(self, name: str, parent: ViewFrame, data: BinaryView):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.bv = data

        tree_widget = QTreeWidget()
        self.tree_widget = tree_widget
        tree_widget.setColumnCount(1)
        tree_widget.headerItem().setText(0, "Hook List")
        tree_widget.itemDoubleClicked.connect(self.on_click)
        tree_widget.installEventFilter(self)

        self.find_hooks = QTreeWidgetItem(None, ["Find"])
        self.avoid_hooks = QTreeWidgetItem(None, ["Avoid"])
        self.custom_hooks = QTreeWidgetItem(None, ["Custom"])
        self.global_hooks = QTreeWidgetItem(None, ["Global"])

        self.hook_lists = [
            self.find_hooks,
            self.avoid_hooks,
            self.custom_hooks,
            self.global_hooks,
        ]

        tree_widget.insertTopLevelItems(0, self.hook_lists)
        for hook_list in self.hook_lists:
            tree_widget.expandItem(hook_list)

        layout = QVBoxLayout()
        layout.addWidget(tree_widget)
        self.setLayout(layout)

        self.hook_items: Dict[Tuple[HookType, int, str], QTreeWidgetItem] = {}

    def eventFilter(self, source, event) -> bool:
        """Event filter to create hook management context menu"""
        if event.type() == QEvent.ContextMenu and source is self.tree_widget:
            pos = source.viewport().mapFromParent(event.pos())
            item = source.itemAt(pos)

            # Right clicked outside an item
            if not item:
                return True

            addr = item.data(self.HOOK_ADDR_COLUMN, self.HOOK_ROLE)
            name = item.data(self.HOOK_NAME_COLUMN, self.HOOK_ROLE)

            # Hook list instead of individual hook
            if addr == None or name == None:
                return True

            menu = QMenu()
            menu.addAction("Delete")

            if menu.exec(event.globalPos()):
                parent = item.parent()
                parent.removeChild(item)

                bv = self.bv
                if parent == self.find_hooks:
                    clear_highlight(bv, addr)
                    bv.session_data.mui_find.remove(addr)
                elif parent == self.avoid_hooks:
                    clear_highlight(bv, addr)
                    bv.session_data.mui_avoid.remove(addr)
                elif parent == self.custom_hooks:
                    clear_highlight(bv, addr)
                    del bv.session_data.mui_custom_hooks[addr]
                elif parent == self.global_hooks:
                    del bv.session_data.mui_global_hooks[name]
                else:
                    raise Exception("Deleting hook with invalid parent")

            return True

        return super().eventFilter(source, event)

    @Slot(QTreeWidgetItem, int)
    def on_click(self, item: QTreeWidgetItem, col: int):
        """Jump to the addr of a hook when double clicked"""
        addr = item.data(self.HOOK_ADDR_COLUMN, self.HOOK_ROLE)

        if addr:
            self.bv.navigate(self.bv.view, addr)

    def add_hook(self, hook_type: HookType, addr: int, name=""):
        """Add a hook to its corresponding hook list"""
        parent = None
        if hook_type == HookType.FIND:
            parent = self.find_hooks
        elif hook_type == HookType.AVOID:
            parent = self.avoid_hooks
        elif hook_type == HookType.CUSTOM:
            parent = self.custom_hooks
        elif hook_type == HookType.GLOBAL:
            parent = self.global_hooks
        else:
            raise Exception("Invalid hook type")

        if name:
            item = QTreeWidgetItem(parent, [name])
        else:
            item = QTreeWidgetItem(parent, [f"{addr:08x}"])
        item.setData(self.HOOK_ADDR_COLUMN, self.HOOK_ROLE, addr)
        item.setData(self.HOOK_NAME_COLUMN, self.HOOK_ROLE, name)
        self.hook_items[(hook_type, addr, name)] = item

    def remove_hook(self, hook_type: HookType, addr: int, name=""):
        """Remove a hook from its corresponding hook list"""
        item = self.hook_items[(hook_type, addr, name)]
        item.parent().removeChild(item)

    def load_existing_hooks(self):
        """Load existing hooks from session data"""
        for addr in self.bv.session_data.mui_find:
            self.add_hook(HookType.FIND, addr)

        for addr in self.bv.session_data.mui_avoid:
            self.add_hook(HookType.AVOID, addr)

        for addr in self.bv.session_data.mui_custom_hooks.keys():
            self.add_hook(HookType.CUSTOM, addr)

        for name in self.bv.session_data.mui_global_hooks.keys():
            self.add_hook(HookType.GLOBAL, 0, name)
