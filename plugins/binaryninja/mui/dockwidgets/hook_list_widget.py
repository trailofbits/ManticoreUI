from enum import Enum
from typing import Dict, Final, Optional, Tuple

from binaryninjaui import DockContextHandler, DockHandler, ViewFrame
from PySide6.QtCore import QEvent, Qt, Slot
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

import mui.dockwidgets.global_hook_dialog
import mui.hook_manager
import mui.mui
from binaryninja import BinaryView
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
        self.mgr = None

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

            parent = item.parent()
            menu = QMenu()
            menu.addAction("Delete")
            if parent == self.custom_hooks or parent == self.global_hooks:
                menu.addAction("Edit")

            action = menu.exec(event.globalPos())
            if not isinstance(action, QAction):
                return True

            if action.text() == "Delete":
                if not self.mgr:
                    return True

                bv = self.bv
                if parent == self.find_hooks:
                    self.mgr.del_find_hook(addr)
                elif parent == self.avoid_hooks:
                    self.mgr.del_avoid_hook(addr)
                elif parent == self.custom_hooks:
                    self.mgr.del_custom_hook(mui.hook_manager.CustomHookIdentity.from_name(name))
                elif parent == self.global_hooks:
                    self.mgr.del_global_hook(name)
                else:
                    raise Exception("Deleting hook with invalid parent")
            elif action.text() == "Edit":
                if not self.mgr:
                    return True

                bv = self.bv
                if parent == self.custom_hooks:
                    mui.mui.edit_custom_hook(bv, addr, name)
                elif parent == self.global_hooks:
                    dialog = mui.dockwidgets.global_hook_dialog.GlobalHookDialog(
                        DockHandler.getActiveDockHandler().parent(), bv, self.mgr
                    )
                    dialog.edit_hook(name)

            return True

        return super().eventFilter(source, event)

    @Slot(QTreeWidgetItem, int)
    def on_click(self, item: QTreeWidgetItem, col: int):
        """Jump to the addr of a hook when double clicked"""
        addr = item.data(self.HOOK_ADDR_COLUMN, self.HOOK_ROLE)

        if addr:
            self.bv.navigate(self.bv.view, addr)

    def add_hook(self, hook_type: HookType, addr: int, name="") -> None:
        """Add a hook to its corresponding hook list"""
        # Prevent repeated entries
        if (hook_type, addr, name) in self.hook_items:
            return

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

    def remove_hook(self, hook_type: HookType, addr: int, name="") -> None:
        """Remove a hook from its corresponding hook list"""
        item = self.hook_items[(hook_type, addr, name)]
        item.parent().removeChild(item)
        del self.hook_items[(hook_type, addr, name)]

    def set_manager(self, mgr) -> None:
        self.mgr = mgr
