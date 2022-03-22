from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QListWidget,
    QListWidgetItem,
)
from binaryninja import (
    BinaryView,
)
from binaryninjaui import UIContext, DockHandler

from mui.dockwidgets import widget
from mui.dockwidgets.code_dialog import CodeDialog
from mui.dockwidgets.hook_list_widget import HookListWidget, HookType


class GlobalHookDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data
        self.ctr = 0

        QDialog.__init__(self, parent)

        self.setWindowTitle("Global Hooks")
        self.setMinimumSize(UIContext.getScaledWindowSize(400, 100))
        self.setAttribute(Qt.WA_DeleteOnClose)

        list_widget = QListWidget(self)
        list_widget.itemDoubleClicked.connect(self.item_double_click)
        self.list_widget = list_widget

        button_layout = QHBoxLayout()
        del_button = QPushButton("Delete")
        del_button.clicked.connect(lambda: self.del_hook())
        new_button = QPushButton("New Hook")
        new_button.clicked.connect(lambda: self.add_hook())
        button_layout.addStretch(1)
        button_layout.addWidget(del_button)
        button_layout.addWidget(new_button)
        button_layout.setContentsMargins(5, 5, 5, 5)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(list_widget)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.load_existing_hooks()

    def add_hook(self) -> None:
        """Add global hook"""
        name = f"global_{self.ctr:02d}"
        if self.edit_hook(name):
            item = QListWidgetItem(name, self.list_widget)
            self.ctr += 1

    def _del_list_item(self, item: QListWidgetItem) -> None:
        """Remove item from list"""
        row = 0
        list_widget = self.list_widget
        while row < list_widget.count():
            cur_item = list_widget.item(row)
            if cur_item == item:
                list_widget.takeItem(row)
                # Don't increment row
            else:
                row += 1

    def del_hook(self) -> None:
        """Delete currently selected global hook"""
        bv = self.bv
        hook_widget: HookListWidget = widget.get_dockwidget(bv, HookListWidget.NAME)
        row = 0
        list_widget = self.list_widget
        selected = list_widget.selectedItems()
        for item in selected:
            self._del_list_item(item)
            # Remove hook
            name = item.text()
            del bv.session_data.mui_global_hooks[name]
            hook_widget.remove_hook(HookType.GLOBAL, 0, name)

    @Slot(QListWidgetItem)
    def item_double_click(self, item: QListWidgetItem):
        """Edit global hook when double clicked"""
        name = item.text()
        if not self.edit_hook(name):
            self._del_list_item(item)

    def edit_hook(self, name) -> bool:
        """Edits global hook by name, returns False if hook code is empty (no hook)"""
        bv = self.bv
        dialog = CodeDialog(DockHandler.getActiveDockHandler().parent(), bv)
        hook_widget: HookListWidget = widget.get_dockwidget(bv, HookListWidget.NAME)

        if name in bv.session_data.mui_global_hooks:
            dialog.set_text(bv.session_data.mui_global_hooks[name])
        else:
            dialog.set_text(
                "\n".join(
                    [
                        "global bv,m",
                        "def hook(state):",
                        "    pass",
                        "m.hook(None)(hook)",
                    ]
                )
            )

        result: QDialog.DialogCode = dialog.exec()

        if result == QDialog.Accepted:
            if len(dialog.text()) == 0:
                # delete the hook if empty input is provided
                if name in bv.session_data.mui_global_hooks:
                    del bv.session_data.mui_global_hooks[name]
                    hook_widget.remove_hook(HookType.GLOBAL, 0, name)
                return False
            else:
                # add/edit the hook if input is non-empty
                # add to hook list if new
                if name not in bv.session_data.mui_global_hooks:
                    hook_widget.add_hook(HookType.GLOBAL, 0, name)
                bv.session_data.mui_global_hooks[name] = dialog.text()
                return True
        else:
            return name in bv.session_data.mui_global_hooks

    def load_existing_hooks(self) -> None:
        """Load existing global hooks into the UI"""
        bv = self.bv
        global_hooks = bv.session_data.mui_global_hooks
        if not global_hooks:
            return

        for name in global_hooks.keys():
            QListWidgetItem(name, self.list_widget)

        name = list(global_hooks.keys())[-1]
        self.ctr = int(name.split("_")[-1]) + 1
