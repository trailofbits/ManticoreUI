import json
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QFileDialog,
    QLabel,
)
from binaryninja import (
    BinaryView,
    Settings,
    SettingsScope,
)
from binaryninjaui import UIContext
from mui.constants import BINJA_NATIVE_RUN_SETTINGS_PREFIX


class LibraryDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data
        self.items: frozenset = frozenset()

        QDialog.__init__(self, parent)

        self.setWindowTitle("Shared Libraries")
        self.setMinimumSize(UIContext.getScaledWindowSize(400, 100))
        self.setAttribute(Qt.WA_DeleteOnClose)

        list_widget = QListWidget(self)
        self.list_widget = list_widget

        button_layout = QHBoxLayout()
        del_button = QPushButton("Delete")
        del_button.clicked.connect(lambda: self.del_lib())
        add_button = QPushButton("Add")
        add_button.clicked.connect(lambda: self.add_lib())
        button_layout.addStretch(1)
        button_layout.addWidget(del_button)
        button_layout.addWidget(add_button)
        button_layout.setContentsMargins(5, 5, 5, 5)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(list_widget)
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.update_items()

    def update_items(self) -> None:
        """Update missing items into list"""
        updated = self.bv.session_data.mui_libs
        diff = updated.difference(self.items)
        if diff:
            self.items = frozenset(updated)
            for lib in diff:
                item = QListWidgetItem(lib, self.list_widget)
            self.update_settings()

    def add_lib(self) -> None:
        """Prompt bndb selection and add to libs"""
        filename, _ = QFileDialog.getOpenFileName(
            None, "Open shared library project", "", "Binary Ninja database files (*.bndb)"
        )
        if filename:
            self.bv.session_data.mui_libs.add(filename)
            self.update_items()

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

    def del_lib(self) -> None:
        """Delete currently selected lib"""
        list_widget = self.list_widget
        selected = list_widget.selectedItems()
        for item in selected:
            self._del_list_item(item)
            self.bv.session_data.mui_libs.remove(item.text())
            self.update_settings()

    def update_settings(self) -> None:
        settings = Settings()
        settings.set_string(
            f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}sharedLibraries",
            json.dumps(list(self.bv.session_data.mui_libs)),
            view=self.bv,
            scope=SettingsScope.SettingsResourceScope,
        )
