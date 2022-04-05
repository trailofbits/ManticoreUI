from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QListWidget,
    QListWidgetItem,
    QLabel,
)
from binaryninja import (
    BinaryView,
)
from binaryninjaui import UIContext

from mui.utils import get_function_models, MUIFunctionModel


class FunctionModelDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data
        self._selected_model = ""

        QDialog.__init__(self, parent)

        self.setWindowTitle("Function Models")
        self.setMinimumSize(UIContext.getScaledWindowSize(400, 100))
        self.setAttribute(Qt.WA_DeleteOnClose)

        list_widget = QListWidget(self)
        list_widget.itemDoubleClicked.connect(self.item_double_click)
        self.list_widget = list_widget

        label = QLabel("Select a function model")
        label.setContentsMargins(5, 5, 5, 5)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(label)
        layout.addWidget(list_widget)

        self.setLayout(layout)

        self.list_function_models()

    def list_function_models(self) -> None:
        """Adds function models to the list"""
        list_widget = self.list_widget
        models = get_function_models()
        for model in models:
            item = QListWidgetItem(model.name, list_widget)

    @Slot(QListWidgetItem)
    def item_double_click(self, item: QListWidgetItem) -> None:
        """Selects item and close dialog"""
        self._selected_model = item.text()
        self.accept()

    def get_selected_model(self) -> str:
        """Returns name of selected function model"""
        return self._selected_model
