from typing import Callable, List, Optional

from PySide6.QtCore import QObject
from PySide6.QtWidgets import QVBoxLayout, QWidget, QPushButton, QHBoxLayout, QLineEdit, QComboBox


class ListWidget(QWidget):
    def __init__(
        self,
        parent: QWidget = None,
        possible_values: Optional[List[str]] = None,
        allow_repeats: bool = True,
        initial_row_count: int = 0,
        validate_fun: Callable[[], None] = lambda: None,
    ):
        QWidget.__init__(self, parent)
        self.validate_fun = validate_fun
        self.possible_values = possible_values
        self.allow_repeats = allow_repeats

        self.row_layout = QVBoxLayout()

        for i in range(initial_row_count):
            self.add_row()

        add_btn = QPushButton("+")
        add_btn.clicked.connect(lambda: self.add_row())

        layout = QVBoxLayout()
        layout.addLayout(self.row_layout)
        layout.addWidget(add_btn)

        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def add_row(self):
        """Adds a new row to the current widget"""

        if self.possible_values is None:
            input = QLineEdit()
            input.editingFinished.connect(lambda: self.validate_fun())
        else:
            input = QComboBox()

            if self.allow_repeats:
                input.addItems(self.possible_values)
            else:
                input.addItems(sorted(set(self.possible_values) - set(self.get_results())))

            input.currentIndexChanged.connect(self._on_index_change)

        btn = QPushButton("-")
        btn.setMaximumWidth(20)

        row = QHBoxLayout()
        row.addWidget(input)
        row.addWidget(btn)

        btn.clicked.connect(lambda: self._on_remove_row([input, btn, row]))

        self.row_layout.addLayout(row)

        if not self.allow_repeats:
            self._remove_repeats()

    def _on_remove_row(self, elements_to_remove: List[QObject]):
        """Remove a row from the list"""

        for x in elements_to_remove:
            x.setParent(None)
            x.deleteLater()

        if not self.allow_repeats:
            self._remove_repeats()

    def _on_index_change(self):
        """Handle index change"""

        self.validate_fun()

        if not self.allow_repeats:
            self._remove_repeats()

    def _remove_repeats(self):
        """Update the available options for each row to prevent repeats"""

        assert self.possible_values is not None
        assert not self.allow_repeats

        not_selected = set(self.possible_values) - set(self.get_results())
        for row in self.row_layout.children():
            combobox: QComboBox = row.itemAt(0).widget()
            curr_text = combobox.currentText()

            # need to disable the event listener temporarily in order to
            # prevent the same method being called recursively
            combobox.currentIndexChanged.disconnect(self._on_index_change)

            combobox.clear()
            combobox.addItems(sorted(not_selected | {curr_text}))
            combobox.setCurrentIndex(combobox.findText(curr_text))

            combobox.currentIndexChanged.connect(self._on_index_change)

    def set_rows(self, values: List[str]):
        """Sets the rows to given values. Adds and removes rows when needed"""

        values_len = len(values)
        curr_row_count = len(self.row_layout.children())

        # adjust row count
        if values_len > curr_row_count:
            for _ in range(values_len - curr_row_count):
                self.add_row()
        elif values_len < curr_row_count:
            for _ in range(curr_row_count - values_len):
                last_row = self.row_layout.children()[-1]
                last_row.itemAt(1).widget().click()

        # set values
        idx = 0
        for row in self.row_layout.children():
            if self.possible_values is None:
                row.itemAt(0).widget().setText(values[idx])
            else:
                if values[idx] in self.possible_values:
                    row.itemAt(0).widget().setCurrentIndex(self.possible_values.index(values[idx]))
            idx += 1

    def get_results(self) -> List[str]:
        "Get all non-empty row inputs as a string array"
        output = []
        for row in self.row_layout.children():
            if self.possible_values is None:
                text = row.itemAt(0).widget().text()
            else:
                text = row.itemAt(0).widget().currentText()

            if text != "":
                output.append(text)
        return output
