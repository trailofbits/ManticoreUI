from typing import Callable, List, Optional

from PySide6.QtWidgets import QVBoxLayout, QWidget, QPushButton, QHBoxLayout, QLineEdit, QComboBox


class ListWidget(QWidget):
    def __init__(
        self,
        parent: QWidget = None,
        possible_values: Optional[List[str]] = None,
        initial_row_count: int = 0,
        validate_fun: Callable[[], None] = lambda: None,
    ):
        QWidget.__init__(self, parent)
        self.validate_fun = validate_fun
        self.possible_values = possible_values

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
            input.addItems(self.possible_values)
            input.currentIndexChanged.connect(lambda: self.validate_fun())

        btn = QPushButton("-")
        btn.setMaximumWidth(20)

        row = QHBoxLayout()
        row.addWidget(input)
        row.addWidget(btn)

        btn.clicked.connect(lambda: [x.deleteLater() for x in [input, btn, row]])

        self.row_layout.addLayout(row)

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
