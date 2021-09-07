from typing import Callable, List

from PySide6.QtWidgets import QVBoxLayout, QWidget, QPushButton, QHBoxLayout, QLineEdit


class ListWidget(QWidget):
    def __init__(
        self,
        parent: QWidget = None,
        initial_row_count: int = 0,
        validate_fun: Callable[[], None] = lambda: None,
    ):
        QWidget.__init__(self, parent)
        self.validate_fun = validate_fun

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
        row = QHBoxLayout()
        line_edit = QLineEdit()
        line_edit.editingFinished.connect(lambda: self.validate_fun())
        btn = QPushButton("-")
        row.addWidget(line_edit)
        row.addWidget(btn)

        btn.clicked.connect(lambda: [x.setParent(None) for x in [line_edit, btn, row]])

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
            row.itemAt(0).widget().setText(values[idx])
            idx += 1

    def get_results(self) -> List[str]:
        "Get all non-empty row inputs as a string array"
        output = []
        for row in self.row_layout.children():
            text = row.itemAt(0).widget().text()
            if text != "":
                output.append(text)
        return output
