import shlex
from typing import List, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QLabel,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QCheckBox,
    QFormLayout,
    QFileDialog,
    QScrollArea,
    QLayout,
)
from binaryninja import BinaryView, show_message_box, MessageBoxButtonSet, MessageBoxIcon
from binaryninjaui import UIContext


class ListWidget(QWidget):
    def __init__(
        self,
        parent: QWidget = None,
        initial_row_count: int = 0,
        validate_fun: Callable = lambda: None,
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

    def get_results(self) -> List[str]:
        "Get all non-empty row inputs as a string array"
        output = []
        for row in self.row_layout.children():
            text = row.itemAt(0).widget().text()
            if text != "":
                output.append(text)
        return output


class RunDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data

        self.bv.set_default_session_data("mui_run_args", {})

        QDialog.__init__(self, parent)

        self.setWindowTitle("Run Manticore")
        self.setMinimumSize(UIContext.getScaledWindowSize(600, 130))
        self.setAttribute(Qt.WA_DeleteOnClose)

        layout = QVBoxLayout()

        titleLabel = QLabel("Manticore Settings")
        titleLayout = QHBoxLayout()
        titleLayout.setContentsMargins(0, 0, 0, 0)
        titleLayout.addWidget(titleLabel)

        self.concrete_start_entry = QLineEdit()
        self.stdin_size_entry = QLineEdit()
        self.argv_entry = QLineEdit()

        self.workspace_url_entry = QLineEdit()
        self.workspace_url_button = QPushButton("Select...")
        workspace_url_layout = QHBoxLayout()
        workspace_url_layout.addWidget(self.workspace_url_entry)
        workspace_url_layout.addWidget(self.workspace_url_button)

        self.env_entry = ListWidget(validate_fun=lambda: self.apply())
        self.symbolic_files_entry = ListWidget(validate_fun=lambda: self.apply())

        form_wrapper = QWidget()
        self.form_layout = QFormLayout(form_wrapper)
        self.form_layout.addRow(
            "Concrete stdin to use before symbolic input", self.concrete_start_entry
        )
        self.form_layout.addRow("Symbolic stdin size to use", self.stdin_size_entry)
        self.form_layout.addRow("Program arguments (use + as a wildcard)", self.argv_entry)
        self.form_layout.addRow("Workspace URL", workspace_url_layout)
        self.form_layout.addRow("Add environment variables", self.env_entry)
        self.form_layout.addRow("Specify symbolic input file", self.symbolic_files_entry)

        self.stdin_size_entry.setText("256")
        self.workspace_url_entry.setText("mem:")

        self.concrete_start_entry.editingFinished.connect(lambda: self.apply())
        self.stdin_size_entry.editingFinished.connect(lambda: self.apply())
        self.argv_entry.editingFinished.connect(lambda: self.apply())
        self.workspace_url_entry.editingFinished.connect(lambda: self.apply())
        self.workspace_url_button.clicked.connect(lambda: self._select_workspace_url())

        buttonLayout = QHBoxLayout()
        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(lambda: self.reject())
        self.acceptButton = QPushButton("Accept")
        self.acceptButton.clicked.connect(lambda: self.accept())
        self.acceptButton.setDefault(True)
        buttonLayout.addStretch(1)
        buttonLayout.addWidget(self.cancelButton)
        buttonLayout.addWidget(self.acceptButton)

        scroll_area = QScrollArea()
        scroll_area.setWidget(form_wrapper)
        scroll_area.setWidgetResizable(True)

        layout.addLayout(titleLayout)
        layout.addSpacing(10)
        layout.addWidget(scroll_area)
        # layout.addStretch(1)
        layout.addSpacing(10)
        layout.addLayout(buttonLayout)

        self.setLayout(layout)

        self.accepted.connect(lambda: self.apply())

    def _select_workspace_url(self):
        file_url = QFileDialog.getExistingDirectory(self, "Select Workspace Directory")
        if file_url != "":
            self.workspace_url_entry.setText(file_url)

    def apply(self):
        try:
            self.bv.session_data.mui_run_args["argv"] = shlex.split(self.argv_entry.text())
            self.bv.session_data.mui_run_args["concrete_start"] = self.concrete_start_entry.text()
            self.bv.session_data.mui_run_args["stdin_size"] = int(self.stdin_size_entry.text())
            self.bv.session_data.mui_run_args["workspace_url"] = self.workspace_url_entry.text()
            self.bv.session_data.mui_run_args["env"] = {
                key: val for key, val in [env.split("=") for env in self.env_entry.get_results()]
            }
            self.bv.session_data.mui_run_args[
                "symbolic_files"
            ] = self.symbolic_files_entry.get_results()

            self.acceptButton.setEnabled(True)
        except Exception as e:
            show_message_box("Invalid Run Options", str(e))
            self.acceptButton.setEnabled(False)
