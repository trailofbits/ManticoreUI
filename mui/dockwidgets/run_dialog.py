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
from binaryninja import (
    BinaryView,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    Settings,
    SettingsScope,
)
from binaryninjaui import UIContext


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


class RunDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data

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

        self._try_restore_options()

    def _select_workspace_url(self):
        file_url = QFileDialog.getExistingDirectory(self, "Select Workspace Directory")
        if file_url != "":
            self.workspace_url_entry.setText(file_url)

    def _try_restore_options(self):
        """Try restoring run options if they are set before"""

        settings = Settings()
        prefix = "mui.run."

        self.argv_entry.setText(shlex.join(settings.get_string_list(f"{prefix}argv", self.bv)))
        self.concrete_start_entry.setText(settings.get_string(f"{prefix}concreteStart", self.bv))
        self.stdin_size_entry.setText(str(settings.get_integer(f"{prefix}stdinSize", self.bv)))
        self.workspace_url_entry.setText(settings.get_string(f"{prefix}workspaceURL", self.bv))
        self.env_entry.set_rows(settings.get_string_list(f"{prefix}env", self.bv))
        self.symbolic_files_entry.set_rows(
            settings.get_string_list(f"{prefix}symbolicFiles", self.bv)
        )
        # [f"{key}={val}" for key, val in run_args["env"].items()]

    def apply(self):
        try:
            settings = Settings()
            prefix = "mui.run."

            settings.set_string_list(
                f"{prefix}argv",
                shlex.split(self.argv_entry.text()),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            settings.set_string(
                f"{prefix}concreteStart",
                self.concrete_start_entry.text(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            settings.set_integer(
                f"{prefix}stdinSize",
                int(self.stdin_size_entry.text()),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            settings.set_string(
                f"{prefix}workspaceURL",
                self.workspace_url_entry.text(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            settings.set_string_list(
                f"{prefix}env",
                self.env_entry.get_results(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            settings.set_string_list(
                f"{prefix}symbolicFiles",
                self.symbolic_files_entry.get_results(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )
            #  = {key: val for key, val in [env.split("=") for env in }

            self.acceptButton.setEnabled(True)
        except Exception as e:
            show_message_box("Invalid Run Options", str(e))
            self.acceptButton.setEnabled(False)
