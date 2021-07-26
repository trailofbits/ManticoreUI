import shlex

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
)
from binaryninja import BinaryView, show_message_box, MessageBoxButtonSet, MessageBoxIcon
from binaryninjaui import UIContext


class RunDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data

        self.bv.set_default_session_data("mui_run_args", {})

        QDialog.__init__(self, parent)

        self.setWindowTitle("Run Manticore")
        self.setMinimumSize(UIContext.getScaledWindowSize(400, 130))
        self.setAttribute(Qt.WA_DeleteOnClose)

        layout = QVBoxLayout()

        titleLabel = QLabel("Manticore Settings")
        titleLayout = QHBoxLayout()
        titleLayout.setContentsMargins(0, 0, 0, 0)
        titleLayout.addWidget(titleLabel)

        self.concrete_start_entry = QLineEdit(self)
        self.stdin_size_entry = QLineEdit(self)
        self.argv_entry = QLineEdit(self)
        self.workspace_url_entry = QLineEdit(self)

        self.formLayout = QFormLayout()
        self.formLayout.addRow(
            "Concrete stdin to use before symbolic input", self.concrete_start_entry
        )
        self.formLayout.addRow("Symbolic stdin size to use", self.stdin_size_entry)
        self.formLayout.addRow("Program arguments (use + as a wildcard)", self.argv_entry)
        self.formLayout.addRow("Workspace URL", self.workspace_url_entry)

        self.stdin_size_entry.setText("256")
        self.workspace_url_entry.setText("mem:")

        self.concrete_start_entry.editingFinished.connect(lambda: self.apply())
        self.stdin_size_entry.editingFinished.connect(lambda: self.apply())
        self.argv_entry.editingFinished.connect(lambda: self.apply())
        self.workspace_url_entry.editingFinished.connect(lambda: self.apply())

        buttonLayout = QHBoxLayout()
        # buttonLayout.setContentsMargins(0, 0, 0, 0)
        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(lambda: self.reject())
        self.acceptButton = QPushButton("Accept")
        self.acceptButton.clicked.connect(lambda: self.accept())
        self.acceptButton.setDefault(True)
        buttonLayout.addStretch(1)
        buttonLayout.addWidget(self.cancelButton)
        buttonLayout.addWidget(self.acceptButton)

        layout.addLayout(titleLayout)
        layout.addSpacing(10)
        layout.addLayout(self.formLayout)
        layout.addStretch(1)
        layout.addSpacing(10)
        layout.addLayout(buttonLayout)

        self.setLayout(layout)

        self.accepted.connect(lambda: self.apply())

    def apply(self):
        try:
            self.bv.session_data.mui_run_args["argv"] = shlex.split(self.argv_entry.text())
            self.bv.session_data.mui_run_args["concrete_start"] = self.concrete_start_entry.text()
            self.bv.session_data.mui_run_args["stdin_size"] = int(self.stdin_size_entry.text())
            self.bv.session_data.mui_run_args["workspace_url"] = self.workspace_url_entry.text()
            self.acceptButton.setEnabled(True)
        except Exception as e:
            show_message_box("Invalid Run Options", str(e))
            self.acceptButton.setEnabled(False)
