from typing import Dict, List, Final

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QLabel,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QFormLayout,
    QFileDialog,
    QScrollArea,
    QCheckBox,
)
from binaryninja import (
    BinaryView,
    show_message_box,
    Settings,
    SettingsScope,
)
from binaryninjaui import UIContext

from mui.constants import BINJA_EVM_RUN_SETTINGS_PREFIX
from mui.dockwidgets.list_widget import ListWidget


class EVMRunDialog(QDialog):
    bool_options: Final[List[str]] = [
        "txnocoverage",
        "txnoether",
        "txpreconstrain",
        "no_testcases",
        "only_alive_testcases",
        "skip_reverts",
        "explore_balance",
        "verbose_trace",
        "limit_loops",
        "profile",
        "avoid_constant",
        "thorough_mode",
        "exclude_all",
    ]

    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data

        QDialog.__init__(self, parent)

        self.setWindowTitle("Run Manticore (EVM)")
        self.setMinimumSize(UIContext.getScaledWindowSize(600, 130))
        self.setAttribute(Qt.WA_DeleteOnClose)

        layout = QVBoxLayout()

        titleLabel = QLabel("Manticore Settings")
        titleLayout = QHBoxLayout()
        titleLayout.setContentsMargins(0, 0, 0, 0)
        titleLayout.addWidget(titleLabel)

        self.contract_name_entry = QLineEdit()
        self.txlimit_entry = QLineEdit()
        self.txaccount_entry = QLineEdit()

        self.workspace_url_entry = QLineEdit()
        self.workspace_url_entry.editingFinished.connect(lambda: self.apply())
        self.workspace_url_button = QPushButton("Select...")
        self.workspace_url_button.clicked.connect(lambda: self._select_workspace_url())
        workspace_url_layout = QHBoxLayout()
        workspace_url_layout.addWidget(self.workspace_url_entry)
        workspace_url_layout.addWidget(self.workspace_url_button)

        self.detectors_to_exclude_entry = ListWidget(validate_fun=lambda: self.apply())

        form_wrapper = QWidget()
        self.form_layout = QFormLayout(form_wrapper)
        self.form_layout.addRow("Workspace URL", workspace_url_layout)
        self.form_layout.addRow("Contract Name", self.contract_name_entry)
        self.form_layout.addRow("txlimit", self.txlimit_entry)
        self.form_layout.addRow("txaccount", self.txaccount_entry)
        self.form_layout.addRow("detectors_to_exclude", self.detectors_to_exclude_entry)

        self.bool_entries: Dict[str, QCheckBox] = {}
        for bool_option in EVMRunDialog.bool_options:
            self.bool_entries[bool_option] = QCheckBox()
            self.form_layout.addRow(bool_option, self.bool_entries[bool_option])
            self.bool_entries[bool_option].stateChanged.connect(lambda: self.apply())

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

        self.workspace_url_entry.setText(
            settings.get_string(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}workspace_url", self.bv)
        )

        self.contract_name_entry.setText(
            settings.get_string(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}contract_name", self.bv)
        )

        self.txlimit_entry.setText(
            str(int(settings.get_double(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txlimit", self.bv)))
        )

        self.txaccount_entry.setText(
            settings.get_string(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txaccount", self.bv)
        )

        self.detectors_to_exclude_entry.set_rows(
            settings.get_string_list(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}detectors_to_exclude", self.bv
            )
        )

        for bool_option in EVMRunDialog.bool_options:
            self.bool_entries[bool_option].setChecked(
                settings.get_bool(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}{bool_option}", self.bv)
            )

    def apply(self):
        try:
            settings = Settings()

            settings.set_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}workspace_url",
                self.workspace_url_entry.text(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )

            settings.set_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}contract_name",
                self.contract_name_entry.text(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )

            settings.set_double(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txlimit",
                int(self.txlimit_entry.text()),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )

            settings.set_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txaccount",
                self.txaccount_entry.text(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )

            settings.set_string_list(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}detectors_to_exclude",
                self.detectors_to_exclude_entry.get_results(),
                view=self.bv,
                scope=SettingsScope.SettingsResourceScope,
            )

            for bool_option in EVMRunDialog.bool_options:
                settings.set_bool(
                    f"{BINJA_EVM_RUN_SETTINGS_PREFIX}{bool_option}",
                    self.bool_entries[bool_option].isChecked(),
                    view=self.bv,
                    scope=SettingsScope.SettingsResourceScope,
                )

            self.acceptButton.setEnabled(True)
        except Exception as e:
            show_message_box("Invalid Run Options", str(e))
            self.acceptButton.setEnabled(False)
