from typing import Dict

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
    QComboBox,
)
from binaryninja import (
    BinaryView,
    show_message_box,
    Settings,
    SettingsScope,
)
from binaryninjaui import UIContext

from mui.dockwidgets.list_widget import ListWidget
from mui.settings import MUISettings


class RunDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView, prefix: str):
        self.bv = data
        self.entries: Dict[str, QWidget] = {}
        self.initialized = False
        self.prefix = prefix

        QDialog.__init__(self, parent)

        self.setWindowTitle("Run Manticore")
        self.setMinimumSize(UIContext.getScaledWindowSize(600, 130))
        self.setAttribute(Qt.WA_DeleteOnClose)

        layout = QVBoxLayout()

        titleLabel = QLabel("Manticore Settings")
        titleLayout = QHBoxLayout()
        titleLayout.setContentsMargins(0, 0, 0, 0)
        titleLayout.addWidget(titleLabel)

        form_wrapper = QWidget()
        self.form_layout = QFormLayout(form_wrapper)
        for name, (prop, extra) in MUISettings.SETTINGS[prefix].items():
            title = prop["title"]
            label = QLabel(title)
            label.setToolTip(prop["description"])
            if "is_dir_path" in extra and extra["is_dir_path"]:
                entry = QLineEdit()
                entry.editingFinished.connect(lambda: self.apply())
                button = QPushButton("Select...")

                # the default parameter here is used for reference capture
                button.clicked.connect(
                    lambda _=None, entry=entry: self._select_path(title, entry, select_dir=True)
                )

                item = QHBoxLayout()
                item.addWidget(entry)
                item.addWidget(button)

                self.entries[name] = entry
            elif "is_file_path" in extra and extra["is_file_path"]:
                entry = QLineEdit()
                entry.editingFinished.connect(lambda: self.apply())
                button = QPushButton("Select...")

                # the default parameter here is used for reference capture
                button.clicked.connect(
                    lambda _=None, entry=entry: self._select_path(title, entry, select_dir=False)
                )

                item = QHBoxLayout()
                item.addWidget(entry)
                item.addWidget(button)

                self.entries[name] = entry
            elif prop["type"] in ["string", "number"]:

                if "possible_values" in extra:
                    item = QComboBox()
                    item.addItems([str(val) for val in extra["possible_values"]])
                    item.currentIndexChanged.connect(lambda: self.apply())
                else:
                    item = QLineEdit()
                    item.editingFinished.connect(lambda: self.apply())

                self.entries[name] = item
            elif prop["type"] == "boolean":
                item = QCheckBox()
                item.stateChanged.connect(lambda: self.apply())
                self.entries[name] = item
            elif prop["type"] == "array":
                item = ListWidget(
                    validate_fun=lambda: self.apply(),
                    possible_values=extra["possible_values"]
                    if "possible_values" in extra
                    else None,
                    allow_repeats=extra["allow_repeats"] if "allow_repeats" in extra else True,
                )
                self.entries[name] = item
            else:
                show_message_box(
                    "Error",
                    f"[ERROR] Cannot create input row for {name} with the type {prop['type']}",
                )
                item = QLabel("...")
            self.form_layout.addRow(label, item)

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
        self.initialized = True

    def _select_path(self, name: str, widget: QLineEdit, select_dir: bool = True):
        if select_dir:
            selected_url = QFileDialog.getExistingDirectory(self, f"Select {name} Directory")
        else:
            selected_url = QFileDialog.getOpenFileName(self, f"Select {name} File")[0]
        if selected_url != "":
            widget.setText(selected_url)

    def _try_restore_options(self):
        """Try restoring run options if they are set before"""

        settings = Settings()
        for name, (prop, extra) in MUISettings.SETTINGS[self.prefix].items():
            if prop["type"] == "string":
                value = settings.get_string(f"{self.prefix}{name}", self.bv)

                if "possible_values" in extra:
                    if value in extra["possible_values"]:
                        self.entries[name].setCurrentIndex(extra["possible_values"].index(value))
                else:
                    self.entries[name].setText(value)
            elif prop["type"] == "number":
                # get_integer can only be used for positive integers, so using get_double as a workaround
                value = int(settings.get_double(f"{self.prefix}{name}", self.bv))

                self.entries[name].setText(str(value))

            elif prop["type"] == "array":
                self.entries[name].set_rows(
                    settings.get_string_list(f"{self.prefix}{name}", self.bv)
                )
            elif prop["type"] == "boolean":
                self.entries[name].setChecked(settings.get_bool(f"{self.prefix}{name}", self.bv))

    def apply(self):
        """Validate inputs and save them to settings"""

        # Do not want this function to be called when restoring options during init
        if not self.initialized:
            return

        try:
            settings = Settings()
            for name, (prop, extra) in MUISettings.SETTINGS[self.prefix].items():
                if prop["type"] == "string":

                    if "possible_values" in extra:
                        value = self.entries[name].currentText()
                    else:
                        value = self.entries[name].text()

                    settings.set_string(
                        f"{self.prefix}{name}",
                        value,
                        view=self.bv,
                        scope=SettingsScope.SettingsResourceScope,
                    )
                elif prop["type"] == "number":

                    # set_integer can only be used for positive integers, so using set_double as a workaround
                    settings.set_double(
                        f"{self.prefix}{name}",
                        int(self.entries[name].text()),
                        view=self.bv,
                        scope=SettingsScope.SettingsResourceScope,
                    )

                elif prop["type"] == "array":
                    settings.set_string_list(
                        f"{self.prefix}{name}",
                        self.entries[name].get_results(),
                        view=self.bv,
                        scope=SettingsScope.SettingsResourceScope,
                    )
                elif prop["type"] == "boolean":
                    settings.set_bool(
                        f"{self.prefix}{name}",
                        self.entries[name].isChecked(),
                        view=self.bv,
                        scope=SettingsScope.SettingsResourceScope,
                    )

            self.acceptButton.setEnabled(True)
        except Exception as e:
            show_message_box("Invalid Run Options", str(e))
            self.acceptButton.setEnabled(False)
