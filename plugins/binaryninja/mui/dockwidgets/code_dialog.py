import typing

from binaryninjaui import UIContext
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from binaryninja import BinaryView
from mui.dockwidgets.QCodeEditor import Pylighter, QCodeEditor


class CodeDialog(QDialog):
    def __init__(self, parent: QWidget, data: BinaryView):
        self.bv = data
        self.output_text: typing.Optional[str] = None

        QDialog.__init__(self, parent)

        self.setWindowTitle("Custom Hook")
        self.setMinimumSize(UIContext.getScaledWindowSize(600, 130))
        self.setAttribute(Qt.WA_DeleteOnClose)

        layout = QVBoxLayout()

        self.editor = QCodeEditor(SyntaxHighlighter=Pylighter, delimeter="    ")
        self.editor.setPlainText(
            "\n".join(
                [
                    "global bv,m,addr",
                    "def hook(state):",
                    "    print('custom hook reached')",
                    "    print(bv)",
                    "m.hook(addr)(hook)",
                ]
            )
        )

        buttonLayout = QHBoxLayout()
        self.cancelButton = QPushButton("Cancel")
        self.cancelButton.clicked.connect(lambda: self.reject())
        self.acceptButton = QPushButton("Accept")
        self.acceptButton.clicked.connect(lambda: self.accept())
        self.acceptButton.setDefault(True)
        buttonLayout.addStretch(1)
        buttonLayout.addWidget(self.cancelButton)
        buttonLayout.addWidget(self.acceptButton)

        layout.addWidget(self.editor)
        layout.addSpacing(10)
        layout.addLayout(buttonLayout)

        self.setLayout(layout)

    def accept(self) -> None:
        self.output_text = self.editor.toPlainText()
        super().accept()

    def text(self) -> typing.Optional[str]:
        """Get editor text"""
        return self.output_text

    def set_text(self, text: str) -> None:
        self.editor.setPlainText(text)
