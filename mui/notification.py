import json

from binaryninja import BinaryView, FileMetadata, Settings, HighlightStandardColor, SettingsScope
from binaryninjaui import UIContextNotification, UIContext, FileContext, ViewFrame

from mui.constants import BINJA_HOOK_SETTINGS_PREFIX
from mui.utils import highlight_instr
from mui.native_hooks import NativeHooks


class UINotification(UIContextNotification):
    """
    This class allows us to monitor various UI events and add listeners.
    """

    def __init__(self):
        UIContextNotification.__init__(self)
        UIContext.registerNotification(self)

    def __del__(self):
        UIContext.unregisterNotification(self)

    def OnAfterOpenFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> None:
        """Restore existing settings right after file open"""

        bv: BinaryView = frame.getCurrentBinaryView()

        # Initialise hooks
        hooks = NativeHooks(bv)
        bv.session_data.hooks = hooks

        # restore highlight
        for addr in hooks.find:
            highlight_instr(bv, addr, HighlightStandardColor.GreenHighlightColor)
        for addr in hooks.avoid:
            highlight_instr(bv, addr, HighlightStandardColor.RedHighlightColor)
        for addr in hooks.custom.keys():
            highlight_instr(bv, addr, HighlightStandardColor.BlueHighlightColor)

    def OnBeforeSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> bool:
        """Update settings to reflect the latest session_data"""

        bv: BinaryView = frame.getCurrentBinaryView()

        # Save to bndb
        bv.session_data.hooks.serialise_metadata()

        return True
