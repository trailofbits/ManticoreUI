import json

from binaryninja import BinaryView, FileMetadata, Settings, HighlightStandardColor, SettingsScope
from binaryninjaui import UIContextNotification, UIContext, FileContext, ViewFrame

from mui.constants import BINJA_HOOK_SETTINGS_PREFIX
from mui.utils import highlight_instr


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

        # restore hook session_data from settings
        settings = Settings()
        bv.session_data.mui_find = set(
            json.loads(settings.get_string(f"{BINJA_HOOK_SETTINGS_PREFIX}find", bv))
        )
        bv.session_data.mui_avoid = set(
            json.loads(settings.get_string(f"{BINJA_HOOK_SETTINGS_PREFIX}avoid", bv))
        )
        bv.session_data.mui_custom_hooks = {
            int(key): item
            for key, item in json.loads(
                settings.get_string(f"{BINJA_HOOK_SETTINGS_PREFIX}custom", bv)
            ).items()
        }

        # restore highlight
        for addr in bv.session_data.mui_find:
            highlight_instr(bv, addr, HighlightStandardColor.GreenHighlightColor)
        for addr in bv.session_data.mui_avoid:
            highlight_instr(bv, addr, HighlightStandardColor.RedHighlightColor)
        for addr in bv.session_data.mui_custom_hooks.keys():
            highlight_instr(bv, addr, HighlightStandardColor.BlueHighlightColor)

    def OnBeforeSaveFile(self, context: UIContext, file: FileContext, frame: ViewFrame) -> bool:
        """Update settings to reflect the latest session_data"""

        bv: BinaryView = frame.getCurrentBinaryView()
        settings = Settings()

        settings.set_string(
            f"{BINJA_HOOK_SETTINGS_PREFIX}find",
            json.dumps(list(bv.session_data.mui_find)),
            view=bv,
            scope=SettingsScope.SettingsResourceScope,
        )

        settings.set_string(
            f"{BINJA_HOOK_SETTINGS_PREFIX}avoid",
            json.dumps(list(bv.session_data.mui_avoid)),
            view=bv,
            scope=SettingsScope.SettingsResourceScope,
        )

        settings.set_string(
            f"{BINJA_HOOK_SETTINGS_PREFIX}custom",
            json.dumps(bv.session_data.mui_custom_hooks),
            view=bv,
            scope=SettingsScope.SettingsResourceScope,
        )

        return True
