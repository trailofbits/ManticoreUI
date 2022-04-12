import json

from binaryninja import BinaryView, FileMetadata, Settings, HighlightStandardColor, SettingsScope
from binaryninjaui import UIContextNotification, UIContext, FileContext, ViewFrame

from mui.constants import BINJA_HOOK_SETTINGS_PREFIX, BINJA_NATIVE_RUN_SETTINGS_PREFIX
from mui.hook_manager import NativeHookManager
from mui.utils import highlight_instr
from mui.dockwidgets.hook_list_widget import HookListWidget
from mui.dockwidgets import widget


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

        # initialise hook manager
        hook_widget: HookListWidget = widget.get_dockwidget(bv, HookListWidget.NAME)

        mgr = NativeHookManager(bv, hook_widget)
        bv.session_data.mui_hook_mgr = mgr
        mgr.load_existing_hooks()

        # restore highlight
        for addr in mgr.list_find_hooks():
            highlight_instr(bv, addr, HighlightStandardColor.GreenHighlightColor)
        for addr in mgr.list_avoid_hooks():
            highlight_instr(bv, addr, HighlightStandardColor.RedHighlightColor)
        for addr in mgr.list_custom_hooks():
            highlight_instr(bv, addr, HighlightStandardColor.BlueHighlightColor)

        # restore shared libraries
        settings = Settings()
        libs = set(
            json.loads(
                settings.get_string(f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}sharedLibraries", bv)
            )
        )
        bv.session_data.mui_libs = libs

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

        settings.set_string(
            f"{BINJA_HOOK_SETTINGS_PREFIX}global",
            json.dumps(bv.session_data.mui_global_hooks),
            view=bv,
            scope=SettingsScope.SettingsResourceScope,
        )

        return True
