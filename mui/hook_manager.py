import json
from typing import List, Set, Dict, Optional
from binaryninja import (
    Settings,
    SettingsScope,
    BinaryView,
    HighlightStandardColor,
)
from mui.constants import BINJA_HOOK_SETTINGS_PREFIX
from mui.dockwidgets.hook_list_widget import HookListWidget, HookType
from mui.utils import clear_highlight, highlight_instr

from muicore.MUICore_pb2 import Hook


class NativeHookManager:
    """Class to manage mui hooks associated with a specific binary view (bv)"""

    def __init__(self, bv: BinaryView, widget: Optional[HookListWidget] = None):
        self.bv = bv
        self.widget = widget

    # Add
    def add_find_hook(self, addr: int) -> None:
        bv = self.bv
        bv.session_data.mui_find.add(addr)
        highlight_instr(bv, addr, HighlightStandardColor.GreenHighlightColor)
        if self.widget:
            self.widget.add_hook(HookType.FIND, addr)

    def add_avoid_hook(self, addr: int) -> None:
        bv = self.bv
        bv.session_data.mui_avoid.add(addr)
        highlight_instr(bv, addr, HighlightStandardColor.RedHighlightColor)
        if self.widget:
            self.widget.add_hook(HookType.AVOID, addr)

    def add_custom_hook(self, addr: int, code: str) -> None:
        bv = self.bv
        bv.session_data.mui_custom_hooks[addr] = code
        highlight_instr(bv, addr, HighlightStandardColor.BlueHighlightColor)
        if self.widget:
            self.widget.add_hook(HookType.CUSTOM, addr)

    def add_global_hook(self, name: str, code: str) -> None:
        self.bv.session_data.mui_global_hooks[name] = code
        if self.widget:
            self.widget.add_hook(HookType.GLOBAL, 0, name)

    # Delete
    def del_find_hook(self, addr: int) -> None:
        bv = self.bv
        bv.session_data.mui_find.remove(addr)
        clear_highlight(bv, addr)
        if self.widget:
            self.widget.remove_hook(HookType.FIND, addr)

    def del_avoid_hook(self, addr: int) -> None:
        bv = self.bv
        bv.session_data.mui_avoid.remove(addr)
        clear_highlight(bv, addr)
        if self.widget:
            self.widget.remove_hook(HookType.AVOID, addr)

    def del_custom_hook(self, addr: int) -> None:
        bv = self.bv
        del bv.session_data.mui_custom_hooks[addr]
        clear_highlight(bv, addr)
        if self.widget:
            self.widget.remove_hook(HookType.CUSTOM, addr)

    def del_global_hook(self, name: str) -> None:
        del self.bv.session_data.mui_global_hooks[name]
        if self.widget:
            self.widget.remove_hook(HookType.GLOBAL, 0, name)

    # Has
    def has_find_hook(self, addr: int) -> bool:
        return addr in self.bv.session_data.mui_find

    def has_avoid_hook(self, addr: int) -> bool:
        return addr in self.bv.session_data.mui_avoid

    def has_custom_hook(self, addr: int) -> bool:
        return addr in self.bv.session_data.mui_custom_hooks

    def has_global_hook(self, name: str) -> bool:
        return name in self.bv.session_data.mui_global_hooks

    # Get
    def get_custom_hook(self, addr: int) -> str:
        return self.bv.session_data.mui_custom_hooks.get(addr, "")

    def get_global_hook(self, name: str) -> str:
        return self.bv.session_data.mui_global_hooks.get(name, "")

    # List
    def list_find_hooks(self) -> Set[int]:
        return self.bv.session_data.mui_find

    def list_avoid_hooks(self) -> Set[int]:
        return self.bv.session_data.mui_avoid

    def list_custom_hooks(self) -> Dict[int, str]:
        return self.bv.session_data.mui_custom_hooks

    def list_global_hooks(self) -> Dict[str, str]:
        return self.bv.session_data.mui_global_hooks

    def load_existing_hooks(self) -> None:
        """restore hook session_data from settings"""
        bv = self.bv
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
        bv.session_data.mui_global_hooks = {
            key: item
            for key, item in json.loads(
                settings.get_string(f"{BINJA_HOOK_SETTINGS_PREFIX}global", bv)
            ).items()
        }

        # Update hook list widget if present
        if self.widget:
            for addr in self.list_find_hooks():
                self.widget.add_hook(HookType.FIND, addr)

            for addr in self.list_avoid_hooks():
                self.widget.add_hook(HookType.AVOID, addr)

            for addr in self.list_custom_hooks():
                self.widget.add_hook(HookType.CUSTOM, addr)

            for name in self.list_global_hooks():
                self.widget.add_hook(HookType.GLOBAL, 0, name)

            self.widget.set_manager(self)

    def save_hooks(self) -> None:
        """store hook session_data into settings for persistence"""
        bv = self.bv
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

    def list_hooks_for_server(self) -> List[Hook]:
        hook_list = []
        hook_list.extend(
            list(
                map(
                    lambda addr: Hook(type=Hook.HookType.FIND, address=addr), self.list_find_hooks()
                )
            )
        )
        hook_list.extend(
            list(
                map(
                    lambda addr: Hook(type=Hook.HookType.AVOID, address=addr),
                    self.list_avoid_hooks(),
                )
            )
        )
        hook_list.extend(
            list(
                map(
                    lambda dat: Hook(type=Hook.HookType.CUSTOM, address=dat[0], func_text=dat[1]),
                    self.list_custom_hooks().items(),
                )
            )
        )
        hook_list.extend(
            list(
                map(
                    lambda dat: Hook(type=Hook.HookType.CUSTOM, func_text=dat[1]),
                    self.list_global_hooks().items(),
                )
            )
        )
        return hook_list
