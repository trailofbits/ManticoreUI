from enum import Enum
from xmlrpc.client import Boolean
from binaryninja import BinaryView


class NativeHookType(Enum):
    FIND = 0
    AVOID = 1
    CUSTOM = 2


class NativeHooks:
    """Class to manage native hooks"""

    def __init__(self, bv: BinaryView) -> None:
        self.bv = bv
        self.deserialise_metadata()
        pass

    def add_hook(self, hook_type: NativeHookType, addr: int, code: str = "") -> None:
        if hook_type == NativeHookType.FIND:
            self.find.add(addr)
        elif hook_type == NativeHookType.AVOID:
            self.avoid.add(addr)
        elif hook_type == NativeHookType.CUSTOM:
            self.custom[addr] = code
        else:
            raise Exception("Added hook of invalid type")

    def del_hook(self, hook_type: NativeHookType, addr: int) -> None:
        if hook_type == NativeHookType.FIND:
            self.find.remove(addr)
        elif hook_type == NativeHookType.AVOID:
            self.avoid.remove(addr)
        elif hook_type == NativeHookType.CUSTOM:
            if addr in self.custom:
                del self.custom[addr]
        else:
            raise Exception("Deleting hook of invalid type")

    def has_hook(self, hook_type: NativeHookType, addr: int) -> Boolean:
        if hook_type == NativeHookType.FIND:
            return addr in self.find
        elif hook_type == NativeHookType.AVOID:
            return addr in self.avoid
        elif hook_type == NativeHookType.CUSTOM:
            return addr in self.custom
        else:
            raise Exception("Searching for hook of invalid type")

    def serialise_metadata(self) -> None:
        bv = self.bv
        bv.store_metadata("mui.hooks.find", list(self.find))
        bv.store_metadata("mui.hooks.avoid", list(self.avoid))
        bv.store_metadata("mui.hooks.custom", self.custom)

    def deserialise_metadata(self) -> None:
        bv = self.bv

        def get_metadata(key, default):
            try:
                return bv.query_metadata(key)
            except KeyError:
                return default

        self.find = set(get_metadata("mui.hooks.find", []))
        self.avoid = set(get_metadata("mui.hooks.avoid", []))
        custom = get_metadata("mui.hooks.custom", dict())
        self.custom = dict()
        for addr in custom.keys():
            self.custom[int(addr)] = custom[addr]
