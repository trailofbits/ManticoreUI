from typing import Callable
from os.path import realpath
from manticore.core.plugin import Plugin
from mui.hook_manager import NativeHookManager


class RebaseHooksPlugin(Plugin):
    def __init__(self, mgr: NativeHookManager, find_f: Callable, avoid_f: Callable):
        super().__init__()
        self.find_f = find_f
        self.avoid_f = avoid_f
        self.filename = mgr.bv.file.original_filename
        self.base = 0
        self.loaded = False

        # Hooks
        self.find = mgr.list_find_hooks()
        self.avoid = mgr.list_avoid_hooks()
        self.custom_hooks = [(addr, func) for addr, func in mgr.list_custom_hooks().items()]
        self.global_hooks = list(mgr.list_global_hooks().values())

    def on_register(self):
        """Called by parent manticore on registration (enable global hooks)"""
        m = self.manticore
        for func in self.global_hooks:
            exec(func, {"bv": None, "m": m})

        # Hack: call m.add_hook once to subscribe _hook_callback
        m.hook(0)(lambda state: state)

    def matching_name(self, filename) -> bool:
        """Checks if filename matches with the library name"""
        if filename:
            return realpath(self.filename) == realpath(filename)
        else:
            return False

    def did_map_memory_callback(self, _state, addr, _size, _perms, filename, offset, _addr):
        """Rebases hooks from library to loaded base address"""
        # If binary base is being loaded
        if self.matching_name(filename) and offset == 0:
            print(f"{filename} mapped @ {addr:#x}")
            with self.locked_context():
                m = self.manticore
                self.loaded = True
                self.base = addr

                # Hack: make m.subscribe != None to prevent error in mcore
                # We don't need subscribe, we just want our hooks to be in m._hooks
                subscribe = m.subscribe
                m.subscribe = lambda x, y: None

                for hook_addr in self.avoid:
                    m.hook(hook_addr + self.base)(self.avoid_f)

                for hook_addr in self.find:
                    m.hook(hook_addr + self.base)(self.find_f)

                for hook_addr, func in self.custom_hooks:
                    exec(func, {"addr": hook_addr + self.base, "bv": None, "m": m})

                # Undo our hack to maintain original manticore behaviour
                m.subscribe = subscribe


class UnicornEmulatePlugin(Plugin):
    """Manticore plugin to speed up emulation using unicorn until `start`"""

    def __init__(self, start: int):
        super().__init__()
        self.start = start

    def will_run_callback(self, ready_states):
        for state in ready_states:
            state.cpu.emulate_until(self.start)
