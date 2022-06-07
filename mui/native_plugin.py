from dataclasses import dataclass
from operator import mod
from typing import Callable, Dict, List, Tuple
from os.path import realpath
from manticore.core.plugin import Plugin
from manticore.native.memory import ProcSelfMapInfo
from mui.hook_manager import NativeHookManager
from mui.utils import MUIState


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


class TraceBlockPlugin(Plugin):
    """Manticore plugin to record execution trace at a **block** level"""

    def __init__(self, mui_state: MUIState):
        super().__init__()
        self.mui_state = mui_state

    # Instructions that jump to new block
    BLOCK_INS = {
        "CALL",
        "RET",
        "JA",
        "JAE",
        "JB",
        "JBE",
        "JC",
        "JCXZ",
        "JECXZ",
        "JRCXZ",
        "JE",
        "JZ",
        "JG",
        "JGE",
        "JL",
        "JLE",
        "JNA",
        "JNAE",
        "JNB",
        "JNBE",
        "JNC",
        "JNE",
        "JNZ",
        "JNG",
        "JNGE",
        "JNL",
        "JNLE",
        "JNO",
        "JNP",
        "JNS",
        "JO",
        "JP",
        "JPE",
        "JPO",
        "JS",
        "JZ",
        "JMP",
        "LJMP",
        "LOOP",
        "LOOPNZ",
    }

    def did_execute_instruction_callback(self, state, pc, _target_pc, instruction):
        # If previous instruction was a BLOCK_INS, current pc should be a new block
        if state.context.get("is_block_start", False):
            state.context["is_block_start"] = False
            state.context.setdefault("trace", set()).add(pc)

        # Check if JMP/CALL/etc. which brings PC to a new block
        canonical_name = state.cpu.canonicalize_instruction_name(instruction)
        if canonical_name in self.BLOCK_INS:
            # Log next executed PC
            state.context["is_block_start"] = True

    def will_terminate_state_callback(self, current_state, _exception):
        self.mui_state.set_trace(current_state.id, current_state.context.get("trace", set()))

    def will_fork_state_callback(self, state, _expression, _solutions, _policy):
        self.mui_state.set_trace(state.id, state.context.get("trace", set()))


@dataclass
class ModuleMapping:
    name: str  # Module name
    start: int  # Start of module
    end: int  # End of module (non-inclusive)


class ModuleMappingPlugin(Plugin):
    def __init__(self, mui_state: MUIState):
        super().__init__()
        self.module_mappings: Dict[str, ModuleMapping] = mui_state.module_mappings

    def update_mappings(self, state):
        mappings: List[ProcSelfMapInfo] = state.cpu.memory.proc_self_mappings()
        for mapping in mappings:
            if mapping.pathname:
                module = self.module_mappings.get(
                    mapping.pathname, ModuleMapping(mapping.pathname, 2**64, -1)
                )
                module.start = min(mapping.start, module.start)
                module.end = max(mapping.end, module.end)
                self.module_mappings[mapping.pathname] = module

    def will_terminate_state_callback(self, current_state, _exception):
        """Callback to update memory mappings when states terminate"""
        self.update_mappings(current_state)

    def will_fork_state_callback(self, state, _expression, _solutions, _policy):
        """Callback to update memory mappings when states fork"""
        self.update_mappings(state)
