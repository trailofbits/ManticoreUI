import os
from typing import Dict, Set
import unittest
from unittest.mock import MagicMock

from manticore.native import Manticore
from mui.native_plugin import RebaseHooksPlugin


class FakeHookManager:
    def __init__(
        self,
        filename: str,
        find_hooks: Set[int] = set(),
        avoid_hooks: Set[int] = set(),
        custom_hooks: Dict[int, str] = {},
        global_hooks: Dict[str, str] = {},
    ):
        self.bv = MagicMock()
        self.bv.file.original_filename = filename
        self.find_hooks = find_hooks
        self.avoid_hooks = avoid_hooks
        self.custom_hooks = custom_hooks
        self.global_hooks = global_hooks

    def list_find_hooks(self) -> Set[int]:
        return self.find_hooks

    def list_avoid_hooks(self) -> Set[int]:
        return self.avoid_hooks

    def list_custom_hooks(self) -> Dict[int, str]:
        return self.custom_hooks

    def list_global_hooks(self) -> Dict[str, str]:
        return self.global_hooks


class RebaseHooksTest(unittest.TestCase):
    BIN_PATH = os.path.join(os.path.dirname(__file__), "binaries", "rebase_harness")
    LIB_PATH = os.path.join(os.path.dirname(__file__), "binaries", "rebase_lib.so")
    FOO = 0x10F9
    FOO_0 = 0x1114
    FOO_1 = 0x110D
    YES = 0x401291
    NO = 0x401291

    def find_f(self, state):
        m = state.manticore
        with m.locked_context() as context:
            context["find_reached"] = True
            m.kill()
        state.abandon()

    def avoid_f(self, state):
        m = state.manticore
        with m.locked_context() as context:
            context["avoid_reached"] = True
        state.abandon()

    def test_rebase_find(self) -> None:
        m = Manticore(self.BIN_PATH, argv=[self.LIB_PATH, str(0xDEAD)])
        with m.locked_context() as context:
            context["find_reached"] = False

        mgr = FakeHookManager(self.LIB_PATH, find_hooks={self.FOO_1})
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertTrue(context["find_reached"])

    def test_rebase_find_no_hit(self) -> None:
        m = Manticore(self.BIN_PATH, argv=[self.LIB_PATH, str(0xB00B)])
        with m.locked_context() as context:
            context["find_reached"] = False

        mgr = FakeHookManager(self.LIB_PATH, find_hooks={self.FOO_1})
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertFalse(context["find_reached"])

    def test_rebase_avoid(self) -> None:
        m = Manticore(self.BIN_PATH, argv=[self.LIB_PATH, str(0)])
        with m.locked_context() as context:
            context["avoid_reached"] = False

        mgr = FakeHookManager(self.LIB_PATH, avoid_hooks={self.FOO_0})
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertTrue(context["avoid_reached"])

    def test_rebase_custom(self) -> None:
        m = Manticore(self.BIN_PATH, argv=[self.LIB_PATH, str(1234)])
        with m.locked_context() as context:
            context["custom_reached"] = False
            context["find_reached"] = False

        custom_code = "\n".join(
            [
                "def hook(state):",
                "    with m.locked_context() as context:",
                "       context['custom_reached'] = True",
                "",
                "    state.cpu.RDI = 0xdead",
                "m.hook(addr)(hook)",
            ]
        )

        m.hook(self.YES)(self.find_f)

        mgr = FakeHookManager(self.LIB_PATH, custom_hooks={self.FOO: custom_code})
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertTrue(context["custom_reached"])
            self.assertTrue(context["find_reached"])

    def test_global(self) -> None:
        m = Manticore(self.BIN_PATH, argv=[self.LIB_PATH, str(1234)])
        with m.locked_context() as context:
            context["global_count"] = 0

        custom_code = "\n".join(
            [
                "global bv,m",
                "def global_hook(state):",
                "    if state.cpu.RIP >= 0x00401000 and state.cpu.RIP <= 0x00402000:",
                "        with m.locked_context() as context:",
                "            context['global_count'] += 1",
                "m.hook(None)(global_hook)",
            ]
        )

        mgr = FakeHookManager(self.LIB_PATH, global_hooks={"ins_count": custom_code})
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertEqual(context["global_count"], 151)


if __name__ == "__main__":
    unittest.main()
