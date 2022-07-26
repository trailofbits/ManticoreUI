import os
import unittest
from typing import Dict, Set, cast
from unittest.mock import MagicMock

from manticore.native import Manticore

from mui.hook_manager import CustomHookIdentity, NativeHookManager
from mui.native_plugin import RebaseHooksPlugin, TraceBlockPlugin
from mui.utils import MUIState


class FakeHookManager:
    def __init__(
        self,
        filename: str,
        find_hooks: Set[int] = set(),
        avoid_hooks: Set[int] = set(),
        custom_hooks: Dict[CustomHookIdentity, str] = {},
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

    def list_custom_hooks(self) -> Dict[CustomHookIdentity, str]:
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

        mgr = cast(NativeHookManager, FakeHookManager(self.LIB_PATH, find_hooks={self.FOO_1}))
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertTrue(context["find_reached"])

    def test_rebase_avoid(self) -> None:
        m = Manticore(self.BIN_PATH, argv=[self.LIB_PATH, str(0)])
        with m.locked_context() as context:
            context["avoid_reached"] = False

        mgr = cast(NativeHookManager, FakeHookManager(self.LIB_PATH, avoid_hooks={self.FOO_0}))
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

        mgr = cast(
            NativeHookManager,
            FakeHookManager(
                self.LIB_PATH, custom_hooks={CustomHookIdentity(self.FOO, 0): custom_code}
            ),
        )
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

        mgr = cast(
            NativeHookManager,
            FakeHookManager(self.LIB_PATH, global_hooks={"ins_count": custom_code}),
        )
        m.register_plugin(RebaseHooksPlugin(mgr, self.find_f, self.avoid_f))
        m.run()

        with m.locked_context() as context:
            self.assertEqual(context["global_count"], 151)


class FakeMUIState:
    def __init__(self):
        self.state_trace: Dict[int, Set[int]] = dict()

    def set_trace(self, state_id: int, trace: Set[int]) -> None:
        self.state_trace[state_id] = trace


class TraceBlockTest(unittest.TestCase):
    BIN_PATH = os.path.join(os.path.dirname(__file__), "binaries", "hello_world")
    # Generated with DynamoRIO: `env -i drrun -t drcov -dump_text -- hello_world > /dev/null`
    # Manticore stdout does not have a tty, piping to /dev/null mimics this
    TRACE = {
        4198400,
        4198416,
        4198428,
        4198433,
        4198440,
        4198447,
        4198480,
        4198528,
        4198568,
        4198576,
        4198632,
        4198640,
        4198653,
        4198679,
        4198684,
        4198704,
        4198713,
        4198733,
        4198784,
        4198836,
        4198848,
        4198862,
        4198896,
        4198902,
        4198910,
        4198923,
        4198963,
        4198979,
        4199006,
        4199016,
        4199023,
        4199034,
        4199042,
        4199055,
        4199181,
        4199192,
        4199214,
        4199229,
        4199328,
        4199343,
        4199362,
        4199370,
        4199379,
        4199392,
        4199428,
        4199438,
        4199456,
        4199490,
        4199520,
        4199536,
        4199565,
        4199576,
        4199581,
        4199600,
        4199621,
        4199641,
        4199645,
        4199687,
        4199703,
        4199712,
        4199729,
        4199808,
        4199824,
        4199828,
        4199830,
        4199861,
        4199936,
        4200043,
        4200096,
        4200123,
        4200160,
        4200172,
        4200181,
        4200192,
        4200225,
        4200236,
        4200307,
        4200350,
        4200442,
        4200447,
        4200455,
        4200460,
        4200484,
        4200496,
        4200544,
        4200576,
        4200912,
        4200954,
        4200963,
        4200976,
        4200992,
        4200998,
        4201019,
        4201168,
        4201217,
        4201236,
        4201241,
        4201255,
        4201271,
        4201280,
        4201312,
        4201339,
        4201424,
        4201443,
        4201465,
        4201488,
        4201524,
        4201537,
        4201552,
        4201563,
        4201584,
        4201595,
        4201598,
        4201603,
        4201696,
        4201704,
        4201708,
        4201744,
        4201803,
        4201814,
        4201833,
        4201904,
        4201917,
        4201944,
        4201982,
        4202007,
        4202016,
        4202020,
        4202025,
        4202029,
        4202038,
        4202058,
        4202073,
        4202078,
        4202079,
        4202094,
        4202128,
        4202138,
        4202161,
        4202224,
        4202237,
        4202288,
        4202293,
        4202307,
        4202327,
        4202384,
        4202392,
        4202400,
        4202410,
        4202441,
        4202453,
        4202465,
        4202480,
        4202633,
        4202648,
        4202656,
        4202661,
        4202705,
        4202784,
        4202804,
        4202832,
        4202912,
        4203138,
    }
    # __init_libc behaves differently between manticore and native
    # likely due to different environment variables, ignore blocks from it
    INIT_LIBC = 0x401180
    INIT_LIBC_END = 0x401398

    def test_trace_block(self) -> None:
        mui_state = cast(MUIState, FakeMUIState())
        m = Manticore(self.BIN_PATH)
        m.register_plugin(TraceBlockPlugin(mui_state))
        m.run()

        trace = mui_state.state_trace[0]

        diff = trace.symmetric_difference(self.TRACE)
        diff = set(filter(lambda x: not self.INIT_LIBC <= x < self.INIT_LIBC_END, diff))
        self.assertFalse(diff)


if __name__ == "__main__":
    unittest.main()
