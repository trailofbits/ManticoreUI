import os
import unittest

from binaryninja import open_view
from mui.hook_manager import CustomHookIdentity, NativeHookManager


class HookPersistenceTest(unittest.TestCase):
    BIN_PATH = os.path.join(os.path.dirname(__file__), "binaries", "hello_world_basic_hooks.bndb")

    def test_hook_loading(self) -> None:
        with open_view(self.BIN_PATH) as bv:
            mgr = NativeHookManager(bv)
            mgr.load_existing_hooks()
            self.assertEqual(mgr.list_find_hooks(), set([0x401152]))
            self.assertEqual(mgr.list_avoid_hooks(), set([0x401153]))
            self.assertEqual(
                mgr.list_custom_hooks(), {CustomHookIdentity(0x40114D, 0): "# custom hook code"}
            )
            self.assertEqual(mgr.list_global_hooks(), {"global_00": "# global hook code"})


if __name__ == "__main__":
    unittest.main()
