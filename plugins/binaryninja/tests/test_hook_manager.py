import os
import unittest
from mui.hook_manager import NativeHookManager
from binaryninja import open_view


class HookManagerTest(unittest.TestCase):
    BIN_PATH = os.path.join(os.path.dirname(__file__), "binaries", "hello_world")
    MAIN = 0x401139

    def setUp(self):
        self.bv = open_view(self.BIN_PATH)
        self.mgr = NativeHookManager(self.bv)

    def tearDown(self):
        self.bv.file.close()

    def test_add_find(self) -> None:
        mgr = self.mgr
        mgr.add_find_hook(self.MAIN)
        self.assertTrue(mgr.has_find_hook(self.MAIN))
        self.assertEqual(mgr.list_find_hooks(), set([self.MAIN]))

    def test_add_avoid(self) -> None:
        mgr = self.mgr
        mgr.add_avoid_hook(self.MAIN)
        self.assertTrue(mgr.has_avoid_hook(self.MAIN))
        self.assertEqual(mgr.list_avoid_hooks(), set([self.MAIN]))

    def test_add_custom(self) -> None:
        mgr = self.mgr
        mgr.add_custom_hook(self.MAIN, "# custom hook code")
        self.assertTrue(mgr.has_custom_hook(self.MAIN))
        self.assertEqual(mgr.get_custom_hook(self.MAIN), "# custom hook code")
        self.assertEqual(mgr.list_custom_hooks(), {self.MAIN: "# custom hook code"})

    def test_add_global(self) -> None:
        mgr = self.mgr
        name = "global_00"
        mgr.add_global_hook(name, "# global hook code")
        self.assertTrue(mgr.has_global_hook(name))
        self.assertEqual(mgr.get_global_hook(name), "# global hook code")
        self.assertEqual(mgr.list_global_hooks(), {name: "# global hook code"})

    def test_del_find(self) -> None:
        mgr = self.mgr
        mgr.add_find_hook(self.MAIN)
        mgr.del_find_hook(self.MAIN)
        self.assertFalse(mgr.has_find_hook(self.MAIN))
        self.assertEqual(mgr.list_find_hooks(), set())

    def test_del_avoid(self) -> None:
        mgr = self.mgr
        mgr.add_avoid_hook(self.MAIN)
        mgr.del_avoid_hook(self.MAIN)
        self.assertFalse(mgr.has_avoid_hook(self.MAIN))
        self.assertEqual(mgr.list_avoid_hooks(), set())

    def test_del_custom(self) -> None:
        mgr = self.mgr
        mgr.add_custom_hook(self.MAIN, "# custom hook code")
        mgr.del_custom_hook(self.MAIN)
        self.assertFalse(mgr.has_custom_hook(self.MAIN))
        self.assertEqual(mgr.get_custom_hook(self.MAIN), "")
        self.assertEqual(mgr.list_custom_hooks(), {})

    def test_del_global(self) -> None:
        mgr = self.mgr
        name = "global_00"
        mgr.add_global_hook(name, "# global hook code")
        mgr.del_global_hook(name)
        self.assertFalse(mgr.has_global_hook(name))
        self.assertEqual(mgr.get_global_hook(name), "")
        self.assertEqual(mgr.list_global_hooks(), {})


if __name__ == "__main__":
    unittest.main()
