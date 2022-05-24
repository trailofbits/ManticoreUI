import tempfile
from time import sleep
from typing import Callable, Optional

from binaryninja import (
    BackgroundTaskThread,
    Settings,
    BinaryView,
    TypedDataAccessor,
    Endianness,
    Architecture,
    open_view,
)
from manticore.core.state import StateBase, TerminateState
from manticore.native import Manticore

from mui.constants import BINJA_NATIVE_RUN_SETTINGS_PREFIX
from mui.dockwidgets import widget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.hook_manager import NativeHookManager
from mui.introspect_plugin import MUIIntrospectionPlugin
from mui.report import NativeResultReport
from mui.utils import MUIState, print_timestamp
from mui.native_plugin import RebaseHooksPlugin, UnicornEmulatePlugin


class ManticoreNativeRunner(BackgroundTaskThread):
    def __init__(self, view: BinaryView, mgr: NativeHookManager):
        BackgroundTaskThread.__init__(self, "Solving with Manticore...", True)
        self.view = view
        self.mgr = mgr

        # Get binary base (if necessary) and rebase hooks
        self.addr_off = self.get_address_offset(view)
        self.find = [addr + self.addr_off for addr in mgr.list_find_hooks()]
        self.avoid = [addr + self.addr_off for addr in mgr.list_avoid_hooks()]
        self.custom_hooks = [
            (addr + self.addr_off, func) for addr, func in mgr.list_custom_hooks().items()
        ]
        self.global_hooks = list(mgr.list_global_hooks().values())

        # Write the binary to disk so that the Manticore API can read it
        self.binary = tempfile.NamedTemporaryFile()
        self.binary.write(view.file.raw.read(0, len(view.file.raw)))
        self.binary.flush()

    def run(self):
        """Initializes manticore, adds the necessary hooks, and runs it"""

        try:
            bv = self.view

            # set up state and clear UI
            state_widget: StateListWidget = widget.get_dockwidget(self.view, StateListWidget.NAME)

            if bv.session_data.mui_state is None:
                bv.session_data.mui_state = MUIState(bv)
                state_widget.listen_to(bv.session_data.mui_state)

            bv.session_data.mui_state.notify_states_changed({})
            bv.session_data.mui_state.paused_states = set()

            settings = Settings()

            m = Manticore.linux(
                self.binary.name,
                workspace_url=settings.get_string(
                    f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}workspaceURL", bv
                ),
                argv=settings.get_string_list(f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}argv", bv).copy(),
                stdin_size=settings.get_integer(f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}stdinSize", bv),
                concrete_start=settings.get_string(
                    f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}concreteStart", bv
                ),
                envp={
                    key: val
                    for key, val in [
                        env.split("=")
                        for env in settings.get_string_list(
                            f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}env", bv
                        )
                    ]
                },
                introspection_plugin_type=MUIIntrospectionPlugin,
            )
            bv.session_data.mui_cur_m = m

            @m.init
            def init(state):
                for file in settings.get_string_list(
                    f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}symbolicFiles", bv
                ):
                    state.platform.add_symbolic_file(file)

            emulate_until: Optional[int]
            try:
                emulate_until = int(
                    settings.get_string(f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}emulateUntil", bv), 16
                )
                emulate_until += self.addr_off
            except:
                emulate_until = None

            if emulate_until:
                print(f"Using Unicorn emulation until {emulate_until:#x}")
                m.register_plugin(UnicornEmulatePlugin(emulate_until))

            def avoid_f(state: StateBase):
                state.context["abandon_code"] = "avoid"
                state.abandon()

            for addr in self.avoid:
                m.hook(addr)(avoid_f)

            def find_f(state: StateBase):
                bufs = state.solve_one_n_batched(state.input_symbols)
                for symbol, buf in zip(state.input_symbols, bufs):
                    print(f"{symbol.name}: {buf!r}\n")

                with m.locked_context() as context:
                    context["find_reached"] = True
                    m.kill()
                state.context["abandon_code"] = "find"
                state.abandon()

            for addr in self.find:
                m.hook(addr)(find_f)

            for addr, func in self.custom_hooks:
                exec(func, {"addr": addr, "bv": bv, "m": m})

            for func in self.global_hooks:
                exec(func, {"bv": bv, "m": m})

            # Global hook for mui_state to add state-specific hooks
            m.hook(None)(bv.session_data.mui_state.state_callback_hook)

            self.load_libraries(m, find_f, avoid_f)

            def run_every(callee: Callable, duration: int = 3) -> Callable:
                """
                Returns a function that calls <callee> every <duration> seconds
                """

                def inner(
                    thread,
                ):  # Takes `thread` as argument, which is provided by the daemon thread API
                    while thread.manticore.is_running():
                        # Pass Manticore's state descriptor dict to the callee
                        callee(thread.manticore.introspect())
                        sleep(duration)

                return inner

            m.register_daemon(run_every(bv.session_data.mui_state.notify_states_changed, 1))

            def check_termination(_):
                """Check if the user wants to termninate manticore"""
                if bv.session_data.mui_is_running == False:
                    print_timestamp("Manticore terminated by user!")
                    with m.locked_context() as context:
                        m.kill()

            m.register_daemon(run_every(check_termination, 1))

            with m.locked_context() as context:
                context["find_reached"] = False
            print_timestamp("Manticore started")
            m.run()
            bv.session_data.mui_state.notify_states_changed(m.introspect())
            with m.locked_context() as context:
                if context["find_reached"]:
                    print_timestamp("Manticore finished")
                else:
                    print_timestamp("Manticore finished without reaching find")

            generate_report = settings.get_bool(
                f"{BINJA_NATIVE_RUN_SETTINGS_PREFIX}generateReport", bv
            )
            if generate_report:
                print("Preparing workspace report ...")
                report = NativeResultReport(bv, m, self)
                report.show_report()

        finally:
            bv.session_data.mui_is_running = False
            bv.session_data.mui_cur_m = None

    def get_address_offset(self, bv: BinaryView):
        """Offsets addresses to take into consideration position independent executables (PIE)"""
        # Addresses taken from https://github.com/trailofbits/manticore/blob/c3eabe03cf94f410bedd96d850df09cb0bda1711/manticore/platforms/linux.py#L954-L956
        BASE_DYN_ADDR = 0x555555554000
        BASE_DYN_ADDR_32 = 0x56555000

        addr_off = None
        if bv.arch == Architecture["x86_64"]:
            h_addr = bv.symbols["__elf_header"][0].address
            h_type = bv.types["Elf64_Header"]
            header = TypedDataAccessor(h_type, h_addr, bv, Endianness.LittleEndian)
            if header["type"].value == 3:  # ET_DYN
                addr_off = BASE_DYN_ADDR
            else:
                addr_off = 0
        elif bv.arch == Architecture["x86"]:
            h_addr = bv.symbols["__elf_header"][0].address
            h_type = bv.types["Elf32_Header"]
            header = TypedDataAccessor(h_type, h_addr, bv, Endianness.LittleEndian)
            if header["type"].value == 3:  # ET_DYN
                addr_off = BASE_DYN_ADDR_32
            else:
                addr_off = 0
        else:
            addr_off = 0

        return addr_off

    def load_libraries(self, m: Manticore, find_f: Callable, avoid_f: Callable) -> None:
        """Load hooks from shared libraries and rebase hooks"""
        for lib_name in self.view.session_data.mui_libs:
            print(f"Loading hooks from external library: {lib_name}")
            with open_view(lib_name, options={"ui.log.minLevel": "ErrorLog"}) as lib_bv:
                lib_mgr = NativeHookManager(lib_bv)
                lib_mgr.load_existing_hooks()
                m.register_plugin(RebaseHooksPlugin(lib_mgr, find_f, avoid_f))
