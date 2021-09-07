import tempfile
from time import sleep
from typing import Callable, Set

from binaryninja import BackgroundTaskThread, Settings, BinaryView
from manticore.core.state import StateBase
from manticore.native import Manticore

from mui.constants import BINJA_RUN_SETTINGS_PREFIX
from mui.dockwidgets import widget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.introspect_plugin import MUIIntrospectionPlugin
from mui.utils import MUIState


class ManticoreNativeRunner(BackgroundTaskThread):
    def __init__(self, find: Set[int], avoid: Set[int], view: BinaryView):
        BackgroundTaskThread.__init__(self, "Solving with Manticore...", True)
        self.find = tuple(find)
        self.avoid = tuple(avoid)
        self.view = view

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

            settings = Settings()

            m = Manticore.linux(
                self.binary.name,
                workspace_url=settings.get_string(f"{BINJA_RUN_SETTINGS_PREFIX}workspaceURL", bv),
                argv=settings.get_string_list(f"{BINJA_RUN_SETTINGS_PREFIX}argv", bv).copy(),
                stdin_size=settings.get_integer(f"{BINJA_RUN_SETTINGS_PREFIX}stdinSize", bv),
                concrete_start=settings.get_string(f"{BINJA_RUN_SETTINGS_PREFIX}concreteStart", bv),
                envp={
                    key: val
                    for key, val in [
                        env.split("=")
                        for env in settings.get_string_list(f"{BINJA_RUN_SETTINGS_PREFIX}env", bv)
                    ]
                },
                introspection_plugin_type=MUIIntrospectionPlugin,
            )

            @m.init
            def init(state):
                for file in settings.get_string_list(
                    f"{BINJA_RUN_SETTINGS_PREFIX}symbolicFiles", bv
                ):
                    state.platform.add_symbolic_file(file)

            def avoid_f(state: StateBase):
                state.abandon()

            for addr in self.avoid:
                m.hook(addr)(avoid_f)

            def find_f(state: StateBase):
                bufs = state.solve_one_n_batched(state.input_symbols)
                for symbol, buf in zip(state.input_symbols, bufs):
                    print(f"{symbol.name}: {buf!r}\n")

                with m.locked_context() as context:
                    m.kill()
                state.abandon()

            for addr in self.find:
                m.hook(addr)(find_f)

            for addr, func in bv.session_data.mui_custom_hooks.items():
                exec(func, {"addr": addr, "bv": bv, "m": m})

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
                    print("Manticore terminated by user!")
                    with m.locked_context() as context:
                        m.kill()

            m.register_daemon(run_every(check_termination, 1))

            m.run()
            bv.session_data.mui_state.notify_states_changed(m.introspect())
            print("Manticore finished")
        finally:
            bv.session_data.mui_is_running = False
