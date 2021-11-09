from pathlib import Path
from time import sleep
from typing import Set, Dict, List, Any, Callable

import pyevmasm as pyevmasm
from binaryninja import (
    BackgroundTaskThread,
    BinaryView,
    Settings,
    ReportCollection,
    PlainTextReport,
    show_report_collection,
)

from manticore import ManticoreEVM
from manticore.core.plugin import Profiler, Plugin
from manticore.ethereum import (
    DetectInvalid,
    DetectIntegerOverflow,
    DetectUninitializedStorage,
    DetectUninitializedMemory,
    DetectReentrancySimple,
    DetectReentrancyAdvanced,
    DetectUnusedRetVal,
    DetectSuicidal,
    DetectDelegatecall,
    DetectExternalCallAndLeak,
    DetectEnvInstruction,
    DetectManipulableBalance,
    State,
)
from manticore.ethereum.plugins import (
    LoopDepthLimiter,
    VerboseTrace,
    KeepOnlyIfStorageChanges,
    SkipRevertBasicBlocks,
    FilterFunctions,
)
from manticore.utils import config
from mui.constants import BINJA_EVM_RUN_SETTINGS_PREFIX
from mui.dockwidgets import widget
from mui.dockwidgets.state_list_widget import StateListWidget
from mui.introspect_plugin import MUIIntrospectionPlugin
from mui.utils import MUIState


class HookPlugin(Plugin):
    """Adds hook functionality to ManticoreEVM via a plugin"""

    def __init__(
        self,
        find_hooks: Set[int],
        avoid_hooks: Set[int],
        custom_hooks: Dict[int, str],
        m: ManticoreEVM,
        bv: BinaryView,
    ) -> None:
        super().__init__()
        self.find_hooks = tuple(find_hooks)
        self.avoid_hooks = tuple(avoid_hooks)
        self.custom_hooks = custom_hooks
        self.m = m
        self.bv = bv

    def _find_callback(self, state: State, pc: int) -> None:
        print("find cb called")

        # find the depth 0 human tx
        for idx in range(len(state.platform._callstack) - 1, -1, -1):
            tx, _, _, _, _ = state.platform._callstack[idx]
            if tx.depth == 0:
                human_tx = tx
                break
        else:
            raise RuntimeError("No human tx found by find hook")

        print(state.solve_one_n_batched(human_tx.data))

        # add the ongoing tx to the list of transactions so the generated testcase contains it
        human_tx.set_result("STOP", used_gas=-1)
        state.platform._transactions.append(human_tx)

        # generate a special testcase for this hook in the workspace
        self.m.generate_testcase(state, name=f"find_hook_{hex(pc)}")

        # terminate manticore
        with self.m.locked_context() as context:
            self.m.kill()

        state.abandon()

    def _avoid_callback(self, state: State) -> None:
        print("avoid cb called")
        state.abandon()

    def will_evm_execute_instruction_callback(
        self, state: State, instruction: pyevmasm.evmasm.Instruction, arguments: List[Any]
    ) -> None:
        at_init = state.platform.current_transaction.sort == "CREATE"
        pc: int = instruction.pc

        # currently do not support hooks during creation
        if not at_init:
            if pc in self.find_hooks:
                self._find_callback(state, pc)

            if pc in self.avoid_hooks:
                self._avoid_callback(state)

            if pc in self.custom_hooks:
                exec(
                    self.custom_hooks[pc], {"addr": pc, "bv": self.bv, "m": self.m, "state": state}
                )


def get_detectors_classes():
    return [
        DetectInvalid,
        DetectIntegerOverflow,
        DetectUninitializedStorage,
        DetectUninitializedMemory,
        DetectReentrancySimple,
        DetectReentrancyAdvanced,
        DetectUnusedRetVal,
        DetectSuicidal,
        DetectDelegatecall,
        DetectExternalCallAndLeak,
        DetectEnvInstruction,
        DetectManipulableBalance,
        # The RaceCondition detector has been disabled for now as it seems to collide with IntegerOverflow detector
        # DetectRaceCondition
    ]


def choose_detectors(args):
    all_detector_classes = get_detectors_classes()
    detectors = {d.ARGUMENT: d for d in all_detector_classes}
    arguments = list(detectors.keys())

    detectors_to_run = []

    if not args["exclude_all"]:
        exclude = []

        if len(args["detectors_to_exclude"]) > 0:
            exclude = args["detectors_to_exclude"]

            for e in exclude:
                if e not in arguments:
                    raise Exception(
                        f"{e} is not a detector name, must be one of {arguments}. See also `--list-detectors`."
                    )

        for arg, detector_cls in detectors.items():
            if arg not in exclude:
                detectors_to_run.append(detector_cls)

    return detectors_to_run


class ManticoreEVMRunner(BackgroundTaskThread):
    def __init__(self, source_file: Path, bv: BinaryView):
        BackgroundTaskThread.__init__(self, "Solving with Manticore EVM...", True)
        self.source_file: Path = source_file
        self.bv: BinaryView = bv

    def run(self):
        """Analyzes the evm contract with manticore"""

        try:

            # set up state and clear UI
            if self.bv.session_data.mui_state is None:
                state_widget: StateListWidget = widget.get_dockwidget(self.bv, StateListWidget.NAME)
                self.bv.session_data.mui_state = MUIState(self.bv)
                state_widget.listen_to(self.bv.session_data.mui_state)

            self.bv.session_data.mui_state.notify_states_changed({})

            settings = Settings()
            options = {}

            options["workspace_url"] = settings.get_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}workspace_url", self.bv
            )

            options["contract_name"] = settings.get_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}contract_name", self.bv
            )
            options["txlimit"] = int(
                settings.get_double(f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txlimit", self.bv)
            )
            options["txaccount"] = settings.get_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}txaccount", self.bv
            )
            options["detectors_to_exclude"] = settings.get_string_list(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}detectors_to_exclude", self.bv
            )

            options["solc_path"] = settings.get_string(
                f"{BINJA_EVM_RUN_SETTINGS_PREFIX}solc_path", self.bv
            )

            for bool_option in [
                "txnocoverage",
                "txnoether",
                "txpreconstrain",
                "no_testcases",
                "only_alive_testcases",
                "skip_reverts",
                "explore_balance",
                "verbose_trace",
                "limit_loops",
                "profile",
                "avoid_constant",
                "thorough_mode",
                "exclude_all",
            ]:
                options[bool_option] = settings.get_bool(
                    f"{BINJA_EVM_RUN_SETTINGS_PREFIX}{bool_option}", self.bv
                )

            if options["txlimit"] < 0:
                options["txlimit"] = None
            if len(options["contract_name"]) < 1:
                options["contract_name"] = None

            if not options["thorough_mode"]:
                options["avoid_constant"] = True
                options["exclude_all"] = True
                options["only_alive_testcases"] = True
                consts_evm = config.get_group("evm")
                consts_evm.oog = "ignore"
                options["skip_reverts"] = True

            # initialize manticore with the various options
            m = ManticoreEVM(
                workspace_url=options["workspace_url"],
                introspection_plugin_type=MUIIntrospectionPlugin,
            )

            if options["skip_reverts"]:
                m.register_plugin(SkipRevertBasicBlocks())

            if options["explore_balance"]:
                m.register_plugin(KeepOnlyIfStorageChanges())

            if options["verbose_trace"]:
                m.register_plugin(VerboseTrace())

            if options["limit_loops"]:
                m.register_plugin(LoopDepthLimiter())

            for detector in choose_detectors(options):
                m.register_detector(detector())

            if options["profile"]:
                profiler = Profiler()
                m.register_plugin(profiler)

            if options["avoid_constant"]:
                # avoid all human level tx that has no effect on the storage
                filter_nohuman_constants = FilterFunctions(
                    regexp=r".*", depth="human", mutability="constant", include=False
                )
                m.register_plugin(filter_nohuman_constants)

            if m.plugins:
                print(f'Registered plugins: {", ".join(d.name for d in m.plugins.values())}')

            m.register_plugin(
                HookPlugin(
                    self.bv.session_data.mui_find,
                    self.bv.session_data.mui_avoid,
                    self.bv.session_data.mui_custom_hooks,
                    m,
                    self.bv,
                )
            )

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

            m.register_daemon(run_every(self.bv.session_data.mui_state.notify_states_changed, 1))

            print("Beginning analysis")

            m.multi_tx_analysis(
                str(self.source_file),
                contract_name=options["contract_name"],
                tx_limit=options["txlimit"],
                tx_use_coverage=not options["txnocoverage"],
                tx_send_ether=not options["txnoether"],
                tx_account=options["txaccount"],
                tx_preconstrain=options["txpreconstrain"],
                compile_args={"solc_solcs_bin": options["solc_path"]},
            )

            self.bv.session_data.mui_state.notify_states_changed(m.introspect())

            print("finalizing...")
            if not options["no_testcases"]:
                m.finalize(only_alive_states=options["only_alive_testcases"])
            else:
                m.kill()

            print("finished")

            collection = ReportCollection()
            for file in sorted(
                [
                    x
                    for x in Path(options["workspace_url"]).iterdir()
                    if x.is_file() and x.name[-4:] != ".pkl"
                ]
            ):
                with open(file) as f:
                    collection.append(PlainTextReport(file.name, f.read()))
            show_report_collection("results", collection)
        finally:
            self.bv.session_data.mui_is_running = False
