import random
import string
from pathlib import Path

from manticore import ManticoreEVM
from manticore.core.plugin import Profiler
from manticore.ethereum import (
    DetectDelegatecall,
    DetectEnvInstruction,
    DetectExternalCallAndLeak,
    DetectIntegerOverflow,
    DetectInvalid,
    DetectManipulableBalance,
    DetectReentrancyAdvanced,
    DetectReentrancySimple,
    DetectSuicidal,
    DetectUninitializedMemory,
    DetectUninitializedStorage,
    DetectUnusedRetVal,
)
from manticore.ethereum.plugins import (
    FilterFunctions,
    KeepOnlyIfStorageChanges,
    LoopDepthLimiter,
    SkipRevertBasicBlocks,
    VerboseTrace,
)
from manticore.utils import config

from binaryninja import (
    BackgroundTaskThread,
    BinaryView,
    PlainTextReport,
    ReportCollection,
    Settings,
    show_report_collection,
)
from mui.constants import BINJA_EVM_RUN_SETTINGS_PREFIX


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
            m = ManticoreEVM(workspace_url=options["workspace_url"])

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
