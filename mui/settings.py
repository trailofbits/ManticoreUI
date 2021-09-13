import json
from typing import Final, Dict, Any, List, Tuple

from binaryninja import Settings

from mui.constants import (
    BINJA_NATIVE_RUN_SETTINGS_PREFIX,
    BINJA_HOOK_SETTINGS_PREFIX,
    BINJA_EVM_RUN_SETTINGS_PREFIX,
    BINJA_SETTINGS_GROUP,
)


class MUISettings:
    # This constant variable contains all MUI settings
    # The data structure is roughly:
    # {
    #     prefix: {
    #         setting_name: ({
    #             properties for binja ninja
    #         }, {
    #             additional properties for UI display, etc
    #             possible_values - changes a line input to a dropdown
    #             is_dir_path     - adds a directory selection button
    #             is_file_path    - adds a file selection button
    #             allow_repeats   - allow the same item to be selected more than once in an array view
    #         })
    #     }
    # }
    SETTINGS: Final[Dict[str, Dict[str, Tuple[Dict[str, Any], Dict[str, Any]]]]] = {
        BINJA_NATIVE_RUN_SETTINGS_PREFIX: {
            "concreteStart": (
                {
                    "title": "Concrete Start",
                    "description": "Initial concrete data for the input symbolic buffer",
                    "type": "string",
                    "default": "",
                },
                {},
            ),
            "stdinSize": (
                {
                    "title": "Stdin Size",
                    "description": "Stdin size to use for manticore",
                    "type": "number",
                    "default": 256,
                },
                {},
            ),
            "argv": (
                {
                    "title": "Program arguments (use + as a wildcard)",
                    "description": "Argv to use for manticore",
                    "type": "array",
                    "elementType": "string",
                    "default": [],
                },
                {},
            ),
            "workspaceURL": (
                {
                    "title": "Workspace URL",
                    "description": "Workspace URL to use for manticore",
                    "type": "string",
                    "default": "mem:",
                },
                {
                    "is_dir_path": True,
                },
            ),
            "env": (
                {
                    "title": "Environment Variables",
                    "description": "Environment variables for manticore",
                    "type": "array",
                    "elementType": "string",
                    "default": [],
                },
                {},
            ),
            "symbolicFiles": (
                {
                    "title": "Symbolic Input Files",
                    "description": "Symbolic input files for manticore",
                    "type": "array",
                    "elementType": "string",
                    "default": [],
                },
                {},
            ),
        },
        BINJA_HOOK_SETTINGS_PREFIX: {
            "avoid": (
                {
                    "title": "Avoid Hooks",
                    "description": "Addresses to attach avoid hooks",
                    "type": "string",
                    "default": json.dumps([]),
                },
                {},
            ),
            "find": (
                {
                    "title": "Find Hooks",
                    "description": "Addresses to attach find hooks",
                    "type": "string",
                    "default": json.dumps([]),
                },
                {},
            ),
            "custom": (
                {
                    "title": "Custom Hooks",
                    "description": "Addresses and python code for custom hooks",
                    "type": "string",
                    "default": json.dumps({}),
                },
                {},
            ),
        },
        BINJA_EVM_RUN_SETTINGS_PREFIX: {
            "workspace_url": (
                {
                    "title": "workspace_url",
                    "description": "Location for the manticore workspace",
                    "type": "string",
                    "default": "",
                },
                {
                    "is_dir_path": True,
                },
            ),
            "contract_name": (
                {
                    "title": "contract_name",
                    "description": "The target contract name defined in the source code",
                    "type": "string",
                    "default": "",
                },
                {},
            ),
            "txlimit": (
                {
                    "title": "txlimit",
                    "description": "Maximum number of symbolic transactions to run (negative integer means no limit)",
                    "type": "number",
                    "minValue": -2147483648,
                    "maxValue": 2147483647,
                    "default": -1,
                },
                {},
            ),
            "txaccount": (
                {
                    "title": "txaccount",
                    "description": 'Account used as caller in the symbolic transactions, either "attacker" or "owner" or "combo1" (uses both)',
                    "type": "string",
                    "default": "attacker",
                },
                {
                    "possible_values": [
                        "attacker",
                        "owner",
                        "combo1",
                    ]
                },
            ),
            "detectors_to_exclude": (
                {
                    "title": "detectors_to_exclude",
                    "description": "List of detectors that should be excluded",
                    "type": "array",
                    "elementType": "string",
                    "default": [],
                },
                {
                    "possible_values": [
                        "delegatecall",
                        "env-instr",
                        "ext-call-leak",
                        "invalid",
                        "lockdrop",
                        "overflow",
                        "reentrancy",
                        "reentrancy-adv",
                        "suicidal",
                        "uninitialized-memory",
                        "uninitialized-storage",
                        "unused-return",
                    ],
                    "allow_repeats": False,
                },
            ),
            "exclude_all": (
                {
                    "title": "exclude_all",
                    "description": "Excludes all detectors",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "thorough_mode": (
                {
                    "title": "thorough_mode",
                    "description": "Configure Manticore for more exhaustive exploration. Evaluate gas, generate testcases for dead states, explore constant functions, and run a small suite of detectors.",
                    "type": "boolean",
                    "default": True,
                },
                {},
            ),
            "txnocoverage": (
                {
                    "title": "txnocoverage",
                    "description": "Do not use coverage as stopping criteria",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "txnoether": (
                {
                    "title": "txnoether",
                    "description": "Do not attempt to send ether to contract",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "txpreconstrain": (
                {
                    "title": "txpreconstrain",
                    "description": "Constrain human transactions to avoid exceptions in the contract function dispatcher",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "no_testcases": (
                {
                    "title": "no_testcases",
                    "description": "Do not generate testcases for discovered states when analysis finishes",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "only_alive_testcases": (
                {
                    "title": "only_alive_testcases",
                    "description": "Do not generate testcases for invalid/throwing states when analysis finishes",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "skip_reverts": (
                {
                    "title": "skip_reverts",
                    "description": "Skip REVERTs",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "explore_balance": (
                {
                    "title": "explore_balance",
                    "description": "Discard all transactions that results in states where the underlying EVM storage did not change",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "verbose_trace": (
                {
                    "title": "verbose_trace",
                    "description": "Dump an extra verbose trace for each state",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "limit_loops": (
                {
                    "title": "limit_loops",
                    "description": "Limit loops depth",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "profile": (
                {
                    "title": "profile",
                    "description": "Use profiler",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
            "avoid_constant": (
                {
                    "title": "avoid_constant",
                    "description": "Avoid exploring constant functions for human transactions",
                    "type": "boolean",
                    "default": False,
                },
                {},
            ),
        },
    }

    PREFIXES: Final[List[str]] = [
        BINJA_NATIVE_RUN_SETTINGS_PREFIX,
        BINJA_HOOK_SETTINGS_PREFIX,
        BINJA_EVM_RUN_SETTINGS_PREFIX,
    ]

    @staticmethod
    def register() -> None:
        """Register all MUI settings if they are yet to be registered"""
        settings = Settings()
        first_setting = (
            f"{MUISettings.PREFIXES[0]}{next(iter(MUISettings.SETTINGS[MUISettings.PREFIXES[0]]))}"
        )

        if not settings.contains(first_setting):
            settings.register_group(BINJA_SETTINGS_GROUP, "MUI Settings")
            for prefix in MUISettings.PREFIXES:
                for name, (prop, _) in MUISettings.SETTINGS[prefix].items():
                    settings.register_setting(f"{prefix}{name}", json.dumps(prop))
