import json
from typing import Final, Dict, Any, List, Tuple

from binaryninja import Settings

from mui.constants import (
    BINJA_NATIVE_RUN_SETTINGS_PREFIX,
    BINJA_HOOK_SETTINGS_PREFIX,
    BINJA_EVM_RUN_SETTINGS_PREFIX,
    BINJA_SETTINGS_GROUP,
)
from mui.utils import evm_populate_default_solc_path, read_from_common


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
        BINJA_NATIVE_RUN_SETTINGS_PREFIX: read_from_common("native_run_settings.json"),
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
                    "description": "Names and python code for custom hooks",
                    "type": "string",
                    "default": json.dumps({}),
                },
                {},
            ),
            "global": (
                {
                    "title": "Global Hooks",
                    "description": "Names and python code for global custom hooks",
                    "type": "string",
                    "default": json.dumps({}),
                },
                {},
            ),
        },
        BINJA_EVM_RUN_SETTINGS_PREFIX: evm_populate_default_solc_path(
            read_from_common("evm_run_settings.json")
        ),
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
