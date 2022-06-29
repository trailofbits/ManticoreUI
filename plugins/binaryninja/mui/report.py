from html import escape
from pathlib import Path
from typing import Any, Dict, Set

from binaryninja import (
    Settings,
    BinaryView,
    HTMLReport,
    PlainTextReport,
    ReportCollection,
    show_report_collection,
)
from manticore.core.state import StateBase
from manticore.native import Manticore
from manticore.utils.helpers import PickleSerializer
from manticore.core.smtlib.expression import Expression
from mui.constants import BINJA_NATIVE_RUN_SETTINGS_PREFIX
from mui.settings import MUISettings


class NativeResultReport:
    def __init__(self, bv: BinaryView, m: Manticore, runner):
        self.bv = bv
        self.m = m
        self.runner = runner
        m.finalize()

    def show_report(self) -> None:
        self.show_raw()
        self.show_summary()

    def show_raw(self) -> None:
        """Creates new tab to view the generated Manticore workspace"""
        m = self.m
        store = m._output.store
        collection = ReportCollection()

        for key in sorted(store.ls("*")):
            if key.endswith(".pkl"):
                continue
            collection.append(PlainTextReport(key, store.load_value(key)))

        show_report_collection("results", collection)

    def show_summary(self) -> None:
        """Creates new tab with summarised information about the manticore run"""
        m = self.m
        reports = []
        store = m._output.store
        keys = set(store.ls("*"))
        has_key = lambda key: key in keys

        n_testcase = 0
        if has_key(".testcase_id"):
            n_testcase = int(store.load_value(".testcase_id")) + 1

        tc_class: Dict[str, set] = {}
        for i in range(n_testcase):
            state = self.get_state(i)
            abandon_code = state.context.get("abandon_code", "others")
            tc_class.setdefault(abandon_code, set()).add(i)
            reports.append(self.testcase_report(i, state))

        summary_report = self.summary_report(tc_class)
        reports.insert(0, summary_report)

        collection = ReportCollection()
        for report in reports:
            collection.append(report)
        show_report_collection("summary", collection)

    def get_state(self, id: int) -> StateBase:
        """Get state from testcase id"""
        m = self.m
        stream_name = f"test_{id:08x}.pkl"
        with m._output.store.load_stream(stream_name, binary=True) as f:
            state: StateBase = PickleSerializer().deserialize(f)
        return state

    def testcase_report(self, id: int, state: StateBase) -> HTMLReport:
        """Generates a HTMLReport summary of a testcase"""
        m = self.m
        bv = self.bv
        data: Dict[str, Any] = {}
        store = m._output.store
        keys = set(store.ls("*"))
        prefix = f"test_{id:08x}."
        data["title"] = f"Testcase {id:08x} summary"

        # Hyperlink to BV if within address space
        pc = state.cpu.PC
        addr_off = self.runner.addr_off
        vma_start = bv.start + addr_off
        vma_end = bv.start + bv.length + addr_off
        data["pc"] = pc
        data["pc_link"] = ""
        if pc >= vma_start and pc < vma_end:
            data["pc_link"] = f"binaryninja://?expr={pc-addr_off:x}"

        # Display reason the state terminated (and color)
        color_mapping = {"find": "green", "avoid": "red", "others": "blue"}
        data["abandon_code"] = escape(state.context.get("abandon_code", "others"))
        data["abandon_code_color"] = color_mapping.get(data["abandon_code"], "initial")

        # Display state registers
        rows = ""
        for register in state.cpu.canonical_registers:
            value = getattr(state.cpu, register, None)
            if isinstance(value, type(None)):
                continue
            elif isinstance(value, Expression):
                value = str(value)
            elif isinstance(value, int):
                value = hex(value)
            else:
                continue
            rows += REG_ROW_TEMPLATE.format(register=register, value=escape(value))
        data["regs"] = REG_TABLE_TEMPLATE.format(rows=rows)

        # Workspace data related to the testcase
        data["workspace_data"] = ""
        prefix_keys = filter(lambda x: x.startswith(prefix), keys)
        exclude = {"smt", "syscalls", "pkl", "messages", "trace"}
        for key in prefix_keys:
            suffix = key.split(".")[-1]
            if suffix in exclude:
                continue
            s = escape(str(store.load_value(key)))
            data["workspace_data"] += KEY_VAL_TEMPLATE.format(key=suffix, value=s)

        # Display formatted trace separately at the end
        s = store.load_value(prefix + "trace").rstrip().replace("\n", ", ")
        s = escape(str(f"{{ {s} }}"))
        data["workspace_data"] += KEY_VAL_TEMPLATE.format(key="trace", value=s)

        html = TESTCASE_TEMPLATE.format(**data)
        return HTMLReport(prefix.rstrip("."), html, view=bv)

    def summary_report(self, tc_class: Dict[str, Set[int]]) -> HTMLReport:
        """Generates a HTMLReport summary of the manticore run"""
        m = self.m
        bv = self.bv
        data: Dict[str, Any] = {}
        store = m._output.store
        keys = set(store.ls("*"))
        has_key = lambda key: key in keys

        name = Path(bv.file.filename).name
        data["title"] = f"MUI Summary Report: {name}"

        if has_key("command.sh"):
            s = store.load_value("command.sh")
            data["command"] = escape(s)

        if has_key("manticore.yml"):
            s = store.load_value("manticore.yml")
            data["config"] = escape(s)

        if has_key("global.solver_stats"):
            s = store.load_value("global.solver_stats")
            data["solver_stats"] = escape(s)

        # Testcase summary/categorisation
        data["n_testcases"] = sum([len(s) for s in tc_class.values()])
        data["tc_find"] = ", ".join([f"test_{i:08x}" for i in tc_class.get("find", [])])
        data["tc_others"] = ", ".join([f"test_{i:08x}" for i in tc_class.get("others", [])])
        data["tc_avoid"] = ", ".join([f"test_{i:08x}" for i in tc_class.get("avoid", [])])

        # MUI settings
        settings = Settings()
        prefix = BINJA_NATIVE_RUN_SETTINGS_PREFIX
        mui_settings = {}
        for name, (prop, _) in MUISettings.SETTINGS[prefix].items():
            if prop["type"] == "string":
                value = settings.get_string(f"{prefix}{name}", self.bv)
                mui_settings[prop["title"]] = value
            elif prop["type"] == "number":
                # get_integer can only be used for positive integers, so using get_double as a workaround
                value = int(settings.get_double(f"{prefix}{name}", self.bv))
                mui_settings[prop["title"]] = value
            elif prop["type"] == "array":
                value = settings.get_string_list(f"{prefix}{name}", self.bv)
                mui_settings[prop["title"]] = value
            elif prop["type"] == "boolean":
                value = settings.get_bool(f"{prefix}{name}", self.bv)
                mui_settings[prop["title"]] = value

        data["mui_settings"] = ""
        for key, val in mui_settings.items():
            data["mui_settings"] += KEY_VAL_TEMPLATE.format(key=key, value=escape(repr(val)))

        html = SUMMARY_TEMPLATE.format(**data)
        return HTMLReport("Overall", html, view=bv)


"""
HTML Templates for the various reports
"""

SUMMARY_TEMPLATE = """\
<h1>{title}</h1>
<h2>Command-line arguments (command.sh)</h2>
<code><pre>
{command}
</pre></code>
<h2>Manticore config (manticore.yml)</h2>
<code><pre>
{config}
</pre></code>
<h2>Solver statistics (global.solver_stats)</h2>
<code><pre>
{solver_stats}
</pre></code>
<h2>Testcases</h2>
<code>{n_testcases} testcases</code>
<table>
    <tr>
        <th align="left" style="padding-right: 10px; color: green">Find</th>
        <th align="left" style="padding-right: 10px; color: blue">Others</th>
        <th align="left" style="padding-right: 10px; color: red">Avoid</th>
    </tr>
    <tr>
        <td style="padding-right: 10px;">{tc_find}</td>
        <td style="padding-right: 10px;">{tc_others}</td>
        <td style="padding-right: 10px;">{tc_avoid}</td>
    </tr>
</table>
<br>
<hr>
<h1>MUI Settings</h1>
{mui_settings}
"""

TESTCASE_TEMPLATE = """\
<h1>{title}</h1>
<div>
<p>Last PC: <a href="{pc_link}">{pc:08x}</a></p>
<p>Termination reason: <span style="color: {abandon_code_color}">{abandon_code}</span></p>
<hr>
</div>
<h1>Workspace data</h1> 
{workspace_data}
{regs}
"""

REG_TABLE_TEMPLATE = """\
<h2>State Registers</h2>
<table>
    <tr>
        <th>Register</th>
        <th>Value</th>
    </tr>
{rows}
</table>
"""

REG_ROW_TEMPLATE = """\
    <tr>
        <td>{register}</td>
        <td>{value}</td>
    </tr>
"""

KEY_VAL_TEMPLATE = """\
<h2>{key}</h2>
<code><pre>
{value}
</pre></code>
"""
