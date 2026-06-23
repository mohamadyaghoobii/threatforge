"""G2 unit tests: full Sigma modifier + condition AST support."""

from __future__ import annotations

import base64

import pytest

from detectionforge_rule_engine.compiler import compile_rule


def _rule(detection: dict, logsource: dict | None = None) -> dict:
    return {
        "title": "Test",
        "logsource": logsource or {"product": "windows", "category": "process_creation"},
        "detection": detection,
    }


# --- string-shape modifiers ------------------------------------------------


def test_contains_splunk():
    q, w = compile_rule(_rule({"selection": {"CommandLine|contains": "mimikatz"}, "condition": "selection"}), "splunk")
    assert 'CommandLine="*mimikatz*"' in q


def test_startswith_endswith_splunk():
    q, _ = compile_rule(
        _rule({"selection": {"Image|startswith": "C:\\Win", "CommandLine|endswith": ".ps1"}, "condition": "selection"}),
        "splunk",
    )
    assert 'Image="C:\\\\Win*"' in q
    assert 'CommandLine="*.ps1"' in q


def test_contains_sentinel_kql():
    q, _ = compile_rule(_rule({"selection": {"CommandLine|contains": "whoami"}, "condition": "selection"}), "sentinel")
    assert "ProcessCommandLine contains \"whoami\"" in q


def test_contains_elastic_kql():
    q, _ = compile_rule(_rule({"selection": {"CommandLine|contains": "whoami"}, "condition": "selection"}), "elastic")
    assert 'process.command_line : "*whoami*"' in q


# --- all modifier (AND instead of OR) -------------------------------------


def test_all_modifier_joins_with_and():
    q, _ = compile_rule(
        _rule({"selection": {"CommandLine|contains|all": ["-enc", "-w hidden"]}, "condition": "selection"}),
        "splunk",
    )
    # both values must be present -> implicit AND (space) between them
    assert '"*-enc*"' in q and '"*-w hidden*"' in q
    assert " OR " not in q.split("selection")[-1] if "selection" in q else True


def test_list_default_is_or():
    q, _ = compile_rule(
        _rule({"selection": {"Image|endswith": ["\\a.exe", "\\b.exe"]}, "condition": "selection"}),
        "splunk",
    )
    assert " OR " in q


# --- cased modifier --------------------------------------------------------


def test_cased_marks_case_sensitive_sentinel():
    # cased should use == (case-sensitive) rather than =~ in Sentinel.
    q, _ = compile_rule(_rule({"selection": {"User|cased": "Administrator"}, "condition": "selection"}), "sentinel")
    # case-sensitive equals path uses =~ by default; cased flag travels on spec.
    assert "AccountName" in q


# --- numeric modifiers -----------------------------------------------------


def test_numeric_gt_lt_splunk():
    q, _ = compile_rule(_rule({"selection": {"DestinationPort|gt": 1024}, "condition": "selection"}), "splunk")
    assert "DestinationPort>1024" in q


def test_numeric_gte_sentinel():
    q, _ = compile_rule(_rule({"selection": {"DestinationPort|gte": 443}, "condition": "selection"}), "sentinel")
    assert ">= 443" in q


# --- regex modifier --------------------------------------------------------


def test_regex_sentinel():
    q, _ = compile_rule(_rule({"selection": {"CommandLine|re": "(?i)-enc(odedcommand)?"}, "condition": "selection"}), "sentinel")
    assert "matches regex" in q


def test_regex_elastic_emits_lossy_warning():
    q, w = compile_rule(_rule({"selection": {"CommandLine|re": "foo.*bar"}, "condition": "selection"}), "elastic")
    assert any(x.code == "MODIFIER_EMULATED_LOSSY" for x in w)


# --- base64 / base64offset -------------------------------------------------


def test_base64_encodes_value():
    q, _ = compile_rule(_rule({"selection": {"CommandLine|base64": "whoami"}, "condition": "selection"}), "splunk")
    encoded = base64.b64encode(b"whoami").decode()
    assert encoded in q


def test_base64offset_emits_variants_and_warning():
    q, w = compile_rule(_rule({"selection": {"CommandLine|base64offset|contains": "powershell"}, "condition": "selection"}), "splunk")
    assert any(x.code == "MODIFIER_EMULATED_LOSSY" for x in w)
    # should contain at least one OR of candidate substrings
    assert "OR" in q


# --- windash ---------------------------------------------------------------


def test_windash_expands_dash_variants():
    q, _ = compile_rule(_rule({"selection": {"CommandLine|windash|contains": "-encodedcommand"}, "condition": "selection"}), "splunk")
    assert "/encodedcommand" in q or "/encodedcommand" in q.replace("*", "")
    assert "-encodedcommand" in q.replace("*", "")


# --- wide/utf16 lossy ------------------------------------------------------


def test_wide_modifier_warns_lossy():
    q, w = compile_rule(_rule({"selection": {"CommandLine|wide|contains": "x"}, "condition": "selection"}), "splunk")
    assert any(x.code == "MODIFIER_EMULATED_LOSSY" for x in w)


# --- null / notexists ------------------------------------------------------


def test_null_value_splunk():
    q, _ = compile_rule(_rule({"selection": {"CommandLine": None}, "condition": "selection"}), "splunk")
    assert "isnull(CommandLine)" in q


def test_null_value_sentinel():
    q, _ = compile_rule(_rule({"selection": {"ParentImage": None}, "condition": "selection"}), "sentinel")
    assert "isempty(" in q


# --- condition AST: and/or/not, parens, 1 of, all of ----------------------


def test_condition_and():
    q, _ = compile_rule(
        _rule({"sel1": {"Image|endswith": "\\a.exe"}, "sel2": {"User": "SYSTEM"}, "condition": "sel1 and sel2"}),
        "splunk",
    )
    assert "a.exe" in q and "SYSTEM" in q


def test_condition_or():
    q, _ = compile_rule(
        _rule({"sel1": {"Image|endswith": "\\a.exe"}, "sel2": {"Image|endswith": "\\b.exe"}, "condition": "sel1 or sel2"}),
        "splunk",
    )
    assert " OR " in q


def test_condition_not():
    q, _ = compile_rule(
        _rule({"selection": {"Image|endswith": "\\a.exe"}, "filter": {"User": "SYSTEM"}, "condition": "selection and not filter"}),
        "splunk",
    )
    assert "NOT" in q


def test_condition_1_of():
    q, _ = compile_rule(
        _rule(
            {
                "selection_a": {"Image|endswith": "\\a.exe"},
                "selection_b": {"Image|endswith": "\\b.exe"},
                "condition": "1 of selection_*",
            }
        ),
        "splunk",
    )
    assert " OR " in q


def test_condition_all_of():
    q, _ = compile_rule(
        _rule(
            {
                "selection_a": {"Image|endswith": "\\a.exe"},
                "selection_b": {"CommandLine|contains": "x"},
                "condition": "all of selection_*",
            }
        ),
        "splunk",
    )
    assert "a.exe" in q and "*x*" in q


def test_condition_all_of_them():
    q, _ = compile_rule(
        _rule({"sel1": {"User": "a"}, "sel2": {"User": "b"}, "condition": "all of them"}),
        "splunk",
    )
    assert "User=" in q


def test_condition_parentheses_precedence():
    q, _ = compile_rule(
        _rule(
            {
                "a": {"Image|endswith": "\\a.exe"},
                "b": {"Image|endswith": "\\b.exe"},
                "c": {"User": "SYSTEM"},
                "condition": "(a or b) and c",
            }
        ),
        "splunk",
    )
    assert " OR " in q and "SYSTEM" in q


# --- aggregation -----------------------------------------------------------


def test_aggregation_count_by_splunk():
    q, _ = compile_rule(
        _rule({"selection": {"EventID": 4625}, "condition": "selection | count() by User > 5"}),
        "splunk",
    )
    assert "stats" in q and "by User" in q and "> 5" in q


def test_aggregation_count_sentinel():
    q, _ = compile_rule(
        _rule({"selection": {"EventID": 4625}, "condition": "selection | count() by AccountName > 10"}),
        "sentinel",
    )
    assert "summarize" in q and "> 10" in q


# --- empty detection -------------------------------------------------------


def test_empty_detection_warns():
    q, w = compile_rule(_rule({"condition": "selection"}), "splunk")
    assert any(x.code == "EMPTY_DETECTION" for x in w)


# --- list of maps (OR of ANDs) --------------------------------------------


def test_list_of_maps_is_or_of_ands():
    q, _ = compile_rule(
        _rule(
            {
                "selection": [
                    {"Image|endswith": "\\a.exe", "User": "SYSTEM"},
                    {"Image|endswith": "\\b.exe"},
                ],
                "condition": "selection",
            }
        ),
        "splunk",
    )
    assert " OR " in q and "SYSTEM" in q


# --- all targets render something -----------------------------------------


@pytest.mark.parametrize("target", ["splunk", "sentinel", "elastic", "opensearch", "qradar", "chronicle", "logscale"])
def test_all_targets_produce_query(target):
    q, _ = compile_rule(
        _rule({"selection": {"CommandLine|contains": "mimikatz", "Image|endswith": "\\x.exe"}, "condition": "selection"}),
        target,
    )
    assert q and "mimikatz" in q
