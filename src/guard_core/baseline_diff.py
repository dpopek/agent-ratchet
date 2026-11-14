#!/usr/bin/env python3
"""Pure baseline ratchet semantics for Guard Core 2.3.3: monotonic diff evaluation, strict-improvement checks and ratchet-state joins."""

from __future__ import annotations

from collections import Counter
import copy
from dataclasses import dataclass
import json
from typing import Any

from guard_core.git_guard_io import LEGACY_2_0_SLOP_KINDS, NEW_2_1_SLOP_KINDS


@dataclass
class BaselineDiffResult:
    is_valid: bool
    reason: str


def _is_ceiling_key(key: str) -> bool:
    return key in ("ceiling", "findings_count") or key.endswith("_ceiling") or key.startswith("max_")


def _is_whitelist_key(key: str) -> bool:
    return key in ("exemptions", "allowed_stray_js_files", "legacy_allowed_files") or key.endswith(("_exemptions", "_whitelist")) or key.startswith("allowed_")


def _item_id(item: Any) -> str:
    if isinstance(item, dict):
        if "id" in item:
            return str(item["id"])
        if "file" in item and "symbol" in item and "kind" in item:
            return f"{item['file']}::{item['symbol']}::{item['kind']}"
        if "file" in item and ("pattern" in item or "kind" in item):
            return f"{item['file']}::{item.get('pattern') or item.get('kind') or ''}::{item.get('detail') or ''}"
        if "file" in item:
            return str(item["file"])
        return json.dumps(item, sort_keys=True)
    return str(item)


def _extract_variant_ceilings(entry: dict[str, Any]) -> list[int] | None:
    if "variant_ceilings" in entry:
        vc = entry["variant_ceilings"]
        if not isinstance(vc, list) or not vc or not all(isinstance(x, int) and not isinstance(x, bool) for x in vc):
            return []
        return list(vc)
    if "symbol" in entry and entry.get("kind") == "excessive_parameter_list" and isinstance(entry.get("ceiling"), int) and not isinstance(entry.get("ceiling"), bool):
        return [int(entry["ceiling"])]
    return None


def _check_variant_ceilings_entry(item_key: str, base_entry: dict[str, Any], curr_entry: dict[str, Any]) -> BaselineDiffResult | None:
    base_vc, curr_vc = _extract_variant_ceilings(base_entry), _extract_variant_ceilings(curr_entry)
    if curr_vc == []:
        return BaselineDiffResult(False, f"Malformed variant_ceilings for '{item_key}'.")
    if base_vc is None or curr_vc is None:
        return None
    if curr_vc != sorted(curr_vc, reverse=True):
        return BaselineDiffResult(False, f"variant_ceilings must be sorted descending for '{item_key}'.")
    if len(curr_vc) > len(base_vc):
        return BaselineDiffResult(False, f"Variant count increased for '{item_key}': {len(base_vc)} -> {len(curr_vc)}.")
    for idx, cv in enumerate(curr_vc):
        if cv > base_vc[idx]:
            return BaselineDiffResult(False, f"Variant ceiling[{idx}] increased for '{item_key}': {base_vc[idx]} -> {cv}.")
    return None


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _check_single_exemption_entry(item_key: str, base_entry: dict[str, Any], curr_entry: dict[str, Any]) -> BaselineDiffResult | None:
    for ceiling_field in ("ceiling_lines", "ceiling"):
        base_c = base_entry.get(ceiling_field)
        if not _is_num(base_c):
            continue
        curr_c = curr_entry.get(ceiling_field)
        if not _is_num(curr_c):
            return BaselineDiffResult(False, f"Exemption {ceiling_field} deleted or retyped to non-numeric for '{item_key}'.")
        if curr_c > base_c:
            return BaselineDiffResult(False, f"Exemption {ceiling_field} increased for '{item_key}': {base_c} -> {curr_c}.")
    return _check_variant_ceilings_entry(item_key, base_entry, curr_entry)


def _check_nested_exemption_ceilings(base_list: list[Any], curr_list: list[Any]) -> BaselineDiffResult | None:
    base_by_id = {_item_id(e): e for e in base_list if isinstance(e, dict) and ("file" in e or "id" in e)}
    for entry in curr_list:
        if isinstance(entry, dict) and ("file" in entry or "id" in entry) and (ik := _item_id(entry)) in base_by_id:
            if (err := _check_single_exemption_entry(ik, base_by_id[ik], entry)) is not None:
                return err
    return None


def _check_list_monotonicity(key: str, base_list: list[Any], curr_list: list[Any]) -> BaselineDiffResult | None:
    base_counts, curr_counts = Counter(_item_id(e) for e in base_list), Counter(_item_id(e) for e in curr_list)
    new_items = sorted(iid for iid, cnt in curr_counts.items() if cnt > base_counts.get(iid, 0))
    if new_items:
        label = "New exemption added" if key == "exemptions" else f"New whitelist entry added to '{key}'"
        return BaselineDiffResult(False, f"{label}: {new_items}. Adding baseline exemptions/whitelist entries is strictly forbidden.")
    return _check_nested_exemption_ceilings(base_list, curr_list)


def _same_json_kind(a: Any, b: Any) -> bool:
    return type(a) is type(b) or (_is_num(a) and _is_num(b))


def _check_baseline_schema_keys(base: dict[str, Any], curr: dict[str, Any]) -> BaselineDiffResult | None:
    if bad_added := sorted(k for k in set(curr) - set(base) if not (_is_ceiling_key(k) and _is_num(curr[k]) and 0 <= curr[k] < float("inf"))):
        return BaselineDiffResult(False, f"Unexpected keys added to baseline: {bad_added}.")
    for key, base_val in base.items():
        if key not in curr:
            return BaselineDiffResult(False, f"Key '{key}' was deleted from the baseline.")
        if not _same_json_kind(curr[key], base_val):
            return BaselineDiffResult(False, f"Key '{key}' changed type: {type(base_val).__name__} -> {type(curr[key]).__name__}.")
    for id_key in ("metric", "version", "guard_version", "scope"):
        if id_key in base and curr.get(id_key) != base.get(id_key):
            return BaselineDiffResult(False, f"Baseline {id_key} changed without authorized migration: {base.get(id_key)} -> {curr.get(id_key)}.")
    return None


def evaluate_baseline_diff(base: dict[str, Any], curr: dict[str, Any]) -> BaselineDiffResult:
    if (schema_err := _check_baseline_schema_keys(base, curr)) is not None:
        return schema_err
    for key, val in curr.items():
        if _is_ceiling_key(key) and _is_num(val) and _is_num(base.get(key)) and val > base[key]:
            return BaselineDiffResult(False, f"Ceiling increased for '{key}': {base[key]} -> {val}. Ratchet must be monotonic non-increasing.")
        if isinstance(val, list) and isinstance(base.get(key), list):
            if (list_err := _check_list_monotonicity(key, base[key], val)) is not None:
                return list_err
    return BaselineDiffResult(True, "OK")


def _entry_tightened(b_e: dict[str, Any], entry: dict[str, Any]) -> bool:
    if any(isinstance(entry.get(cf), (int, float)) and isinstance(b_e.get(cf), (int, float)) and entry[cf] < b_e[cf] for cf in ("ceiling", "ceiling_lines")):
        return True
    b_vc, c_vc = _extract_variant_ceilings(b_e), _extract_variant_ceilings(entry)
    return bool(b_vc and c_vc and (len(c_vc) < len(b_vc) or any(c_vc[i] < b_vc[i] for i in range(len(c_vc)))))


def _has_strict_improvement(base: dict[str, Any], curr: dict[str, Any]) -> bool:
    for key, val in curr.items():
        if _is_ceiling_key(key) and _is_num(val) and _is_num(base.get(key)) and val < base[key]:
            return True
        if isinstance(val, list) and _is_whitelist_key(key) and isinstance(base.get(key), list):
            if len(val) < len(base[key]):
                return True
            base_by_id = {_item_id(e): e for e in base[key] if isinstance(e, dict)}
            if any(isinstance(e, dict) and _item_id(e) in base_by_id and _entry_tightened(base_by_id[_item_id(e)], e) for e in val):
                return True
    return False


def _tracked_kinds_for_baseline(data: dict[str, Any]) -> frozenset[str] | None:
    if data.get("metric") != "refactoring_slop":
        return None
    ver = str(data.get("version", ""))
    if ver == "1.0":
        return frozenset()
    if ver == "2.0.0":
        return LEGACY_2_0_SLOP_KINDS
    return LEGACY_2_0_SLOP_KINDS | NEW_2_1_SLOP_KINDS


def _join_exemption_entries(entries: list[dict[str, Any]]) -> dict[str, Any]:
    joined = copy.deepcopy(entries[0])
    for ceiling_field in ("ceiling_lines", "ceiling"):
        vals = [int(e[ceiling_field]) for e in entries if isinstance(e.get(ceiling_field), (int, float)) and not isinstance(e.get(ceiling_field), bool)]
        if vals:
            joined[ceiling_field] = min(vals)
    vcs = [_extract_variant_ceilings(e) for e in entries]
    valid_vcs = [vc for vc in vcs if vc]
    if valid_vcs and any("variant_ceilings" in e for e in entries):
        min_len = min(len(vc) for vc in valid_vcs)
        merged_vc = [min(vc[i] for vc in valid_vcs) for i in range(min_len)]
        if len(merged_vc) > 1:
            joined["variant_ceilings"] = merged_vc
        else:
            joined.pop("variant_ceilings", None)
    return joined


def _join_whitelist_field(ordered: list[dict[str, Any]], key: str) -> list[Any]:
    parent_maps: list[tuple[frozenset[str] | None, dict[str, Any]]] = []
    all_ids: list[str] = []
    seen_ids: set[str] = set()
    for s in ordered:
        s_list = s.get(key, [])
        if not isinstance(s_list, list):
            continue
        tk = _tracked_kinds_for_baseline(s) if key == "exemptions" else None
        id_map = {_item_id(item): item for item in s_list}
        parent_maps.append((tk, id_map))
        for iid in id_map:
            if iid not in seen_ids:
                seen_ids.add(iid)
                all_ids.append(iid)
    merged_list: list[Any] = []
    for iid in all_ids:
        sample = next(m[iid] for _, m in parent_maps if iid in m)
        kind = sample.get("kind") if isinstance(sample, dict) else None
        relevant = [m[iid] for tk, m in parent_maps if (tk is None or (isinstance(kind, str) and kind in tk)) and iid in m]
        tracking_count = sum(1 for tk, _ in parent_maps if tk is None or (isinstance(kind, str) and kind in tk))
        if len(relevant) == tracking_count and relevant:
            merged_list.append(_join_exemption_entries(relevant) if all(isinstance(x, dict) for x in relevant) else copy.deepcopy(relevant[0]))
    return merged_list


def _join_ratchet_states(states: list[dict[str, Any]]) -> dict[str, Any]:
    if len(states) == 1:
        return copy.deepcopy(states[0])
    ordered = sorted(states, key=lambda s: str(s.get("version", "")), reverse=True)
    joined = copy.deepcopy(ordered[0])
    top_ver = str(joined.get("version", ""))
    same_ver_states = [s for s in states if str(s.get("version", "")) == top_ver]
    pool = states if len(same_ver_states) == len(states) else same_ver_states

    for key in sorted({*joined, *(k for s in pool for k, v in s.items() if _is_ceiling_key(k) and _is_num(v))}):
        val = joined.get(key)
        if _is_ceiling_key(key) and (val is None or _is_num(val)):
            if nums := [s[key] for s in pool if _is_num(s.get(key))]:
                joined[key] = min(nums)
        elif isinstance(val, list) and _is_whitelist_key(key):
            joined[key] = _join_whitelist_field(ordered, key)
    return joined
