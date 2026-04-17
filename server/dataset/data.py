"""Dataset conversion utilities.

This script converts the Mitre Attacks Framework dataset (loaded as a pandas
DataFrame) into a MongoDB-friendly JSON seed file for the `MalwareKeyword` model.

Usage:
  python server/dataset/data.py --out server/dataset/malware_keywords.seed.json

Notes:
  - The input dataset is loaded from HuggingFace via the `hf://` fsspec handler.
  - Depending on your environment, you may need:
	  pip install pandas fsspec huggingface_hub
	and to authenticate with:
	  huggingface-cli login
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd


HF_DATASET_URL = (
	"hf://datasets/darkknight25/Mitre_Attacks_Framework_Dataset/"
	"Mitre_framework_dataset.jsonl"
)


# Additional static, language-agnostic high-risk patterns.
# These are appended to the generated seed JSON alongside MITRE-derived keywords.
STATIC_WEIGHTED_PATTERN_GROUPS: List[Dict[str, Any]] = [
	{
		"category": "command_execution",
		"weight": 1.0,
		"patterns": [
			"eval(",
			"exec(",
			"os.system(",
			"subprocess.Popen",
			"subprocess.call",
			"system(",
			"Runtime.getRuntime().exec",
		],
	},
	{
		"category": "network_requests",
		"weight": 0.9,
		"patterns": [
			"requests.post(",
			"requests.get(",
			"fetch(",
			"axios.post(",
			"axios.get(",
			"socket.connect(",
			"http://",
			"https://",
		],
	},
	{
		"category": "data_exfiltration",
		"weight": 1.0,
		"patterns": [
			"send(",
			"post(",
			"upload(",
			"webhook",
			"discord webhook",
			"ftp.upload",
			"requests.post(data=",
		],
	},
	{
		"category": "file_operations",
		"weight": 0.7,
		"patterns": [
			"open(",
			"read(",
			"write(",
			"os.listdir(",
			"shutil.copy",
			"fs.readFile",
			"fs.writeFile",
		],
	},
	{
		"category": "obfuscation",
		"weight": 0.95,
		"patterns": [
			"base64.b64decode",
			"base64.b64encode",
			"atob(",
			"btoa(",
			"eval(base64",
			"exec(base64",
			"Buffer.from(",
			"decodeURIComponent(",
		],
	},
	{
		"category": "persistence",
		"weight": 0.9,
		"patterns": [
			"registry",
			"HKCU",
			"HKLM",
			"startup",
			"cron",
			"crontab",
			"schtasks",
			"autorun",
		],
	},
	{
		"category": "keylogging",
		"weight": 1.0,
		"patterns": [
			"pynput.keyboard",
			"keyboard.Listener",
			"on_press",
			"keylogger",
			"log keystrokes",
		],
	},
	{
		"category": "process_manipulation",
		"weight": 0.85,
		"patterns": [
			"psutil.process_iter",
			"kill(",
			"taskkill",
			"ProcessBuilder",
			"process.kill",
		],
	},
	{
		"category": "environment_access",
		"weight": 0.8,
		"patterns": [
			"os.environ",
			"process.env",
			"getenv(",
			"System.getenv",
		],
	},
	{
		"category": "credential_access",
		"weight": 1.0,
		"patterns": [
			"browser_passwords",
			"chrome passwords",
			"decrypt_password",
			"login_data",
			"cookies.sqlite",
		],
	},
	{
		"category": "screenshot_capture",
		"weight": 0.85,
		"patterns": [
			"pyautogui.screenshot",
			"ImageGrab.grab",
			"takeScreenshot",
			"captureScreen",
		],
	},
	{
		"category": "webcam_access",
		"weight": 0.9,
		"patterns": [
			"cv2.VideoCapture",
			"getUserMedia",
			"navigator.mediaDevices",
			"webcam.capture",
		],
	},
	{
		"category": "clipboard_access",
		"weight": 0.75,
		"patterns": [
			"pyperclip.paste",
			"clipboard.readText",
			"clipboardData",
			"xclip",
		],
	},
	{
		"category": "anti_analysis",
		"weight": 0.95,
		"patterns": [
			"check_vm",
			"detect_sandbox",
			"anti_debug",
			"isDebuggerPresent",
			"sleep(10000)",
		],
	},
	{
		"category": "downloader",
		"weight": 0.9,
		"patterns": [
			"wget ",
			"curl ",
			"downloadFile",
			"urllib.request",
			"requests.get(url",
		],
	},
	{
		"category": "combination_high_risk",
		"weight": 1.5,
		"patterns": [
			"base64 + exec",
			"requests.post + data",
			"socket.connect + exec",
			"keylogger + webhook",
			"download + execute",
		],
	},
]


def convert_static_groups_to_keywords(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	"""Convert static category/weight/pattern groups into MalwareKeyword seed docs."""

	docs: List[Dict[str, Any]] = []
	seen = set()

	for group in groups:
		category = group.get("category")
		patterns = group.get("patterns")
		weight = group.get("weight")

		if not _is_non_empty_str(category):
			continue
		if not isinstance(patterns, list):
			continue
		try:
			weight_num = float(weight)
		except Exception:  # noqa: BLE001
			weight_num = 1.0

		for p in patterns:
			pattern = _clean_pattern(p)
			if not pattern:
				continue

			doc = {
				"pattern": pattern,
				"matchMode": "substring",
				"category": str(category).strip(),
				"weight": weight_num,
				"source": "static",
				"enabled": True,
				"meta": {"dataset": "static_weighted_patterns"},
			}

			key = (
				str(doc.get("pattern", "")).strip().lower(),
				str(doc.get("category", "")).strip().lower(),
				str(doc.get("source", "")).strip().lower(),
			)
			if key in seen:
				continue
			seen.add(key)
			docs.append(doc)

	return docs


def _is_non_empty_str(value: Any) -> bool:
	return isinstance(value, str) and value.strip() != ""


def _norm_col(name: str) -> str:
	return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _pick_column(df: pd.DataFrame, preferred: Iterable[str]) -> Optional[str]:
	"""Pick the first existing column matching any preferred normalized name."""

	normalized_to_actual = {_norm_col(c): c for c in df.columns}
	for p in preferred:
		p_norm = _norm_col(p)
		if p_norm in normalized_to_actual:
			return normalized_to_actual[p_norm]
	return None


def _infer_columns(df: pd.DataFrame) -> Tuple[Optional[str], Optional[str], Optional[str]]:
	"""Infer (technique_name, technique_id, tactic) columns by heuristics."""

	technique_name = _pick_column(
		df,
		[
			"technique_name",
			"technique",
			"technique title",
			"attack_technique",
			"name",
		],
	)

	technique_id = _pick_column(
		df,
		[
			"technique_id",
			"attack_id",
			"technique id",
			"id",
			"external_id",
		],
	)

	tactic = _pick_column(
		df,
		[
			"tactic",
			"tactics",
			"attack_tactic",
			"kill_chain_phases",
		],
	)

	return technique_name, technique_id, tactic


def _clean_pattern(text: Any) -> Optional[str]:
	if not _is_non_empty_str(text):
		return None
	value = " ".join(str(text).strip().split())
	if len(value) < 3:
		return None
	return value


def _iter_keywords_from_row(
	row: Dict[str, Any],
	technique_name_col: Optional[str],
	technique_id_col: Optional[str],
	tactic_col: Optional[str],
) -> Iterable[Dict[str, Any]]:
	technique_name = _clean_pattern(row.get(technique_name_col)) if technique_name_col else None
	technique_id = _clean_pattern(row.get(technique_id_col)) if technique_id_col else None

	tactic_raw = row.get(tactic_col) if tactic_col else None
	tactics: List[str] = []
	if isinstance(tactic_raw, list):
		tactics = [t for t in (" ".join(str(x).split()) for x in tactic_raw) if t]
	elif _is_non_empty_str(tactic_raw):
		# Some datasets store tactics as a comma-separated string.
		tactics = [t.strip() for t in str(tactic_raw).split(",") if t.strip()]

	meta = {
		"techniqueName": technique_name,
		"techniqueId": technique_id,
		"tactics": tactics,
	}

	if technique_name:
		yield {
			"pattern": technique_name,
			"matchMode": "substring",
			"category": "mitre_technique_name",
			"weight": 6,
			"source": "mitre",
			"enabled": True,
			"meta": meta,
		}

	# MITRE technique IDs (e.g. T1059) can be high-signal indicators.
	if technique_id and re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id, flags=re.IGNORECASE):
		yield {
			"pattern": technique_id.upper(),
			"matchMode": "substring",
			"category": "mitre_technique_id",
			"weight": 4,
			"source": "mitre",
			"enabled": True,
			"meta": meta,
		}

	for t in tactics:
		if len(t) < 4:
			continue
		yield {
			"pattern": t,
			"matchMode": "substring",
			"category": "mitre_tactic",
			"weight": 2,
			"source": "mitre",
			"enabled": True,
			"meta": meta,
		}


def convert_mitre_df_to_keywords(df: pd.DataFrame, limit_rows: Optional[int] = None) -> List[Dict[str, Any]]:
	technique_name_col, technique_id_col, tactic_col = _infer_columns(df)

	if technique_name_col is None and technique_id_col is None:
		raise RuntimeError(
			"Unable to infer technique columns from dataset. "
			f"Columns present: {list(df.columns)}"
		)

	max_rows = int(limit_rows) if isinstance(limit_rows, int) and limit_rows > 0 else None

	docs: List[Dict[str, Any]] = []
	seen = set()

	iterable = df.to_dict(orient="records")
	if max_rows is not None:
		iterable = iterable[:max_rows]

	for row in iterable:
		for doc in _iter_keywords_from_row(row, technique_name_col, technique_id_col, tactic_col):
			key = (
				str(doc.get("pattern", "")).strip().lower(),
				str(doc.get("category", "")).strip().lower(),
				str(doc.get("source", "")).strip().lower(),
			)
			if key in seen:
				continue
			seen.add(key)
			docs.append(doc)

	return docs


def main() -> int:
	parser = argparse.ArgumentParser(description="Convert Mitre DF to MalwareKeyword seed JSON")
	parser.add_argument("--out", required=True, help="Output JSON file path")
	parser.add_argument("--limit", type=int, default=0, help="Optional max rows to process")
	args = parser.parse_args()

	out_path = Path(args.out)
	out_path.parent.mkdir(parents=True, exist_ok=True)

	try:
		df = pd.read_json(HF_DATASET_URL, lines=True)
	except Exception as exc:  # noqa: BLE001
		raise SystemExit(
			"Failed to load the HuggingFace dataset via hf://. "
			"Install dependencies (pandas, fsspec, huggingface_hub) and authenticate if required. "
			f"Original error: {exc}"
		)

	docs = convert_mitre_df_to_keywords(df, limit_rows=args.limit if args.limit > 0 else None)
	static_docs = convert_static_groups_to_keywords(STATIC_WEIGHTED_PATTERN_GROUPS)

	# Merge and dedupe across both sources.
	merged: List[Dict[str, Any]] = []
	seen = set()
	for doc in docs + static_docs:
		key = (
			str(doc.get("pattern", "")).strip().lower(),
			str(doc.get("category", "")).strip().lower(),
			str(doc.get("source", "")).strip().lower(),
		)
		if key in seen:
			continue
		seen.add(key)
		merged.append(doc)

	out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
	print(f"Wrote {len(merged)} keyword documents to {out_path}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())