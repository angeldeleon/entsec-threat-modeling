"""Configuration. Strict parsing, secrets by reference only."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .analyze.engine import DEFAULT_API_BASE, DEFAULT_MAX_TOKENS, DEFAULT_MODEL
from .baseline import DEFAULT_RETAIN, DEFAULT_STATE_PATH
from .validation import ValidationError, read_text_file, validate_env_var_name

_MAX_CONFIG_BYTES = 512 * 1024
FORMATS = ("markdown", "md", "json", "html")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(slots=True)
class AnalysisConfig:
    api_key_env: str = "ANTHROPIC_API_KEY"
    model: str = DEFAULT_MODEL
    api_base: str = DEFAULT_API_BASE
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: float = 120.0
    verify_tls: bool = True
    allow_internal: bool = False
    temperature: float = 0.0


@dataclass(slots=True)
class Config:
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    state_path: str = DEFAULT_STATE_PATH
    retain: int = DEFAULT_RETAIN
    fail_on: str = "high"
    output_format: str = "markdown"


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)}. "
            f"Valid keys: {', '.join(sorted(allowed))}"
        )


def _bounded_number(value: Any, where: str, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be a number") from exc
    if not low <= number <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return number


def _strict_bool(value: Any, where: str) -> bool:
    """Accept only a real boolean.

    ``bool("no")`` is True, so a quoted ``allow_internal: "no"`` would turn the
    SSRF guard off while reading as though it were off. Any non-empty string
    does this, and YAML quoting is easy to get wrong.
    """
    if isinstance(value, bool):
        return value
    raise ValidationError(
        f'{where} must be true or false, not {value!r}. A quoted "no" is a string, '
        "and every non-empty string counts as true."
    )


def parse_config(raw: Any) -> Config:
    if not isinstance(raw, dict):
        raise ValidationError("config must be a mapping")
    _reject_unknown(
        raw, {"analysis", "state_path", "retain", "fail_on", "output_format"}, "the top level"
    )
    config = Config()

    analysis_raw = raw.get("analysis") or {}
    if not isinstance(analysis_raw, dict):
        raise ValidationError("analysis must be a mapping")
    _reject_unknown(
        analysis_raw,
        {
            "api_key_env",
            "model",
            "api_base",
            "max_tokens",
            "timeout",
            "verify_tls",
            "allow_internal",
            "temperature",
        },
        "analysis",
    )

    config.analysis.api_key_env = validate_env_var_name(
        analysis_raw.get("api_key_env", "ANTHROPIC_API_KEY"), where="analysis.api_key_env"
    )
    config.analysis.model = str(analysis_raw.get("model", DEFAULT_MODEL))
    config.analysis.api_base = str(analysis_raw.get("api_base", DEFAULT_API_BASE))
    if "max_tokens" in analysis_raw:
        config.analysis.max_tokens = int(
            _bounded_number(analysis_raw["max_tokens"], "analysis.max_tokens", 1000, 64_000)
        )
    if "timeout" in analysis_raw:
        config.analysis.timeout = _bounded_number(
            analysis_raw["timeout"], "analysis.timeout", 5, 900
        )
    config.analysis.verify_tls = _strict_bool(
        analysis_raw.get("verify_tls", True), "analysis.verify_tls"
    )
    config.analysis.allow_internal = _strict_bool(
        analysis_raw.get("allow_internal", False), "analysis.allow_internal"
    )
    if "temperature" in analysis_raw:
        config.analysis.temperature = _bounded_number(
            analysis_raw["temperature"], "analysis.temperature", 0.0, 1.0
        )

    config.state_path = str(raw.get("state_path", DEFAULT_STATE_PATH))
    if "retain" in raw:
        config.retain = int(_bounded_number(raw["retain"], "retain", 2, 500))

    config.fail_on = str(raw.get("fail_on", "high")).strip().casefold()
    if config.fail_on not in SEVERITIES:
        raise ValidationError(f"fail_on must be one of {', '.join(SEVERITIES)}")

    config.output_format = str(raw.get("output_format", "markdown")).strip().casefold()
    if config.output_format not in FORMATS:
        raise ValidationError(f"output_format must be one of {', '.join(FORMATS)}")
    return config


def load_config(path: str | Path) -> Config:
    # Read through a descriptor rather than by path -- see
    # :func:`entsec.validation.read_text_file` for what is being refused and why.
    text = read_text_file(Path(path).expanduser(), max_bytes=_MAX_CONFIG_BYTES, what="config file")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValidationError(f"config file is not valid YAML: {exc}") from exc
    return parse_config(raw or {})
