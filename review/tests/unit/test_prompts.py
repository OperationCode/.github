import json
import re
from pathlib import Path

import pytest

REVIEW_DIR = Path(__file__).resolve().parents[2]
PROMPTS = REVIEW_DIR / "prompts"
SPEC = REVIEW_DIR.parent / "docs" / "claude-review-design.md"
FINDINGS_SCHEMA = REVIEW_DIR / "schema" / "findings.schema.json"

EXPECTED = {"system.md", "review.md", "security.md", "supply-chain.md"}
# Pass name -> max findings, from the spec's pass table.
PASSES = {"review": 10, "security": 10, "supply-chain": 15}

# Only a block on its own lines counts; inline mentions like "<grounding_rules>" in prose do not.
BLOCK_RE = re.compile(r"^<grounding_rules>\n(.*?)^</grounding_rules>$", re.M | re.S)
# The renderer fills {nonce}; prompts never hold a real one.
NONCE_PLACEHOLDER = "untrusted_pr_{nonce}"
LITERAL_NONCE_RE = re.compile(r"untrusted_pr_[0-9a-fA-F]{16}")
DELIM_RE = re.compile(r"untrusted_pr_(\{nonce\}|\*|\S*)")
PLACEHOLDER_RE = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


def grounding_blocks(text: str) -> list[str]:
    return BLOCK_RE.findall(text)


def prompt_files() -> list[Path]:
    return sorted(p for p in PROMPTS.rglob("*") if p.is_file())


def spec_block() -> str:
    blocks = grounding_blocks(SPEC.read_text(encoding="utf-8"))
    assert len(blocks) == 1, "spec must hold exactly one <grounding_rules> block"
    return blocks[0]


def test_expected_prompt_files_exist():
    names = {p.name for p in prompt_files()}
    assert EXPECTED <= names, f"missing prompt files: {EXPECTED - names}"


@pytest.mark.parametrize("path", prompt_files(), ids=lambda p: p.name)
def test_prompt_has_grounding_rules(path):
    blocks = grounding_blocks(path.read_text(encoding="utf-8"))
    assert len(blocks) == 1, f"{path.name}: expected one <grounding_rules> block, found {len(blocks)}"
    assert blocks[0].strip(), f"{path.name}: <grounding_rules> block is empty"
    assert blocks[0] == spec_block(), f"{path.name}: <grounding_rules> differs from the spec"


@pytest.mark.parametrize(
    "text",
    [
        "no block here",
        "<grounding_rules>\n</grounding_rules>\n",
        "<grounding_rules>\n   \n</grounding_rules>\n",
        "inline <grounding_rules> mention only </grounding_rules>",
    ],
)
def test_block_check_rejects_missing_or_empty(text):
    assert not any(b.strip() for b in grounding_blocks(text))


@pytest.mark.parametrize("path", prompt_files(), ids=lambda p: p.name)
def test_delimiter_is_placeholder_not_literal_nonce(path):
    text = path.read_text(encoding="utf-8")
    assert NONCE_PLACEHOLDER in text, f"{path.name}: must reference {NONCE_PLACEHOLDER}"
    assert not LITERAL_NONCE_RE.search(text), f"{path.name}: holds a literal nonce"
    outside_block = BLOCK_RE.sub("", text)
    for m in DELIM_RE.finditer(outside_block):
        assert m.group(1) == "{nonce}", f"{path.name}: bad delimiter reference {m.group(0)!r}"
    assert set(PLACEHOLDER_RE.findall(text)) == {"{nonce}"}, f"{path.name}: unknown placeholder"


def test_placeholder_fill_leaves_no_placeholder():
    nonce = "0123456789abcdef"
    for path in prompt_files():
        filled = path.read_text(encoding="utf-8").replace("{nonce}", nonce)
        assert f"untrusted_pr_{nonce}" in filled
        assert not PLACEHOLDER_RE.search(filled)


def test_system_prompt_states_output_contract():
    text = (PROMPTS / "system.md").read_text(encoding="utf-8")
    schema = json.loads(FINDINGS_SCHEMA.read_text(encoding="utf-8"))
    item = schema["properties"]["findings"]["items"]
    for field in schema["required"] + item["required"]:
        assert f"`{field}`" in text, f"system.md: output contract misses field {field}"
    for field in ("category", "severity", "confidence", "side"):
        for value in item["properties"][field]["enum"]:
            assert f"`{value}`" in text, f"system.md: misses {field} value {value}"
    assert "never give a verdict" in text


@pytest.mark.parametrize("name,cap", PASSES.items())
def test_pass_prompt(name, cap):
    text = (PROMPTS / f"{name}.md").read_text(encoding="utf-8")
    assert text.startswith(f"You are running the {name} pass.")
    assert f"At most {cap} findings." in text
    schema = json.loads(FINDINGS_SCHEMA.read_text(encoding="utf-8"))
    assert cap <= schema["properties"]["findings"]["maxItems"]
