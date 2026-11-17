"""Egress Firewall and Leak Blocker.

Enforces a strict deny-by-default security policy inspecting all tool calls,
arguments, and model outputs prior to execution or returning to the user.

Checks:
1. Tool allowlist: only explicitly whitelisted tools may be invoked.
2. Network egress: URL domains must exist in EGRESS_ALLOWED_DOMAINS (default: none).
3. Data exfiltration patterns: base64 blobs > 200 chars, data: URIs, markdown links/images
   with query strings, hex strings > 128 chars, and image SHA-256 leakage.
4. Prompt injection signals: forbidden phrases, zero-width, and bidi unicode characters.
5. Output size cap: strict response size bounds.

Audit Guarantee:
Every block writes an audit event with the rule_id and SHA-256 hash of the offending
content, NEVER the raw content itself.
"""

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Dict, List, Optional, Set
import unicodedata
import urllib.parse
import idna
from app.audit_log import AuditLogger, audit_logger
from app.config import get_settings


@dataclass(frozen=True)
class FirewallDecision:
    """Outcome of a firewall inspection."""

    allowed: bool
    rule_id: str
    reason: str
    redacted_output: Optional[str] = None


class EgressFirewall:
    """Deny-by-default firewall inspecting agent actions and model output."""

    # Zero-width and bidirectional Unicode control characters
    BIDI_ZERO_WIDTH_PATTERN = re.compile(
        r"[\u200b\u200c\u200d\ufeff\u2060\u200e\u200f\u202a-\u202e\u2066-\u2069]"
    )

    # Prompt injection phrases (evaluated after NFKC normalisation)
    PROMPT_INJECTION_PHRASES: tuple[str, ...] = (
        "ignore previous instructions",
        "send this image to",
        "upload to",
        "forward to",
        "reveal your system prompt",
    )

    # Hex strings longer than 128 chars
    HEX_PATTERN = re.compile(r"[0-9a-fA-F]{129,}")

    # Base64 continuous runs longer than 200 chars
    BASE64_CONTINUOUS_PATTERN = re.compile(r"[A-Za-z0-9+/=]{201,}")

    # Base64 chunk pattern for split/chunked base64 exfiltration
    BASE64_CHUNK_PATTERN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

    # Data URIs
    DATA_URI_PATTERN = re.compile(r"(?i)\bdata:[^\s,;]+;base64,")

    # Markdown links and images with query strings: ![alt](url?q) or [text](url?q)
    MARKDOWN_QUERY_PATTERN = re.compile(r"!?\[[^\]]*\]\([^\)\s]*\?[^\)\s]*\)")

    # Standard URL pattern for network egress
    URL_PATTERN = re.compile(
        r"""(?i)\b((?:https?|ftp|file)://[^\s<>"'{}|\\^`]+|www\.[^\s<>"'{}|\\^`]+)"""
    )

    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None,
        max_output_chars: int = 50000,
        logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize firewall with security policies.

        Args:
            allowed_tools: Permitted tool names (default: ["describe_image", "extract_text"]).
            allowed_domains: Permitted outbound domain names (default: empty list).
            max_output_chars: Maximum permitted character length for agent output.
            logger: AuditLogger instance for tamper-evident recording.
        """
        self.allowed_tools: Set[str] = set(
            allowed_tools
            if allowed_tools is not None
            else ["describe_image", "extract_text"]
        )

        settings = get_settings()
        if allowed_domains is not None:
            self.allowed_domains: Set[str] = {d.strip().lower() for d in allowed_domains if d.strip()}
        else:
            self.allowed_domains = set(settings.allowed_domains_list)

        self.max_output_chars: int = max_output_chars
        self.audit_logger: AuditLogger = logger or audit_logger

    def _block(
        self,
        rule_id: str,
        reason: str,
        session_id: str,
        image_sha256: str,
        offending_text: str,
    ) -> FirewallDecision:
        """Record audit event and return a blocked FirewallDecision.

        CRITICAL: Only the SHA-256 hash of offending_text is logged, NEVER the text itself.
        """
        text_hash = hashlib.sha256(offending_text.encode("utf-8")).hexdigest()
        self.audit_logger.log_event(
            event_type="firewall_block",
            session_id=session_id,
            image_sha256=image_sha256,
            metadata={
                "rule_id": rule_id,
                "reason": reason,
                "offending_text_sha256": text_hash,
            },
        )
        return FirewallDecision(
            allowed=False,
            rule_id=rule_id,
            reason=reason,
            redacted_output=None,
        )

    def _detect_split_base64(self, text: str) -> bool:
        """Detect split or whitespace-separated base64 blobs exceeding 200 characters."""
        if self.BASE64_CONTINUOUS_PATTERN.search(text):
            return True
        tokens = text.split()
        streak_len = 0
        for tok in tokens:
            if self.BASE64_CHUNK_PATTERN.match(tok):
                streak_len += len(tok)
                if streak_len > 200:
                    return True
            else:
                streak_len = 0
        return False

    def _is_domain_allowed(self, hostname: str) -> bool:
        """Check if hostname or its IDNA/punycode representation is whitelisted."""
        clean_host = hostname.strip().lower().split(":")[0]
        if not clean_host:
            return False
        if clean_host in self.allowed_domains:
            return True
        try:
            puny_host = idna.encode(clean_host).decode("ascii").lower()
            if puny_host in self.allowed_domains:
                return True
        except Exception:
            return False
        return False

    def _check_network_egress(self, text: str) -> Optional[str]:
        """Extract URLs and return the first disallowed URL found, or None."""
        matches = self.URL_PATTERN.findall(text)
        for raw_url in matches:
            cleaned_url = raw_url.rstrip(".,;:!?)")
            parsed = urllib.parse.urlsplit(cleaned_url)
            host = parsed.netloc or parsed.path.split("/")[0]
            if not self._is_domain_allowed(host):
                return cleaned_url
        return None

    def _check_prompt_injection(self, text: str) -> Optional[tuple[str, str]]:
        """Check for zero-width/bidi control chars and injection phrases.

        Returns:
            Optional[tuple[rule_id, reason]]: Block rule and reason, or None if clean.
        """
        # 1. Check for zero-width and bidirectional unicode control characters
        if self.BIDI_ZERO_WIDTH_PATTERN.search(text):
            return (
                "PROMPT_INJECTION_BIDI_ZERO_WIDTH",
                "Zero-width or bidirectional Unicode control characters detected.",
            )

        # 2. Strip control characters and normalise to NFKC
        cleaned = self.BIDI_ZERO_WIDTH_PATTERN.sub("", text)
        normalised = unicodedata.normalize("NFKC", cleaned).lower()

        # 3. Check for forbidden prompt-injection phrases
        for phrase in self.PROMPT_INJECTION_PHRASES:
            if phrase in normalised:
                return (
                    "PROMPT_INJECTION_PHRASE",
                    f"Prompt injection phrase detected: '{phrase}'.",
                )

        return None

    def _check_exfiltration(
        self, text: str, image_sha256: str
    ) -> Optional[tuple[str, str]]:
        """Inspect text for data exfiltration patterns.

        Returns:
            Optional[tuple[rule_id, reason]]: Detected exfiltration pattern, or None.
        """
        # 1. Session Image SHA-256 leakage
        if image_sha256 and image_sha256.lower() in text.lower():
            return (
                "EXFIL_IMAGE_SHA256",
                "Text contains session image SHA-256 digest.",
            )

        # 2. Data URIs
        if self.DATA_URI_PATTERN.search(text):
            return (
                "EXFIL_DATA_URI",
                "Data URI detected in text or arguments.",
            )

        # 3. Markdown images or links with query strings
        if self.MARKDOWN_QUERY_PATTERN.search(text):
            return (
                "EXFIL_MARKDOWN_QUERY",
                "Markdown link or image with query string detected.",
            )

        # 4. Hex strings > 128 characters
        if self.HEX_PATTERN.search(text):
            return (
                "EXFIL_HEX_STRING",
                "Hexadecimal string exceeding 128 characters detected.",
            )

        # 5. Base64 strings > 200 characters (continuous or split)
        if self._detect_split_base64(text):
            return (
                "EXFIL_BASE64_BLOB",
                "Base64 encoded blob exceeding 200 characters detected.",
            )

        return None

    def inspect_input_text(
        self, text: str, session_id: str, image_sha256: str
    ) -> FirewallDecision:
        """Inspect user prompt or extracted OCR text for prompt injection signals.

        Args:
            text: Text to evaluate.
            session_id: Active session identifier.
            image_sha256: Active image SHA-256 digest.

        Returns:
            FirewallDecision: Allowed or blocked status.
        """
        injection = self._check_prompt_injection(text)
        if injection is not None:
            rule_id, reason = injection
            return self._block(rule_id, reason, session_id, image_sha256, text)

        return FirewallDecision(
            allowed=True,
            rule_id="ALLOWED",
            reason="Input validation passed.",
            redacted_output=None,
        )

    def inspect_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str,
        image_sha256: str,
    ) -> FirewallDecision:
        """Validate an agent tool invocation against allowlists and exfiltration rules.

        Args:
            tool_name: Name of tool the agent attempts to call.
            tool_args: Dictionary of tool invocation arguments.
            session_id: Session identifier.
            image_sha256: Cryptographic hash of session image.

        Returns:
            FirewallDecision: Permitted or blocked outcome.
        """
        # 1. Tool allowlist check
        if tool_name not in self.allowed_tools:
            return self._block(
                rule_id="TOOL_NOT_ALLOWED",
                reason=f"Tool '{tool_name}' is not in the allowed tool registry.",
                session_id=session_id,
                image_sha256=image_sha256,
                offending_text=tool_name,
            )

        # 2. Extract and check all string arguments
        def extract_strings(val: Any) -> List[str]:
            res: List[str] = []
            if isinstance(val, str):
                res.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    res.extend(extract_strings(v))
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    res.extend(extract_strings(item))
            return res

        for arg_str in extract_strings(tool_args):
            # Check prompt injection
            injection = self._check_prompt_injection(arg_str)
            if injection is not None:
                rule_id, reason = injection
                return self._block(rule_id, reason, session_id, image_sha256, arg_str)

            # Check data exfiltration patterns first (e.g. markdown queries, data URIs, base64 blobs)
            exfil = self._check_exfiltration(arg_str, image_sha256)
            if exfil is not None:
                rule_id, reason = exfil
                return self._block(rule_id, reason, session_id, image_sha256, arg_str)

            # Check network egress
            disallowed_url = self._check_network_egress(arg_str)
            if disallowed_url is not None:
                return self._block(
                    rule_id="UNAUTHORIZED_EGRESS_URL",
                    reason=f"Unauthorized network egress URL detected: {disallowed_url}",
                    session_id=session_id,
                    image_sha256=image_sha256,
                    offending_text=disallowed_url,
                )

        return FirewallDecision(
            allowed=True,
            rule_id="ALLOWED",
            reason="Tool invocation passed all firewall checks.",
            redacted_output=None,
        )

    def inspect_model_output(
        self,
        output_text: str,
        session_id: str,
        image_sha256: str,
    ) -> FirewallDecision:
        """Inspect model generated output before returning to user or executing further.

        Args:
            output_text: Raw textual output from AI model.
            session_id: Session identifier.
            image_sha256: Cryptographic hash of session image.

        Returns:
            FirewallDecision: Permitted or blocked outcome.
        """
        # 1. Output size cap
        if len(output_text) > self.max_output_chars:
            return self._block(
                rule_id="OUTPUT_SIZE_EXCEEDED",
                reason=f"Output length {len(output_text)} exceeds maximum limit of {self.max_output_chars} chars.",
                session_id=session_id,
                image_sha256=image_sha256,
                offending_text=f"LENGTH:{len(output_text)}",
            )

        # 2. Data exfiltration patterns (markdown queries, data URIs, base64 blobs, image sha256)
        exfil = self._check_exfiltration(output_text, image_sha256)
        if exfil is not None:
            rule_id, reason = exfil
            return self._block(rule_id, reason, session_id, image_sha256, output_text)

        # 3. Network egress
        disallowed_url = self._check_network_egress(output_text)
        if disallowed_url is not None:
            return self._block(
                rule_id="UNAUTHORIZED_EGRESS_URL",
                reason=f"Unauthorized network egress URL detected in model output: {disallowed_url}",
                session_id=session_id,
                image_sha256=image_sha256,
                offending_text=disallowed_url,
            )

        # 4. Prompt injection signals in output
        injection = self._check_prompt_injection(output_text)
        if injection is not None:
            rule_id, reason = injection
            return self._block(rule_id, reason, session_id, image_sha256, output_text)

        return FirewallDecision(
            allowed=True,
            rule_id="ALLOWED",
            reason="Model output passed all firewall checks.",
            redacted_output=output_text,
        )
