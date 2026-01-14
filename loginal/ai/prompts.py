from typing import List

class AIGeneratorPrompts:
    @staticmethod
    def get_bulk_analysis_prompt(samples: List[str], delimiter_hint: str = None) -> str:
        """
        Prompt for Gemini 2.5 Flash (Bulk Layer).
        Goal: Summarize patterns and extraction tokens.
        """
        samples_str = "\n".join(samples[:50]) # Limit to 50 lines
        
        hint_text = ""
        if delimiter_hint:
             hint_text = f"IMPORTANT: The system has detected that these logs are separated by {delimiter_hint}. Respect this structure."

        return f"""
You are a Security Log Analyst. Analyze the following log samples and extract key patterns.
Goal: Identify the log format, key fields (IP, User, Host), and any potential anomalies.

LOG SAMPLES:
---
{samples_str}
---

{hint_text}

CRITICAL INSTRUCTIONS:
1. **JSON Only**: Output MUST be valid, parseable JSON. Do not include markdown keys like `[0:"Index"]` (invalid). Use `["Field", "Value"]`.
2. **Regex Safety**: If fields contain spaces (e.g. "Outbound Traffic Spike"), DO NOT use lazy matches `.*?` followed by `\\s`. Use greedy matches `.*` anchored by the next KNOWN delimiter (like `\\t` or `|`).
3. **Delimiter Check**: If logs are tab-separated, mention that in "pattern_summary".

OUTPUT FORMAT (JSON):
{{
  "log_format": "syslog/json/apache/custom",
  "delimiter": "\\t or space or CSV...",
  "pattern_summary": "Brief description of the event structure",
  "extracted_fields": ["list", "of", "field_names"],
  "regex_candidate": "Safest regex to capture the main message",
  "anomalies": ["List of any suspicious keywords found"]
}}
"""

    @staticmethod
    def get_expert_sigma_prompt(samples: List[str], bulk_summary: dict, description: str) -> str:
        """
        Prompt for Gemini Expert Layer.
        Goal: Generate a valid Sigma YAML rule.
        """
        import datetime
        today = datetime.datetime.now().strftime("%Y/%m/%d")

        samples_str = "\n".join(samples[:20]) # Precise samples
        return f"""
You are a Senior Threat Hunter. Write a Sigma Rule (YAML) to detect the following activity.

USER DESCRIPTION: {description}

BULK ANALYSIS CONTEXT:
Format: {bulk_summary.get('log_format', 'Unknown')}
Patterns: {bulk_summary.get('pattern_summary', 'N/A')}

LOG SAMPLES (Positive Matches):
---
{samples_str}
---

REQUIREMENTS:
1. Output ONLY the raw Sigma YAML block. No markdown fencing if possible, or inside ```yaml```.
2. Use standard fields (title, id, status, description, logsource, detection, condition, level).
3. Ensure the detection logic matches the provided samples.
4. Add a comment in the 'description' explaining the logic.
5. METADATA: Use the date {today} in the 'date' field.
6. PRECISION: If specific users or hosts are mentioned in the description, include them in the selection.

OUTPUT:
"""

    @staticmethod
    def get_triage_prompt(provenance_str: str) -> str:
        """
        Prompt for Gemini Flash (Bulk).
        Goal: Rapid Incident Triage & Summary.
        """
        return f"""
You are a SOC Automation Bot. Triage this incident based on the provenance facts.
GOAL: Provide a 2-sentence executive summary and 3 prioritized triage steps.

INCIDENT FACTS (PROVENANCE):
{provenance_str}

OUTPUT FORMAT (JSON):
{{
  "summary": "Short 2-sentence description of what happened and why it matters.",
  "priority_score": 85, // 0-100 based on severity and entities involved
  "triage_steps": [
    "Step 1: Check X",
    "Step 2: Isolate Y",
    "Step 3: Verify Z"
  ]
}}
"""

    @staticmethod
    def get_root_cause_prompt(provenance_str: str) -> str:
        """
        Prompt for Gemini Pro (Expert).
        Goal: Deep Forensic Analysis.
        """
        return f"""
You are a Principal Forensic Analyst. Perform a Root Cause Analysis (RCA) on this incident.
GOAL: Explain the attack chain, likely root cause, and suggested remediation.

INCIDENT FACTS:
{provenance_str}

REQUIREMENTS:
1. DO NOT include any conversational text like "Here is the report". Start directly with the markdown headers.
2. Explain the "Who, What, Where, When, Why".
3. Decode any obfuscation if visible.
4. Suggest specific mitigation commands (e.g. firewall block, kill process).

OUTPUT FORMAT (Markdown):
## Executive Summary
...
## Forensic Analysis
...
## Attack Chain
1. Initial Access...
2. Execution...
...
## Recommended Mitigation
- [ ] Action 1...
"""

    @staticmethod
    def get_explain_prompt(event_str: str) -> str:
        """
        Prompt for Gemini Flash (Bulk).
        Goal: Explain a single log event in plain English.
        """
        return f"""
You are a Security Analyst. Explain this log event in plain English.
GOAL: Provide a concise explanation of what this event means for a non-technical user, and assess if it is malicious.

EVENT DATA:
{event_str}

OUTPUT FORMAT (JSON):
{{
  "explanation": "2-3 sentences explaining the event.",
  "is_malicious": true/false,
  "confidence": "high/medium/low"
}}
"""
