import os
import json
import re
import google.generativeai as genai
from typing import Dict, Any, List, Optional
from .prompts import AIGeneratorPrompts

class AIGateway:
    """
    Production-ready wrapper for Google Gemini 2.5 API.
    Handles JSON cleanup and Rate Limits.
    NOTE: Using Sync methods to avoid Streamlit 'Event Loop Closed' errors.
    """
    
    # No hardcoded key. Must be provided via Env Var or GUI.
    
    def __init__(self, api_key: str = None):
        self.usage_stats = {"bulk_calls": 0, "expert_calls": 0}
        
        # 1. SECURITY: Check Param, then Env Var
        self.api_key = api_key or os.getenv("LOGINAL_GEMINI_KEY")
        
        if not self.api_key:
            # We don't raise error here anymore to allow GUI to show "Configure Settings" message
            # raise ValueError("❌ CRITICAL: LOGINAL_GEMINI_KEY environment variable not set.")
            print("Warning: Gemini API Key not set.")
            self.bulk_model = None
            self.expert_model = None
            return
        
        genai.configure(api_key=self.api_key)
        
        # 2. MODELS (2026 Standard)
        self.bulk_model = genai.GenerativeModel("gemini-2.5-flash")
        self.expert_model = genai.GenerativeModel("gemini-2.5-pro")
        
        self.usage_stats = {"bulk_calls": 0, "expert_calls": 0}

    def _clean_json_markdown(self, text: str) -> str:
        """
        Robustly extracts JSON from Markdown text blocks using Regex.
        """
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            return match.group(1)
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            return match.group(1)
        return text

    def analyze_bulk(self, samples: List[str], delimiter_hint: str = None) -> Dict[str, Any]:
        """
        Sync analysis.
        """
        try:
            prompt = AIGeneratorPrompts.get_bulk_analysis_prompt(samples, delimiter_hint)
            
            resp = self.bulk_model.generate_content(prompt)
            self.usage_stats["bulk_calls"] += 1
            
            clean_text = self._clean_json_markdown(resp.text)
            return json.loads(clean_text)

        except Exception as e:
            return {
                "error": True, 
                "message": f"AI Error: {str(e)}",
                "raw_response": str(e)
            }

    def generate_rule_expert(self, samples: List[str], bulk_summary: dict, description: str) -> str:
        """
        Uses Expert model to write Sigma rules.
        """
        try:
            prompt = AIGeneratorPrompts.get_expert_sigma_prompt(samples, bulk_summary, description)
            
            resp = self.expert_model.generate_content(prompt)
            self.usage_stats["expert_calls"] += 1
            
            text = resp.text.strip()
            if text.startswith("```"):
                lines = text.splitlines()
                if "yaml" in lines[0] or "sigma" in lines[0]:
                    text = "\n".join(lines[1:-1])
                else: 
                     text = "\n".join(lines[1:-1])
            
            return text
            
        except Exception as e:
            return f"# Generation Error: {str(e)}"

    def generate_triage(self, provenance_data: dict) -> Dict[str, Any]:
        """
        Bulk Triage Analysis.
        """
        try:
            # Convert dict to pretty string for prompt
            prov_str = json.dumps(provenance_data, indent=2)
            prompt = AIGeneratorPrompts.get_triage_prompt(prov_str)
            
            resp = self.bulk_model.generate_content(prompt)
            self.usage_stats["bulk_calls"] += 1
            
            clean_text = self._clean_json_markdown(resp.text)
            return json.loads(clean_text)
        except Exception as e:
            return {"error": str(e), "summary": "AI Error during triage."}

    def generate_root_cause(self, provenance_data: dict) -> str:
        """
        Expert Root Cause Analysis.
        """
        try:
            prov_str = json.dumps(provenance_data, indent=2)
            prompt = AIGeneratorPrompts.get_root_cause_prompt(prov_str)
            
            resp = self.expert_model.generate_content(prompt)
            self.usage_stats["expert_calls"] += 1
            
            text = resp.text.strip()
            # Clean preamble if it exists (Look for first header)
            if "## Executive Summary" in text:
                text = text[text.find("## Executive Summary"):]
            elif "# Executive Summary" in text:
                text = text[text.find("# Executive Summary"):]
            
            return text
        except Exception as e:
            return f"Error analyzing root cause: {str(e)}"

    def explain_event(self, event_data: dict) -> Dict[str, Any]:
        """
        Single Event Explanation.
        """
        if not self.bulk_model:
            return {"explanation": "AI API Key is missing. Please configure it in Settings.", "is_malicious": False, "confidence": "error"}

        try:
            event_str = json.dumps(event_data, indent=2)
            prompt = AIGeneratorPrompts.get_explain_prompt(event_str)
            
            resp = self.bulk_model.generate_content(prompt)
            self.usage_stats["bulk_calls"] += 1
            
            clean_text = self._clean_json_markdown(resp.text)
            return json.loads(clean_text)
        except Exception as e:
             return {"explanation": f"Error: {str(e)}", "is_malicious": False, "confidence": "low"}

    def get_usage(self):
        return self.usage_stats
