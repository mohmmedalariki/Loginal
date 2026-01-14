import yaml
import os
import re
from typing import List, Dict, Any, Callable
from .rules import DetectionRule, LogEvent

class SigmaLoader:
    """
    Loads Sigma rules from YAML files and converts them to DetectionRules.
    MVP implementation supporting basic field matching and keywords.
    """
    
    def load_from_directory(self, rule_dir: str) -> List[DetectionRule]:
        rules = []
        if not os.path.exists(rule_dir):
            return []

        for root, _, files in os.walk(rule_dir):
            for file in files:
                if file.endswith(".yml") or file.endswith(".yaml"):
                    try:
                        rule = self._parse_file(os.path.join(root, file))
                        if rule:
                            rules.append(rule)
                    except Exception as e:
                        # Log warning but continue
                        print(f"Failed to parse {file}: {e}")
        return rules

    def _parse_file(self, path: str) -> DetectionRule:
        with open(path, 'r') as f:
            data = yaml.safe_load(f)

        if not data or 'detection' not in data:
            return None

        title = data.get('title', 'Unknown Sigma Rule')
        description = data.get('description', '')
        level = data.get('level', 'medium')
        tags = data.get('tags', [])
        
        # Build condition
        # This is the complex part. We need to parse 'detection' section.
        # For MVP, we support 'keywords' and simple field map.
        detection = data['detection']
        condition_str = detection.get('condition', '')
        
        # We need to construct a lambda that evaluates this
        # Simplification: if condition is just "selection", "keywords", or "all of ..."
        
        # 1. Parse 'selection' or 'keywords' chunks
        matchers = {}
        for key, value in detection.items():
            if key == 'condition': 
                continue
            matchers[key] = self._build_matcher(value)

        # 2. Build final condition function
        # Support basic "selection" or "keywords" logic
        def condition_func(event: LogEvent) -> bool:
            # Very naive condition parser for MVP
            # If "selection" in detection, logic is usually AND within selection
            # logic is usually AND/OR between named blocks based on 'condition' string
            
            # Simple fallback: if any matcher returns True, we might say match?
            # No, we must respect 'condition'.
            
            # Case 1: condition: selection
            if condition_str.strip() in matchers:
                 return matchers[condition_str.strip()](event)
                 
            # Case 2: condition: keywords
            if 'keywords' in matchers and condition_str == 'keywords':
                return matchers['keywords'](event)
            
            # Case 3: "all of selection" or just check all (default fallback)
            # If we match ALL defined blocks (AND logic)
            all_match = True
            for matcher in matchers.values():
                if not matcher(event):
                    all_match = False
                    break
            return all_match

        return DetectionRule(
            name=title,
            severity=level,
            condition=condition_func,
            description=description,
            tags=tags
        )

    def _build_matcher(self, logic: Any) -> Callable[[LogEvent], bool]:
        """
        Convert a Sigma detection block (dict or list) into a callable.
        """
        # List of strings -> OR keywords search
        if isinstance(logic, list):
            # Keyword search in message or full raw
            keywords = [str(k).lower() for k in logic]
            return lambda e: any(k in e.message.lower() for k in keywords)

        # Dict -> Field matching (AND implied usually)
        if isinstance(logic, dict):
            # e.g. { 'EventID': 4624, 'AccountType': 'User' }
            def matcher(event: LogEvent) -> bool:
                for field, target in logic.items():
                    # Map sigma field to LogEvent field if possible, else check original_data
                    # Naive mapping
                    val = None
                    if field.lower() == 'user': val = event.user
                    elif field.lower() == 'host': val = event.host
                    else:
                        # Inspect original data
                        val = event.original_data.get(field)
                        if not val and 'raw_text' in event.original_data:
                            # fallback search in raw? strict sigma says no, but for MVP flexible
                            pass

                    if val is None:
                        return False
                    
                    # Equality check (support list as OR)
                    if isinstance(target, list):
                        if str(val) not in [str(t) for t in target]:
                            return False
                    else:
                        if str(val) != str(target):
                            return False
                return True
            return matcher

        return lambda e: False
