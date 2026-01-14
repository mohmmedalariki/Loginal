from urllib.parse import urlparse, parse_qs, unquote
import base64
import re
from typing import Dict, Any, List

class URLAnalyzer:
    """
    Analyzes URLs for forensic artifacts, decoding, and IOC extraction.
    """
    
    # Regex for finding IPv4 addresses
    IPV4_REGEX = re.compile(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}')
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Decompose and analyze a URL.
        """
        if not url:
            return {}

        # 1. Basic Parsing
        # Handle "defanged" URLs common in security logs (e.g. hxxp://)
        clean_url = url.replace("hxxp", "http").replace("[.]", ".")
        
        try:
            parsed = urlparse(clean_url)
        except Exception as e:
            return {"error": f"Parse error: {str(e)}", "original": url}

        result = {
            "original": url,
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment,
            "defanged": url != clean_url
        }

        # 2. Query Parameter Analysis & Decoding
        query_params = parse_qs(parsed.query)
        decoded_params = {}
        
        for k, v_list in query_params.items():
            for v in v_list:
                # Check for Base64
                decoded = self._try_base64(v)
                if decoded:
                    if "decoded_payloads" not in result:
                        result["decoded_payloads"] = []
                    result["decoded_payloads"].append({
                        "source": "query_param",
                        "key": k,
                        "value": decoded
                    })

        # 3. IOC Extraction
        iocs = []
        # Check netloc for IP
        if self.IPV4_REGEX.match(parsed.netloc):
            iocs.append({"type": "ip", "value": parsed.netloc})
            
        # Check path/query for embedded IPs (e.g. redirect usage)
        for ip in self.IPV4_REGEX.findall(parsed.path + parsed.query):
            iocs.append({"type": "embedded_ip", "value": ip})

        if iocs:
            result["extracted_iocs"] = iocs

        return result

    def _try_base64(self, s: str) -> str:
        """Attempt to decode a string as Base64."""
        if len(s) < 4:
            return None
        
        # Add padding if missing
        pad = len(s) % 4
        if pad > 0:
            s += "=" * (4 - pad)
            
        try:
            # URL-safe decoder usually handles standard too, but let's be safe
            decoded_bytes = base64.urlsafe_b64decode(s)
            
            # Heuristic: is it readable text?
            try:
                decoded_str = decoded_bytes.decode('utf-8')
                # If it has too many non-printable chars, might be binary junk
                # Simple check: 90% printable
                printable = sum(1 for c in decoded_str if c.isprintable())
                if printable / len(decoded_str) > 0.8:
                    return decoded_str
            except UnicodeDecodeError:
                pass
        except Exception:
            pass
            
        return None
