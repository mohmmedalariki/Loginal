import re

class Patterns:
    """
    Centralized collection of Regex patterns for IOC detection.
    """
    
    # Networking
    IPV4 = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    URL = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
    DOMAIN = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Hashes
    MD5 = r'\b[a-fA-F0-9]{32}\b'
    SHA1 = r'\b[a-fA-F0-9]{40}\b'
    SHA256 = r'\b[a-fA-F0-9]{64}\b'
    
    # Encodings
    BASE64 = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'

    # Filter Lists (for domains)
    IGNORED_EXTS = ['.php', '.js', '.css', '.html', '.py', '.txt', '.log', '.json', '.xml', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']

    @staticmethod
    def get_all_iocs(text: str) -> dict:
        """
        Helper to extract all supported IOCs from text.
        Returns a dict of {kind: [unique_values]}
        """
        results = {}
        for kind, pat in [
            ("IP", Patterns.IPV4),
            ("Domain", Patterns.DOMAIN),
            ("URL", Patterns.URL),
            ("MD5", Patterns.MD5),
            ("SHA1", Patterns.SHA1),
            ("SHA256", Patterns.SHA256)
        ]:
            matches = list(set(re.findall(pat, text)))
            
            # Domain Filtering
            if kind == "Domain":
                matches = [m for m in matches if not any(m.lower().endswith(ext) for ext in Patterns.IGNORED_EXTS)]
            
            if matches:
                results[kind] = matches
        return results
