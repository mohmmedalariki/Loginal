import re
from sentence_transformers import SentenceTransformer
import os
from typing import List, Dict, Union
import numpy as np

class LogEmbedder:
    """
    Wraps sentence-transformers model for log embedding.
    Model: all-MiniLM-L6-v2 (Small, Fast, Good Quality)
    """
    MODEL_NAME = "all-MiniLM-L6-v2"
    
    def __init__(self):
        # This will download the model to ~/.cache/torch/sentence_transformers on first run
        self.model = SentenceTransformer(self.MODEL_NAME)
        self.vector_dim = 384

    @staticmethod
    def normalize_text(text: str) -> str:
        """
        Redacts high-variance tokens (IPs, Dates, UUIDs) to focus on semantics.
        """
        if not text: return ""
        
        # 1. UUIDs
        text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', text, flags=re.I)
        # 2. IP Addresses (Simple)
        text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', text)
        # 3. Timestamps (ISO-ish)
        text = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', '<DATE>', text)
        # 4. Hex Strings (long)
        text = re.sub(r'\b0x[a-f0-9]+\b', '<HEX>', text, flags=re.I)
        
        return text.lower().strip()

    @staticmethod
    def format_log(event: Dict) -> str:
        """
        Constructs the semantic string: "event_type | message | host user"
        """
        msg = event.get('message', '')
        evt_type = event.get('event_type', 'unknown')
        host = event.get('host', '')
        user = event.get('user', '')
        
        # "ssh_failed | password for root failed | web01 root"
        # We put strict semantic info first
        raw = f"{evt_type} | {msg} | {host} {user}"
        return LogEmbedder.normalize_text(raw)

    def embed_logs(self, inputs: Union[List[str], List[Dict]], batch_size: int = 128) -> np.ndarray:
        """
        Embed a list of raw strings or Log Event Dicts.
        """
        if not inputs:
            return np.array([])
        
        processed = []
        for item in inputs:
            if isinstance(item, dict):
                processed.append(self.format_log(item))
            else:
                processed.append(self.normalize_text(str(item)))
        
        embeddings = self.model.encode(
            processed, 
            batch_size=batch_size, 
            show_progress_bar=True, 
            normalize_embeddings=True # Crucial for cosine similarity via dot product
        )
        
        return embeddings
