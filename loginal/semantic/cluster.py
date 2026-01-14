try:
    import hdbscan
    HAS_HDBSCAN = True
except ImportError:
    HAS_HDBSCAN = False

try:
    import umap
    HAS_UMAP = True
except ImportError:
    HAS_UMAP = False

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple

class LogClusterer:
    """
    Clustering engine using HDBSCAN (Density-based) and UMAP (Dim Reduction).
    """

    def __init__(self):
        if not HAS_HDBSCAN:
            raise ImportError("hdbscan not installed. Please install it.")
        if not HAS_UMAP:
            raise ImportError("umap-learn not installed. Please install it.")

    def cluster_and_visualize(self, vectors: np.ndarray, min_cluster_size: int = 3) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        1. Reduce dimensions to 2D using UMAP (for viz).
        2. Cluster using HDBSCAN on the original (or reduced) vectors.
        
        Returns: 
           - DataFrame with columns ['x', 'y', 'label'] for plotting.
           - Array of cluster labels (-1 means noise).
        """
        if vectors.shape[0] < 5:
            # Too few points to cluster effectively
            return pd.DataFrame(), np.array([])
            
        # 1. UMAP for Visualization (2D)
        # We also use these 2D points for clustering to ensure the visual clusters match the algorithmic ones
        # (Though technically clustering on high-dim is better, for UI consistency 2D clustering is often preferred)
        reducer = umap.UMAP(
            n_components=2, 
            random_state=42,
            n_neighbors=5 if vectors.shape[0] < 20 else 15
        )
        embedding_2d = reducer.fit_transform(vectors)
        
        # 2. HDBSCAN Clustering
        clusterer = hdbscan.HDBSCAN(
            min_cluster_size=min_cluster_size,
            min_samples=1, # Sensitive to small clusters
            metric='euclidean'
        )
        labels = clusterer.fit_predict(embedding_2d)
        
        # Prepare DataFrame
        df = pd.DataFrame(embedding_2d, columns=['x', 'y'])
        df['label'] = labels
        df['label'] = df['label'].astype(str) # For categorical plotting
        
        return df, labels

    def generate_label(self, messages: List[str]) -> str:
        """
        Generate a human-readable label for a cluster using simple frequency analysis.
        """
        if not messages:
            return "Empty Cluster"
            
        # 1. Tokenize and Counts
        from collections import Counter
        import re
        
        tokens = []
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'from', 'of', 'for', 'with', 'by', 'and', 'or', 'is', 'are', 'was', 'were', 'log', 'event'}
        
        for m in messages:
            # Simple split by non-alphanumeric
            parts = re.split(r'[^a-zA-Z0-9_]', m.lower())
            for p in parts:
                if len(p) > 2 and p not in stop_words and not p.isdigit():
                    tokens.append(p)
                    
        counts = Counter(tokens)
        
        # 2. Extract Top 3 Keywords
        top_k = counts.most_common(3)
        if not top_k:
            return "Unknown Pattern"
            
        label = " / ".join([t[0] for t in top_k])
        return f"{label} ({len(messages)} events)"
