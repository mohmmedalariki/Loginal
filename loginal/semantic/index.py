import faiss
import numpy as np
import os
from typing import List, Tuple

class VectorIndex:
    """
    Wraps FAISS for simple IndexFlatIP.
    Pure Vector Store (Metadata moved to SQLite).
    """
    
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.index = faiss.IndexFlatIP(dimension)
        self.next_id = 0

    def add_vectors(self, vectors: np.ndarray):
        """
        Add vectors to the index. Returns the start_id for metadata mapping.
        """
        n = len(vectors)
        self.index.add(vectors.astype('float32'))
        
        start_id = self.next_id
        self.next_id += n
        return start_id

    def search(self, query_vector: np.ndarray, k: int = 10) -> Tuple[List[int], List[float]]:
        """
        Search for nearest neighbors.
        Returns (List[VectorIDs], List[Scores])
        """
        # Ensure query is 2D array
        if len(query_vector.shape) == 1:
            query_vector = query_vector.reshape(1, -1)
            
        distances, indices = self.index.search(query_vector.astype('float32'), k)
        
        result_ids = []
        scores = []
        
        # We only did 1 query, take 0th result
        for idx, score in zip(indices[0], distances[0]):
            if idx != -1:
                result_ids.append(int(idx))
                scores.append(float(score))
                
        return result_ids, scores

    def save(self, directory: str):
        """Persist index state."""
        os.makedirs(directory, exist_ok=True)
        faiss.write_index(self.index, os.path.join(directory, "vector.index"))
        with open(os.path.join(directory, "state.txt"), "w") as f:
            f.write(str(self.next_id))

    def load(self, directory: str):
        """Load index state."""
        idx_path = os.path.join(directory, "vector.index")
        state_path = os.path.join(directory, "state.txt")
        
        if os.path.exists(idx_path):
            self.index = faiss.read_index(idx_path)
            if os.path.exists(state_path):
                with open(state_path, "r") as f:
                    self.next_id = int(f.read().strip())
            return True
        return False
