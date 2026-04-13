import json
import logging
import os
import uuid
from typing import List, Dict, Tuple, Any, Optional
from uuid import uuid4
from langchain_core.documents import Document as LangchainDocument
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_community.vectorstores.utils import filter_complex_metadata
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
import chromadb
from chromadb.errors import UniqueConstraintError
from asteraskills.config.settings import get_settings
from collections import defaultdict
from sklearn.feature_extraction.text import TfidfVectorizer
from enum import Enum, auto

import numpy as np

# Qdrant imports (optional, will fail gracefully if not installed)
try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    # Try new QdrantVectorStore first (langchain 0.2+), fall back to deprecated Qdrant
    try:
        from langchain_qdrant import QdrantVectorStore as LangchainQdrant
    except ImportError:
        from langchain_qdrant import Qdrant as LangchainQdrant
    QDRANT_AVAILABLE = True
except ImportError:
    QDRANT_AVAILABLE = False
    QdrantClient = None
    LangchainQdrant = None

# Check ChromaDB version and warn about potential issues
try:
    chromadb_version = chromadb.__version__
    logger = logging.getLogger(__name__)
    logger.info(f"ChromaDB version: {chromadb_version}")
    
    # Warn about known problematic versions
    if chromadb_version.startswith("0.6."):
        logger.warning(f"ChromaDB version {chromadb_version} may have compatibility issues. Consider upgrading to 1.0.x")
    elif chromadb_version.startswith("0.4.") or chromadb_version.startswith("0.5."):
        logger.warning(f"ChromaDB version {chromadb_version} is very old and may have significant issues. Consider upgrading to 1.0.x")
except Exception as e:
    logger.warning(f"Could not determine ChromaDB version: {e}")
settings = get_settings()
logger = logging.getLogger(__name__)
embedding_provider: str = "openai"
embedding_model: str = "text-embedding-3-small"


def sanitize_collection_name(name: str) -> str:
    """
    Sanitize collection name to comply with ChromaDB naming rules.
    
    ChromaDB collection names must:
    1. Contain 3-63 characters
    2. Start and end with an alphanumeric character
    3. Otherwise contain only alphanumeric characters, underscores or hyphens (-)
    4. Contain no two consecutive periods (..)
    5. Not be a valid IPv4 address
    
    Args:
        name: Collection name to sanitize
        
    Returns:
        Sanitized collection name that complies with ChromaDB rules
    """
    if not name:
        return "collection"
    
    # Remove leading/trailing non-alphanumeric characters (except underscores/hyphens in middle)
    # Replace leading underscores/hyphens with 'c' (collection)
    sanitized = name.strip()
    
    # If name starts with underscore or hyphen, prefix with 'c'
    if sanitized and sanitized[0] in ['_', '-']:
        sanitized = 'c' + sanitized
    
    # If name ends with underscore or hyphen, append '0'
    if sanitized and sanitized[-1] in ['_', '-']:
        sanitized = sanitized + '0'
    
    # Replace invalid characters (keep only alphanumeric, underscore, hyphen)
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', sanitized)
    
    # Replace consecutive periods with single underscore
    sanitized = re.sub(r'\.\.+', '_', sanitized)
    
    # Ensure minimum length of 3
    if len(sanitized) < 3:
        sanitized = sanitized.ljust(3, '0')
    
    # Truncate to max length of 63
    if len(sanitized) > 63:
        sanitized = sanitized[:63]
        # Ensure it still ends with alphanumeric
        if sanitized[-1] in ['_', '-']:
            sanitized = sanitized[:-1] + '0'
    
    # Final check: ensure it starts and ends with alphanumeric
    if sanitized and not sanitized[0].isalnum():
        sanitized = 'c' + sanitized[1:] if len(sanitized) > 1 else 'collection'
    if sanitized and not sanitized[-1].isalnum():
        sanitized = sanitized[:-1] + '0' if len(sanitized) > 1 else 'collection'
    
    return sanitized


_embeddings_instance: Optional[OpenAIEmbeddings] = None


def _ensure_embeddings() -> OpenAIEmbeddings:
    global _embeddings_instance
    if _embeddings_instance is None:
        key = settings.OPENAI_API_KEY or os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(
                "OPENAI_API_KEY is required for embedding-backed vector operations "
                "(semantic search tools). Set it in the environment or repo .env."
            )
        _embeddings_instance = OpenAIEmbeddings(
            model=embedding_model,
            openai_api_key=key,
        )
    return _embeddings_instance


class _LazyEmbeddings:
    def __getattr__(self, name: str):
        return getattr(_ensure_embeddings(), name)


embeddings_model = _LazyEmbeddings()
CHROMA_STORE_PATH = settings.CHROMA_STORE_PATH

class ChromaDBEmbeddingFunction:
    """ChromaDB-compatible embedding function wrapper for Langchain OpenAIEmbeddings."""
    
    def __init__(self, langchain_embeddings: OpenAIEmbeddings):
        self.langchain_embeddings = langchain_embeddings
    
    def __call__(self, input: List[str]) -> List[List[float]]:
        """
        Convert texts to embeddings using the Langchain model.
        
        Note: ChromaDB 0.4.16+ requires the parameter to be named 'input' instead of 'texts'.
        """
        return self.langchain_embeddings.embed_documents(input)

class DuplicatePolicy(Enum):
    """Policy for handling duplicate documents in the store."""
    SKIP = auto()  # Skip duplicate documents
    OVERWRITE = auto()  # Overwrite existing documents
    FAIL = auto()  # Raise an error if duplicates are found

class BM25Ranker:
    """BM25 ranking implementation for document search."""
    
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.vectorizer = TfidfVectorizer(
            stop_words='english',
            lowercase=True,
            ngram_range=(1, 2)
        )
        self.doc_freqs = None
        self.avgdl = 0
        self.doc_count = 0
        self.doc_lens = []
        self.doc_vectors = None
        
    def fit(self, documents: List[str]):
        """Fit the BM25 ranker on a collection of documents."""
        if not documents:
            return
            
        # Transform documents to TF-IDF vectors
        self.doc_vectors = self.vectorizer.fit_transform(documents)
        
        # Calculate document frequencies
        self.doc_freqs = self.vectorizer.idf_
        
        # Calculate average document length
        self.doc_lens = [len(doc.split()) for doc in documents]
        self.avgdl = sum(self.doc_lens) / len(documents)
        self.doc_count = len(documents)
        
    def rank(self, query: str, k: int = 5) -> List[Tuple[int, float]]:
        """Rank documents based on BM25 score for a query."""
        if not self.doc_vectors or not self.doc_freqs:
            return []
            
        # Transform query to TF-IDF vector
        query_vector = self.vectorizer.transform([query])
        
        # Calculate BM25 scores
        scores = []
        for i in range(self.doc_count):
            # Calculate term frequency in query
            query_tf = query_vector[0, i]
            
            # Calculate document length normalization
            doc_len = self.doc_lens[i]
            length_norm = (1 - self.b + self.b * doc_len / self.avgdl)
            
            # Calculate BM25 score
            score = query_tf * self.doc_freqs[i] * (self.k1 + 1) / (self.k1 + length_norm)
            scores.append((i, float(score)))
            
        # Sort by score and return top k
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:k]

class DocumentVectorstore:
    """Handle FAISS vectorstore operations."""

    def __init__(self, vectorstore_path: str, embeddings_model: OpenAIEmbeddings):
        self.vectorstore_path = vectorstore_path
        self.embeddings_model = embeddings_model
        self.vectorstore = None

    def initialize(self):
        """Initialize or load FAISS vectorstore."""
        if os.path.exists(self.vectorstore_path):
            logger.info(f"Loading FAISS vectorstore from {self.vectorstore_path}")
            self.vectorstore = FAISS.load_local(
                self.vectorstore_path, self.embeddings_model, allow_dangerous_deserialization=True
            )
        else:
            logger.info(f"Initializing new FAISS vectorstore at {self.vectorstore_path}")
            # Only initializes a new FAISS vectorstore when documents with embeddings are provided
            self.vectorstore = None

    def add_documents(self, documents: List[LangchainDocument]):
        """Add documents to the vectorstore."""
        if not documents:
            logger.warning("No documents provided to add to the vectorstore.")
            return

        if not self.vectorstore:
            logger.info("Initializing FAISS vectorstore.")
            self.vectorstore = FAISS.from_documents(documents, self.embeddings_model)
        else:
            logger.info("Adding documents to the existing vectorstore.")
            self.vectorstore.add_documents(documents)

        self.vectorstore.save_local(self.vectorstore_path)
        logger.info(f"Added {len(documents)} documents to the vectorstore.")

    def semantic_search(self, query: str, k: int = 5) -> List[Dict]:
        """Perform semantic search on the vectorstore.
        
        Args:
            query: The search query string
            k: Number of results to return (default: 5)
            
        Returns:
            List of dictionaries containing search results with scores
        """
        if not self.vectorstore:
            logger.warning("Vectorstore not initialized. Please initialize first.")
            return []
            
        try:
            # Perform similarity search with scores
            results = self.vectorstore.similarity_search_with_score(query, k=k)
            
            # Format results
            formatted_results = []
            for doc, score in results:
                formatted_results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "score": float(score),  # Convert numpy float to Python float
                    "id": doc.metadata.get("id", None)
                })
            
            # Sort results by score (lower is better for FAISS)
            formatted_results.sort(key=lambda x: x["score"])
            
            logger.info(f"Found {len(formatted_results)} results for query: {query}")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error during semantic search: {str(e)}")
            return []

    def bulk_add_data(self, data: List[Dict[str, Any]]):
        """Add multiple insights at once.
        
        Args:
            insights: List of insight dictionaries with keys:
                     title, content, scenario, tags (optional), metadata (optional)
        """
        documents = []
        for element in data:
            meta = element.get("metadata", {})
            for key in meta:
                meta.update({
                    key: element[key]
                })
            
            documents.append(LangchainDocument(
                page_content=element["content"],
                metadata=meta
            ))
        
        self.store.add_documents(documents)
        
    def delete_insights(self, ids: List[str]):
        """Delete insights by their IDs.
        
        Args:
            ids: List of document IDs to delete
        """
        self.store.delete(ids)

    def delete_by_project_id(self, project_id: str) -> Dict[str, int]:
        """Delete all documents for a specific project ID.
        
        Args:
            project_id: The project ID to delete documents for
            
        Returns:
            Dictionary containing the number of documents deleted
        """
        try:
            logger.info(f"Deleting documents for project ID: {project_id}")
            print(f"DEBUG: Collection name: {self.collection_name}")
            print(f"DEBUG: Collection object: {self.collection}")
            
            # Get all documents with the specified project_id to count them
            where_clause = {"project_id": project_id}
            print(f"DEBUG: Using where clause: {where_clause}")
            
            results = self.collection.get(where=where_clause)
            print(f"DEBUG: Query results: {results}")
            document_count = len(results['ids']) if results['ids'] else 0
            print(f"DEBUG: Found {document_count} documents to delete")
            
            if document_count == 0:
                logger.info(f"No documents found for project ID: {project_id}")
                return {"documents_deleted": 0}
            
            # Delete documents with the specified project_id
            print(f"DEBUG: Attempting to delete documents with where clause: {where_clause}")
            self.collection.delete(where=where_clause)
            print(f"DEBUG: Delete operation completed")
            
            # Also delete from TF-IDF collection if enabled
            if self.tf_idf and self.tfidf_collection:
                try:
                    self.tfidf_collection.delete(where={"project_id": project_id})
                    logger.info(f"Deleted {document_count} documents from TF-IDF collection for project ID: {project_id}")
                except Exception as e:
                    logger.warning(f"Error deleting from TF-IDF collection: {str(e)}")
            
            logger.info(f"Successfully deleted {document_count} documents for project ID: {project_id}")
            return {"documents_deleted": document_count}
            
        except Exception as e:
            error_msg = f"Error deleting documents for project ID {project_id}: {str(e)}"
            logger.error(error_msg)
            return {"documents_deleted": 0, "error": str(e)}

        
    def semantic_search_with_bm25(self, query: str, k: int = 5) -> List[Dict]:
        """Perform semantic search using both vector similarity and BM25 ranking.
        
        Args:
            query: The search query string
            k: Number of results to return (default: 5)
            
        Returns:
            List of dictionaries containing search results with combined scores
        """
        if not self.vectorstore:
            logger.warning("Vectorstore not initialized. Please initialize first.")
            return []
            
        try:
            # Get vector similarity results
            vector_results = self.vectorstore.similarity_search_with_score(query, k=k)
            
            # Initialize BM25 ranker
            bm25 = BM25Ranker()
            
            # Prepare documents for BM25
            documents = [doc.page_content for doc, _ in vector_results]
            bm25.fit(documents)
            
            # Get BM25 scores
            bm25_scores = bm25.rank(query, k=k)
            
            # Combine scores
            combined_results = []
            for (doc, vector_score), (idx, bm25_score) in zip(vector_results, bm25_scores):
                # Normalize scores to [0, 1] range
                norm_vector_score = 1 / (1 + vector_score)  # Convert distance to similarity
                norm_bm25_score = bm25_score / max(score for _, score in bm25_scores)
                
                # Combine scores (weighted average)
                combined_score = 0.7 * norm_vector_score + 0.3 * norm_bm25_score
                
                combined_results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "vector_score": float(vector_score),
                    "bm25_score": float(bm25_score),
                    "combined_score": float(combined_score),
                    "id": doc.metadata.get("id", None)
                })
            
            # Sort by combined score
            combined_results.sort(key=lambda x: x["combined_score"], reverse=True)
            
            logger.info(f"Found {len(combined_results)} results for query: {query}")
            return combined_results
            
        except Exception as e:
            logger.error(f"Error during semantic search with BM25: {str(e)}")
            return []



class DocumentChromaStore:
    """Handle Chroma vectorstore operations."""

    def __init__(self, persistent_client: chromadb.PersistentClient, collection_name: str, vectorstore_path: str = None, embeddings_model: OpenAIEmbeddings = embeddings_model, tf_idf:bool = False):
        """Initialize the Chroma store.
        
        Args:
            collection_name: Name of the collection to store documents
            vectorstore_path: Optional path to store the database. Defaults to CHROMA_STORE_PATH
            embeddings_model: Optional embeddings model. Defaults to global embeddings_model
        """
        self.collection_name = collection_name
        self.vectorstore_path = vectorstore_path or CHROMA_STORE_PATH
        self.embeddings_model = embeddings_model or embeddings_model
        self.persistent_client = persistent_client
        self.tf_idf = tf_idf
        self.vectorizer = TfidfVectorizer()
        self.vectorstore = None
        self.tfidf_vectorstore = None
        self.collection = None
        self.tfidf_collection_name = f"{self.collection_name}_tfidf"
        # Ensure the storage directory exists
        self.initialize()
        

    def initialize(self):
        """Initialize or load the Chroma vectorstore."""
        
        try:
            if self.collection:
                logger.debug(f"Chroma store with collection {self.collection_name} already initialized, skipping")
                return
            logger.info(f"Initializing Chroma store with collection {self.collection_name}")
            
            # First, try to clean up any corrupted collections
            self._cleanup_corrupted_collections()
            
            # Assume collections already exist - just get them directly
            logger.info(f"Assuming collection '{self.collection_name}' already exists - getting collection directly")
            
            try:
                # Get the existing collection directly
                self.collection = self.persistent_client.get_collection(name=self.collection_name)
                logger.info(f"Successfully retrieved existing collection '{self.collection_name}'")
                
                # Check if there's an embedding dimension mismatch by testing the collection
                try:
                    # Test if we can add a document to check for dimension mismatch
                    test_embedding = self.embeddings_model.embed_query("test")
                    test_ids = ["test_dimension_check"]
                    test_doc = {
                        "embeddings": [test_embedding],
                        "documents": ["test"],
                        "metadatas": [{"test": True}]
                    }
                    # This will fail if there's a dimension mismatch
                    self.collection.add(ids=test_ids, **test_doc)
                    # If successful, remove the test document
                    self.collection.delete(ids=test_ids)
                    logger.info("Collection embedding dimension is compatible")
                except Exception as dim_error:
                    if "dimension" in str(dim_error).lower():
                        logger.warning(f"Embedding dimension mismatch detected: {dim_error}")
                        logger.info(f"Deleting and recreating collection '{self.collection_name}' with correct embedding dimensions")
                        
                        try:
                            # Delete the existing collection with wrong dimensions
                            self.persistent_client.delete_collection(name=self.collection_name)
                            logger.info(f"Deleted collection '{self.collection_name}' due to dimension mismatch")
                            
                            # Create ChromaDB embedding function wrapper
                            chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                            
                            # Recreate the collection with correct embedding model
                            self.collection = self.persistent_client.create_collection(
                                name=self.collection_name,
                                metadata={"description": f"Collection for {self.collection_name}"},
                                embedding_function=chroma_embedding_function
                            )
                            logger.info(f"Recreated collection '{self.collection_name}' with correct embedding dimensions")
                        except Exception as recreate_error:
                            logger.error(f"Failed to recreate collection '{self.collection_name}': {recreate_error}")
                            # Fallback to alternative collection name
                        logger.info(f"Using alternative collection name for '{self.collection_name}' with correct embedding model")
                        
                        # Store original collection name
                        original_collection_name = self.collection_name
                        # Use a different collection name to avoid conflicts
                        alternative_collection_name = f"{self.collection_name}_v2"
                        self.collection_name = alternative_collection_name
                        
                        try:
                            # Try to get the alternative collection
                            self.collection = self.persistent_client.get_collection(name=self.collection_name)
                            logger.info(f"Successfully retrieved alternative collection '{self.collection_name}'")
                        except Exception as get_error:
                            logger.info(f"Alternative collection '{self.collection_name}' does not exist, creating it...")
                            try:
                                # Create ChromaDB embedding function wrapper
                                chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                                
                                # Create the alternative collection with correct embedding model
                                self.collection = self.persistent_client.create_collection(
                                    name=self.collection_name,
                                    embedding_function=chroma_embedding_function
                                )
                                logger.info(f"Successfully created alternative collection '{self.collection_name}' with correct embedding model")
                            except Exception as create_error:
                                logger.error(f"Error creating alternative collection '{self.collection_name}': {create_error}")
                                # Fallback to original collection name
                                self.collection_name = original_collection_name
                                try:
                                    self.collection = self.persistent_client.get_collection(name=self.collection_name)
                                    logger.info(f"Using original collection '{self.collection_name}' as fallback")
                                except Exception as fallback_error:
                                    logger.error(f"Failed to get original collection '{self.collection_name}': {fallback_error}")
                                    raise create_error
                    else:
                        raise dim_error
                        
            except Exception as e:
                logger.warning(f"Collection '{self.collection_name}' does not exist or error getting it: {e}, attempting to create it...")
                try:
                    # Create ChromaDB embedding function wrapper
                    chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                    
                    # Try to create the collection as a fallback
                    self.collection = self.persistent_client.create_collection(
                        name=self.collection_name,
                        embedding_function=chroma_embedding_function
                    )
                    logger.info(f"Successfully created collection '{self.collection_name}'")
                except Exception as create_error:
                    # Check if collection already exists (UniqueConstraintError)
                    if isinstance(create_error, UniqueConstraintError) or "already exists" in str(create_error) or "UniqueConstraintError" in str(type(create_error).__name__):
                        logger.info(f"Collection '{self.collection_name}' already exists, retrieving it...")
                        try:
                            self.collection = self.persistent_client.get_collection(name=self.collection_name)
                            logger.info(f"Successfully retrieved existing collection '{self.collection_name}'")
                        except Exception as get_error:
                            logger.error(f"Failed to get existing collection '{self.collection_name}': {get_error}")
                            raise get_error
                    else:
                        logger.error(f"Failed to create collection '{self.collection_name}': {create_error}")
                        logger.error("Please create the collection manually before using this service.")
                        raise
            
            # Get TF-IDF collection if enabled
            if self.tf_idf:
                try:
                    self.tfidf_collection = self.persistent_client.get_collection(name=self.tfidf_collection_name)
                    logger.info(f"Successfully retrieved existing TF-IDF collection '{self.tfidf_collection_name}'")
                    
                    # Check if there's an embedding dimension mismatch for TF-IDF collection too
                    try:
                        # Test if we can add a document to check for dimension mismatch
                        test_embedding = self.embeddings_model.embed_query("test")
                        test_ids = ["test_tfidf_dimension_check"]
                        test_doc = {
                            "embeddings": [test_embedding],
                            "documents": ["test"],
                            "metadatas": [{"test": True}]
                        }
                        # This will fail if there's a dimension mismatch
                        self.tfidf_collection.add(ids=test_ids, **test_doc)
                        # If successful, remove the test document
                        self.tfidf_collection.delete(ids=test_ids)
                        logger.info("TF-IDF collection embedding dimension is compatible")
                    except Exception as dim_error:
                        if "dimension" in str(dim_error).lower():
                            logger.warning(f"TF-IDF collection embedding dimension mismatch detected: {dim_error}")
                            logger.info(f"Using alternative TF-IDF collection name for '{self.tfidf_collection_name}' with correct embedding model")
                            
                            # Store original TF-IDF collection name
                            original_tfidf_collection_name = self.tfidf_collection_name
                            # Use a different collection name to avoid conflicts
                            alternative_tfidf_collection_name = f"{self.tfidf_collection_name}_v2"
                            self.tfidf_collection_name = alternative_tfidf_collection_name
                            
                            try:
                                # Try to get the alternative TF-IDF collection
                                self.tfidf_collection = self.persistent_client.get_collection(name=self.tfidf_collection_name)
                                logger.info(f"Successfully retrieved alternative TF-IDF collection '{self.tfidf_collection_name}'")
                            except Exception as get_error:
                                logger.info(f"Alternative TF-IDF collection '{self.tfidf_collection_name}' does not exist, creating it...")
                            try:
                                # Create ChromaDB embedding function wrapper
                                chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                                
                                # Create the alternative TF-IDF collection with correct embedding model
                                self.tfidf_collection = self.persistent_client.create_collection(
                                    name=self.tfidf_collection_name,
                                    embedding_function=chroma_embedding_function
                                )
                                logger.info(f"Successfully created alternative TF-IDF collection '{self.tfidf_collection_name}' with correct embedding model")
                            except Exception as create_error:
                                logger.error(f"Error creating alternative TF-IDF collection '{self.tfidf_collection_name}': {create_error}")
                                # Fallback to original collection name
                                self.tfidf_collection_name = original_tfidf_collection_name
                                try:
                                    self.tfidf_collection = self.persistent_client.get_collection(name=self.tfidf_collection_name)
                                    logger.info(f"Using original TF-IDF collection '{self.tfidf_collection_name}' as fallback")
                                except Exception as fallback_error:
                                    logger.error(f"Failed to get original TF-IDF collection '{self.tfidf_collection_name}': {fallback_error}")
                                    # Disable TF-IDF functionality as fallback
                                    self.tf_idf = False
                                    logger.warning("Disabling TF-IDF functionality due to collection issues")
                        else:
                            raise dim_error
                            
                except Exception as e:
                    logger.warning(f"TF-IDF collection '{self.tfidf_collection_name}' does not exist, creating it...")
                    try:
                        # Create ChromaDB embedding function wrapper
                        chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                        
                        # Try to create the TF-IDF collection as a fallback
                        self.tfidf_collection = self.persistent_client.create_collection(
                            name=self.tfidf_collection_name,
                            embedding_function=chroma_embedding_function
                        )
                        logger.info(f"Successfully created TF-IDF collection '{self.tfidf_collection_name}'")
                    except Exception as create_error:
                        # Check if collection already exists
                        if isinstance(create_error, UniqueConstraintError) or "already exists" in str(create_error) or "UniqueConstraintError" in str(type(create_error).__name__):
                            logger.info(f"TF-IDF collection '{self.tfidf_collection_name}' already exists, retrieving it...")
                            try:
                                self.tfidf_collection = self.persistent_client.get_collection(name=self.tfidf_collection_name)
                                logger.info(f"Successfully retrieved existing TF-IDF collection '{self.tfidf_collection_name}'")
                            except Exception as get_error:
                                logger.error(f"Failed to get existing TF-IDF collection '{self.tfidf_collection_name}': {get_error}")
                                logger.error("TF-IDF collection retrieval failed. Continuing without TF-IDF functionality.")
                                # Don't raise here - continue without TF-IDF
                        else:
                            logger.error(f"Failed to create TF-IDF collection '{self.tfidf_collection_name}': {create_error}")
                            logger.error("TF-IDF collection creation failed. Continuing without TF-IDF functionality.")
                            # Don't raise here - continue without TF-IDF
                        self.tf_idf = False
                        logger.warning("Continuing without TF-IDF functionality")
            
            # Initialize the Langchain Chroma wrapper
            self.vectorstore = Chroma(
                client=self.persistent_client,
                collection_name=self.collection_name,
                embedding_function=self.embeddings_model,
            )
            if self.tf_idf and self.tfidf_collection:
                self.tfidf_vectorstore = Chroma(
                    client=self.persistent_client,
                    collection_name=self.tfidf_collection_name,
                    embedding_function=self.embeddings_model,
                )
            
            logger.info(f"Successfully initialized Chroma store with collection {self.collection_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Chroma store: {str(e)}")
            raise

    def _cleanup_corrupted_collections(self):
        """Clean up corrupted collections that might have invalid configurations."""
        try:
            logger.info("Checking for corrupted collections...")
            
            # List all collections to check for corruption
            try:
                # In ChromaDB v0.6.0+, list_collections() only returns collection names
                collection_names = self.persistent_client.list_collections()
                logger.info(f"Found {len(collection_names)} existing collections: {collection_names}")
            except Exception as e:
                logger.warning(f"Could not list collections, may indicate corruption: {str(e)}")
                # If we can't list collections, try to clean up the database
                self._reset_chromadb_database()
                return
            
            # Check each collection for corruption
            corrupted_collections = []
            for collection_name in collection_names:
                try:
                    # Try to get the collection to see if it's accessible
                    test_collection = self.persistent_client.get_collection(name=collection_name)
                    logger.debug(f"Collection '{collection_name}' is accessible")
                except Exception as e:
                    if "_type" in str(e) or "JSON" in str(e) or "configuration" in str(e):
                        logger.warning(f"Collection '{collection_name}' appears to be corrupted: {str(e)}")
                        corrupted_collections.append(collection_name)
                    else:
                        logger.debug(f"Collection '{collection_name}' has other issues: {str(e)}")
            
            # Delete corrupted collections
            for collection_name in corrupted_collections:
                try:
                    logger.info(f"Attempting to delete corrupted collection: {collection_name}")
                    self.persistent_client.delete_collection(name=collection_name)
                    logger.info(f"Successfully deleted corrupted collection: {collection_name}")
                except Exception as e:
                    logger.error(f"Failed to delete corrupted collection '{collection_name}': {str(e)}")
                    # If we can't delete individual collections, try to reset the entire database
                    if "Collection" in str(e) or "not found" in str(e):
                        logger.warning("Attempting to reset ChromaDB database due to corruption")
                        self._reset_chromadb_database()
                        return
                        
        except Exception as e:
            logger.error(f"Error during collection cleanup: {str(e)}")
            # If cleanup fails, try to reset the database
            logger.warning("Collection cleanup failed, attempting to reset ChromaDB database")
            self._reset_chromadb_database()

    def _reset_chromadb_database(self):
        """Reset the ChromaDB database by removing corrupted data."""
        try:
            logger.warning("Resetting ChromaDB database due to corruption...")
            
            # Get the database path from the vectorstore_path or use default
            db_path = self.vectorstore_path or CHROMA_STORE_PATH
            
            if db_path and os.path.exists(db_path):
                logger.info(f"Removing corrupted database at: {db_path}")
                
                # Remove the entire database directory
                import shutil
                shutil.rmtree(db_path)
                logger.info("Successfully removed corrupted database")
                
                # Recreate the persistent client
                self.persistent_client = chromadb.PersistentClient(path=db_path)
                logger.info("Recreated ChromaDB persistent client")
            else:
                logger.warning(f"Database path {db_path} does not exist, skipping reset")
                
        except Exception as e:
            logger.error(f"Failed to reset ChromaDB database: {str(e)}")
            # Create a new client as a last resort
            try:
                self.persistent_client = chromadb.PersistentClient(path=self.vectorstore_path)
                logger.info("Created new ChromaDB persistent client as fallback")
            except Exception as fallback_error:
                logger.error(f"Failed to create fallback ChromaDB client: {str(fallback_error)}")
                raise

    def compute_document_embeddings(self, documents: List[LangchainDocument]) -> List[List[float]]:
        """Compute embeddings for a list of documents.
        
        Args:
            documents: List of LangchainDocument objects
            
        Returns:
            List of embedding vectors for each document
        """
        try:
            # Extract text content from documents
            texts = [doc.page_content for doc in documents]
            
            # Compute embeddings using the embeddings model
            embeddings = self.embeddings_model.embed_documents(texts)
            
            return embeddings
        except Exception as e:
            logger.error(f"Error computing document embeddings: {str(e)}")
            return []

    def add_documents(self, docs: List[Any]):
        """Add documents to the vectorstore.
        
        Args:
            docs: List of dictionaries containing 'metadata' and 'data' keys
            
        Returns:
            List of document IDs that were added
        """
        if not docs:
            logger.warning("No documents provided to add to the vectorstore.")
            return []
            
        documents, ids = [], []
        for doc in docs:
            if isinstance(doc, LangchainDocument):
                documents.append(doc)
                document_id = str(uuid4())
                if doc.metadata.get("id", None) is None:
                    doc.metadata["id"] = document_id
                ids.append(doc.metadata.get("id", document_id))
                continue
            else:
                if not isinstance(doc, dict):
                    logger.warning(f"Skipping invalid document format: {doc}")
                    continue
                    
                if 'metadata' not in doc or 'data' not in doc:
                    logger.warning(f"Skipping document missing required fields: {doc}")
                    continue    
              
                try:
                    document_id, document = create_langchain_doc_util(metadata=doc['metadata'], data=doc['data'])    
                    if document and document_id:
                        documents.append(document)
                        ids.append(document_id)
                    else:
                        logger.warning(f"Failed to create document from doc: {doc}")
                except Exception as e:
                    logger.error(f"Error creating document from doc {doc}: {str(e)}")
                    continue
        
        if documents:
            # Filter complex metadata from documents before adding to ChromaDB
            try:
                filtered_documents = filter_complex_metadata(documents)
                logger.info(f"Filtered complex metadata from {len(documents)} documents")
            except Exception as e:
                logger.warning(f"Error filtering complex metadata: {e}. Using original documents.")
                filtered_documents = documents
            
            # Compute embeddings for all documents
            embeddings = self.compute_document_embeddings(filtered_documents)
            
            if embeddings:
                # Add documents with pre-computed embeddings
                try:
                    self.vectorstore.add_documents(
                        documents=filtered_documents,
                        ids=ids,
                        embeddings=embeddings
                    )
                except Exception as e:
                    # Check if error is due to embedding dimension mismatch
                    if "dimension" in str(e).lower() or "dimensionality" in str(e).lower():
                        logger.warning(f"Embedding dimension mismatch detected: {e}")
                        logger.info(f"Recreating collection '{self.collection_name}' with correct embedding dimensions")
                        
                        try:
                            # Delete and recreate the collection
                            self.persistent_client.delete_collection(name=self.collection_name)
                            logger.info(f"Deleted collection '{self.collection_name}' due to dimension mismatch")
                            
                            # Create ChromaDB embedding function wrapper
                            chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                            
                            # Recreate the collection
                            self.collection = self.persistent_client.create_collection(
                                name=self.collection_name,
                                metadata={"description": f"Collection for {self.collection_name}"},
                                embedding_function=chroma_embedding_function
                            )
                            
                            # Reinitialize the vectorstore with the new collection
                            self.vectorstore = Chroma(
                                client=self.persistent_client,
                                collection_name=self.collection_name,
                                embedding_function=self.embeddings_model,
                            )
                            logger.info(f"Recreated collection '{self.collection_name}' with correct embedding dimensions")
                            
                            # Retry adding documents
                            self.vectorstore.add_documents(
                                documents=filtered_documents,
                                ids=ids,
                                embeddings=embeddings
                            )
                        except Exception as recreate_error:
                            logger.error(f"Failed to recreate collection: {recreate_error}")
                            raise
                    else:
                        # Re-raise if it's not a dimension error
                        raise
                
                # Add TF-IDF vectors if enabled
                if self.tf_idf:
                    self.add_tfidf_vectors(documents=filtered_documents, ids=ids)
                
                logger.info(f"Added {len(filtered_documents)} documents with embeddings to the vectorstore.")
                print("documents added to the vectorstore", len(filtered_documents))
                return ids
            else:
                # Fallback to regular document addition if embedding computation fails
                try:
                    self.vectorstore.add_documents(documents=filtered_documents, ids=ids)
                except Exception as e:
                    # Check if error is due to embedding dimension mismatch
                    if "dimension" in str(e).lower() or "dimensionality" in str(e).lower():
                        logger.warning(f"Embedding dimension mismatch detected: {e}")
                        logger.info(f"Recreating collection '{self.collection_name}' with correct embedding dimensions")
                        
                        try:
                            # Delete and recreate the collection
                            self.persistent_client.delete_collection(name=self.collection_name)
                            logger.info(f"Deleted collection '{self.collection_name}' due to dimension mismatch")
                            
                            # Create ChromaDB embedding function wrapper
                            chroma_embedding_function = ChromaDBEmbeddingFunction(self.embeddings_model)
                            
                            # Recreate the collection
                            self.collection = self.persistent_client.create_collection(
                                name=self.collection_name,
                                metadata={"description": f"Collection for {self.collection_name}"},
                                embedding_function=chroma_embedding_function
                            )
                            
                            # Reinitialize the vectorstore with the new collection
                            self.vectorstore = Chroma(
                                client=self.persistent_client,
                                collection_name=self.collection_name,
                                embedding_function=self.embeddings_model,
                            )
                            logger.info(f"Recreated collection '{self.collection_name}' with correct embedding dimensions")
                            
                            # Retry adding documents
                            self.vectorstore.add_documents(documents=filtered_documents, ids=ids)
                        except Exception as recreate_error:
                            logger.error(f"Failed to recreate collection: {recreate_error}")
                            raise
                    else:
                        # Re-raise if it's not a dimension error
                        raise
                
                if self.tf_idf:
                    self.add_tfidf_vectors(documents=filtered_documents, ids=ids)
                logger.info(f"Added {len(filtered_documents)} documents to the vectorstore (without pre-computed embeddings).")
                return ids
        else:
            logger.warning("No valid documents were found to add to the vectorstore.")
            return []

    def add_tfidf_vectors(self, documents: List[LangchainDocument], ids: List[str]):
        if not self.tf_idf:
            return
        if documents:
            # TF-IDF indexing
            # Note: TfidfVectorizer().fit_transform(...) recomputes the TF-IDF each time. If your corpus grows dynamically, consider persisting the vectorizer using joblib or pickle.
            
            # Extract page contents
            texts = [doc.page_content for doc in documents]
            # Generate TF-IDF vectors
            tfidf_matrix = self.vectorizer.fit_transform(texts)
            metadata_list = [doc.metadata for doc in documents]
            tfidf_ids = [str(uuid.uuid4()) for _ in range(len(texts))]
            
            # Filter complex metadata for TF-IDF collection as well
            try:
                filtered_metadata_list = []
                for metadata in metadata_list:
                    # Create a temporary document to filter metadata
                    temp_doc = LangchainDocument(page_content="", metadata=metadata)
                    filtered_docs = filter_complex_metadata([temp_doc])
                    if filtered_docs:
                        filtered_metadata_list.append(filtered_docs[0].metadata)
                    else:
                        filtered_metadata_list.append(metadata)
            except Exception as e:
                logger.warning(f"Error filtering complex metadata for TF-IDF: {e}. Using original metadata.")
                filtered_metadata_list = metadata_list
            
            self.tfidf_collection.add(
                embeddings=tfidf_matrix.toarray(),
                ids=tfidf_ids,
                metadatas=filtered_metadata_list
            )
            logger.info(f"Added {len(texts)} TF-IDF vectors to collection {self.tfidf_collection_name}")
        else:
            logger.warning("No documents provided to add to the vectorstore.")
        return

    def semantic_search(self, query: str, k: int = 5, where: Dict = None, query_embedding: List[float] = None) -> List[Dict]:
        """Perform semantic search on the Chroma store using embeddings.
        
        Args:
            query: The search query string (will be embedded if query_embedding not provided)
            k: Number of results to return (default: 5)
            where: Optional metadata filter dictionary
            query_embedding: Optional pre-computed query embedding vector
            
        Returns:
            List of dictionaries containing search results with scores
        """
        if not self.collection:
            logger.warning("Chroma collection not initialized. Please initialize first.")
            return []
            
        try:
            logger.info(f"Semantic search in collection '{self.collection_name}' with query: '{query[:100]}...' (k={k})")
            
            # Check collection count before querying
            try:
                count = self.collection.count()
                logger.info(f"Collection '{self.collection_name}' has {count} documents")
                if count == 0:
                    logger.warning(f"Collection '{self.collection_name}' is empty - no results will be returned")
                elif k > count:
                    logger.warning(f"Requested {k} results but collection '{self.collection_name}' only has {count} documents")
            except Exception as e:
                logger.debug(f"Could not get count for collection '{self.collection_name}': {e}")
            
            # Generate query embedding if not provided
            if query_embedding is None:
                logger.debug("Generating embedding for query")
                query_embedding = self.embeddings_model.embed_query(query)
            
            # Prepare query parameters for semantic search with embeddings
            query_kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": k
            }
            
            # Handle the where parameter safely - only pass filter if where is not None and contains valid values
            if where is not None and isinstance(where, dict) and where:
                # Log the original where parameter for debugging
                logger.debug(f"Original where parameter: {where}")
                
                # Filter out None values from the where clause
                filtered_where = {}
                for key, value in where.items():
                    if value is not None:
                        filtered_where[key] = value
                    else:
                        logger.warning(f"Filtering out None value for key '{key}' in where clause")
                
                # Only add filter if we have valid filters
                if filtered_where:
                    query_kwargs["where"] = filtered_where
                    logger.debug(f"Using filtered where clause: {filtered_where}")
                else:
                    logger.info("No valid filters found in where clause, proceeding without filter")
            else:
                logger.debug(f"Where parameter is {where}, proceeding without filter")
            
            # Perform semantic search query on ChromaDB collection using embeddings
            try:
                logger.debug(f"Performing semantic search query on collection {self.collection_name}")
                results = self.collection.query(**query_kwargs)
                
                logger.info(f"results in semantic_search for {self.collection_name}: {len(results['ids'][0]) if results['ids'] else 0} results")
            except Exception as search_error:
                logger.error(f"Error in semantic search query: {str(search_error)}")
                # Fallback to basic query without filters
                try:
                    logger.warning("Falling back to basic query without filters")
                    basic_kwargs = {
                        "query_embeddings": [query_embedding],
                        "n_results": k
                    }
                    results = self.collection.query(**basic_kwargs)
                except Exception as fallback_error:
                    logger.error(f"Fallback query also failed: {str(fallback_error)}")
                    return []
            
            # Format results - ChromaDB query() returns nested lists
            formatted_results = []
            if results and results.get('ids') and len(results['ids']) > 0:
                ids_list = results['ids'][0]  # First query result
                documents_list = results.get('documents', [[]])[0]
                metadatas_list = results.get('metadatas', [[]])[0]
                distances_list = results.get('distances', [[]])[0]
                
                for i in range(len(ids_list)):
                    try:
                        # Get document content and metadata
                        content = documents_list[i] if i < len(documents_list) else ""
                        metadata = metadatas_list[i] if i < len(metadatas_list) else {}
                        doc_id = ids_list[i]
                        
                        # Convert distance to similarity score (lower distance = higher similarity)
                        # ChromaDB uses L2 distance, so we convert to similarity
                        distance = distances_list[i] if i < len(distances_list) else 1.0
                        similarity_score = 1.0 / (1.0 + distance)  # Convert distance to similarity
                        
                        formatted_results.append({
                            "content": content,
                            "metadata": metadata,
                            "score": float(similarity_score),
                            "distance": float(distance),
                            "id": doc_id
                        })
                    except Exception as format_error:
                        logger.warning(f"Error formatting result {i}: {str(format_error)}")
                        continue
            
            # Sort results by score (higher is better for similarity)
            formatted_results.sort(key=lambda x: x["score"], reverse=True)
            
            logger.info(f"Found {len(formatted_results)} {self.collection_name} results for query: {query}")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error during semantic search query: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []

    def semantic_search_with_bm25(self, query: str, k: int = 5, where: Dict = None, query_embedding: List[float] = None) -> List[Dict]:
        """Perform semantic search with BM25 ranking.
        
        Args:
            query: The search query string
            k: Number of results to return (default: 5)
            where: Optional metadata filter dictionary
            query_embedding: Optional pre-computed query embedding vector
            
        Returns:
            List of dictionaries containing search results with BM25 scores
        """
        if not self.collection:
            logger.warning("Chroma collection not initialized. Please initialize first.")
            return []
            
        try:
            # Generate query embedding if not provided
            if query_embedding is None:
                logger.debug("Generating embedding for query in BM25 search")
                query_embedding = self.embeddings_model.embed_query(query)
            
            # First get documents using semantic search
            query_kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": k * 2  # Get more documents for BM25 ranking
            }
            
            # Only add filter if where is not None and contains valid values
            if where is not None and isinstance(where, dict) and where:
                # Log the original where parameter for debugging
                logger.debug(f"Original where parameter in BM25 search: {where}")
                
                # Filter out None values from the where clause
                filtered_where = {}
                for key, value in where.items():
                    if value is not None:
                        filtered_where[key] = value
                    else:
                        logger.warning(f"Filtering out None value for key '{key}' in BM25 where clause")
                
                # Only add filter if we have valid filters
                if filtered_where:
                    query_kwargs["where"] = filtered_where
                    logger.debug(f"Using filtered where clause in BM25 search: {filtered_where}")
                else:
                    logger.info("No valid filters found in BM25 where clause, proceeding without filter")
            else:
                logger.debug(f"Where parameter in BM25 search is {where}, proceeding without filter")
                
            # Perform semantic search query on ChromaDB collection
            results = self.collection.query(**query_kwargs)
            
            if not results or not results.get('ids') or len(results['ids']) == 0:
                logger.info(f"No documents found for BM25 search")
                return []
            
            # Prepare documents for BM25 - ChromaDB query() returns nested lists
            documents = []
            metadatas = []
            ids = []
            
            ids_list = results['ids'][0]
            documents_list = results.get('documents', [[]])[0]
            metadatas_list = results.get('metadatas', [[]])[0]
            
            for i in range(len(ids_list)):
                content = documents_list[i] if i < len(documents_list) else ""
                metadata = metadatas_list[i] if i < len(metadatas_list) else {}
                doc_id = ids_list[i]
                
                if content:  # Only include documents with content
                    documents.append(content)
                    metadatas.append(metadata)
                    ids.append(doc_id)
            
            if not documents:
                logger.info(f"No documents with content found for BM25 search")
                return []
            
            # Initialize BM25 ranker
            bm25 = BM25Ranker()
            bm25.fit(documents)
            
            # Get BM25 scores
            bm25_scores = bm25.rank(query, k=min(k, len(documents)))
            
            # Format results with BM25 scores
            combined_results = []
            for idx, bm25_score in bm25_scores:
                if idx < len(documents):
                    combined_results.append({
                        "content": documents[idx],
                        "metadata": metadatas[idx],
                        "bm25_score": float(bm25_score),
                        "id": ids[idx]
                    })
            
            # Sort by BM25 score (higher is better)
            combined_results.sort(key=lambda x: x["bm25_score"], reverse=True)
            
            logger.info(f"Found {len(combined_results)} BM25 results for query: {query}")
            return combined_results
            
        except Exception as e:
            logger.error(f"Error during BM25 search: {str(e)}")
            return []

    def semantic_search_with_tfidf(self, query: str, k: int = 5, where: Dict = None, query_embedding: List[float] = None) -> List[Dict]:
        """Perform semantic search with TF-IDF ranking.
        
        Args:
            query: The search query string
            k: Number of results to return (default: 5)
            where: Optional metadata filter dictionary
            query_embedding: Optional pre-computed query embedding vector
            
        Returns:
            List of dictionaries containing search results with TF-IDF scores
        """
        if not self.collection:
            logger.warning("Chroma collection not initialized. Please initialize first.")
            return []
            
        try:
            # Generate query embedding if not provided
            if query_embedding is None:
                logger.debug("Generating embedding for query in TF-IDF search")
                query_embedding = self.embeddings_model.embed_query(query)
            
            # First get documents using semantic search
            query_kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": k * 2  # Get more documents for TF-IDF ranking
            }
            
            # Only add filter if where is not None and contains valid values
            if where is not None and isinstance(where, dict) and where:
                # Log the original where parameter for debugging
                logger.debug(f"Original where parameter in TF-IDF search: {where}")
                
                # Filter out None values from the where clause
                filtered_where = {}
                for key, value in where.items():
                    if value is not None:
                        filtered_where[key] = value
                    else:
                        logger.warning(f"Filtering out None value for key '{key}' in TF-IDF where clause")
                
                # Only add filter if we have valid filters
                if filtered_where:
                    query_kwargs["where"] = filtered_where
                    logger.debug(f"Using filtered where clause in TF-IDF search: {filtered_where}")
                else:
                    logger.info("No valid filters found in TF-IDF where clause, proceeding without filter")
            else:
                logger.debug(f"Where parameter in TF-IDF search is {where}, proceeding without filter")
                
            # Perform semantic search query on ChromaDB collection
            results = self.collection.query(**query_kwargs)
            
            if not results or not results.get('ids') or len(results['ids']) == 0:
                logger.info(f"No documents found for TF-IDF search")
                return []
            
            # Prepare documents for TF-IDF - ChromaDB query() returns nested lists
            documents = []
            metadatas = []
            ids = []
            
            ids_list = results['ids'][0]
            documents_list = results.get('documents', [[]])[0]
            metadatas_list = results.get('metadatas', [[]])[0]
            
            for i in range(len(ids_list)):
                content = documents_list[i] if i < len(documents_list) else ""
                metadata = metadatas_list[i] if i < len(metadatas_list) else {}
                doc_id = ids_list[i]
                
                if content:  # Only include documents with content
                    documents.append(content)
                    metadatas.append(metadata)
                    ids.append(doc_id)
            
            if not documents:
                logger.info(f"No documents with content found for TF-IDF search")
                return []

            try:
                # TF-IDF vector for query
                tfidf_vectorizer = TfidfVectorizer()
                tfidf_matrix = tfidf_vectorizer.fit_transform(documents + [query])
                query_vector = tfidf_matrix[-1].toarray()[0]

                # TF-IDF similarity scores (cosine)
                tfidf_doc_vectors = tfidf_matrix[:-1].toarray()
                cosine_scores = np.dot(tfidf_doc_vectors, query_vector) / (
                    np.linalg.norm(tfidf_doc_vectors, axis=1) * np.linalg.norm(query_vector) + 1e-10)

                # Format results with TF-IDF scores
                results_list = []
                for i in range(len(documents)):
                    results_list.append({
                        "content": documents[i],
                        "metadata": metadatas[i],
                        "tfidf_score": float(cosine_scores[i]),
                        "id": ids[i]
                    })

                # Sort by TF-IDF score descending
                results_list.sort(key=lambda x: x["tfidf_score"], reverse=True)
                
                # Return top k results
                top_results = results_list[:k]
                logger.info(f"Found {len(top_results)} TF-IDF results for query: {query}")
                return top_results
                
            except Exception as e:
                # TF-IDF calculation failed, fall back to direct query results
                logger.warning(f"TF-IDF calculation failed, falling back to direct query results: {str(e)}")
                # Format direct query results only
                results_list = []
                for i in range(len(documents)):
                    results_list.append({
                        "content": documents[i],
                        "metadata": metadatas[i],
                        "tfidf_score": 0.0,
                        "id": ids[i]
                    })
                logger.info(f"Returning {len(results_list)} direct query results for query: {query}")
                return results_list
                
        except Exception as e:
            logger.error(f"Error during TF-IDF search: {str(e)}")
            return []
    
    def tfidf_search(self, query: str, k: int = 5, where: Dict = None) -> List[Dict]:
        """Perform search using semantic search with TF-IDF ranking.
        
        Args:
            query: The search query string
            k: Number of results to return (default: 5)
            where: Optional metadata filter dictionary
            
        Returns:
            List of dictionaries containing search results with scores
        """
        if not self.collection:
            logger.warning("Chroma collection not initialized.")
            return []
            
        try:
            # Generate query embedding
            logger.debug("Generating embedding for query in TF-IDF only search")
            query_embedding = self.embeddings_model.embed_query(query)
            
            # First get documents using semantic search
            query_kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": k * 2  # Get more documents for TF-IDF ranking
            }
            
            # Only add where clause if it's not None and contains valid values
            if where is not None and isinstance(where, dict) and where:
                # Log the original where parameter for debugging
                logger.debug(f"Original where parameter in TF-IDF only search: {where}")
                
                # Filter out None values from the where clause
                filtered_where = {}
                for key, value in where.items():
                    if value is not None:
                        filtered_where[key] = value
                    else:
                        logger.warning(f"Filtering out None value for key '{key}' in TF-IDF only where clause")
                
                # Only add where if we have valid filters
                if filtered_where:
                    query_kwargs["where"] = filtered_where
                    logger.debug(f"Using filtered where clause in TF-IDF only search: {filtered_where}")
                else:
                    logger.info("No valid filters found in TF-IDF only where clause, proceeding without filter")
            else:
                logger.debug(f"Where parameter in TF-IDF only search is {where}, proceeding without filter")
                
            # Query the main collection using semantic search
            results = self.collection.query(**query_kwargs)
            
            if not results or not results.get('ids') or len(results['ids']) == 0:
                logger.info(f"No documents found for TF-IDF search")
                return []
            
            # Prepare documents for TF-IDF - ChromaDB query() returns nested lists
            documents = []
            metadatas = []
            ids = []
            
            ids_list = results['ids'][0]
            documents_list = results.get('documents', [[]])[0]
            metadatas_list = results.get('metadatas', [[]])[0]
            
            for i in range(len(ids_list)):
                content = documents_list[i] if i < len(documents_list) else ""
                metadata = metadatas_list[i] if i < len(metadatas_list) else {}
                doc_id = ids_list[i]
                
                if content:  # Only include documents with content
                    documents.append(content)
                    metadatas.append(metadata)
                    ids.append(doc_id)
            
            if not documents:
                logger.info(f"No documents with content found for TF-IDF search")
                return []
            
            # Convert query to TF-IDF vector
            tfidf_vectorizer = TfidfVectorizer()
            tfidf_matrix = tfidf_vectorizer.fit_transform(documents + [query])
            query_vector = tfidf_matrix[-1].toarray()[0]
            
            # Calculate TF-IDF similarity scores
            tfidf_doc_vectors = tfidf_matrix[:-1].toarray()
            cosine_scores = np.dot(tfidf_doc_vectors, query_vector) / (
                np.linalg.norm(tfidf_doc_vectors, axis=1) * np.linalg.norm(query_vector) + 1e-10)
            
            # Format results
            formatted_results = []
            for i in range(len(documents)):
                formatted_results.append({
                    "content": documents[i],
                    "metadata": metadatas[i],
                    "score": float(cosine_scores[i]),
                    "id": ids[i]
                })
            
            # Sort results by score (higher is better for cosine similarity)
            formatted_results.sort(key=lambda x: x["score"], reverse=True)
            
            # Return top k results
            top_results = formatted_results[:k]
            logger.info(f"Found {len(top_results)} TF-IDF results for query: {query}")
            return top_results
            
        except Exception as e:
            logger.error(f"Error during TF-IDF search: {str(e)}")
            return []

def _to_qdrant_point_id(id_value: Any) -> str:
    """Convert a document/section id to a valid Qdrant point ID (UUID). Qdrant accepts only UUID or unsigned integer."""
    if id_value is None:
        return str(uuid4())
    s = str(id_value).strip()
    if not s:
        return str(uuid4())
    try:
        uuid.UUID(s)
        return s
    except (ValueError, AttributeError, TypeError):
        pass
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, "qdrant.point." + s))


class DocumentQdrantStore:
    """Handle Qdrant vectorstore operations using the unified storage architecture."""
    
    def __init__(
        self,
        qdrant_client: Optional[QdrantClient] = None,
        collection_name: str = "default",
        embeddings_model: Optional[OpenAIEmbeddings] = None,
        host: Optional[str] = None,
        port: int = 6333,
        tf_idf: bool = False,
        batch_size: int = 200,
    ):
        """Initialize the Qdrant store.
        
        Args:
            qdrant_client: Optional QdrantClient instance. If None, creates a new client
            collection_name: Name of the collection to store documents
            embeddings_model: Optional embeddings model. Defaults to global embeddings_model
            host: Qdrant server host (used if qdrant_client is None)
            port: Qdrant server port (used if qdrant_client is None)
            tf_idf: Whether to enable TF-IDF indexing (not fully supported for Qdrant yet)
            batch_size: Batch size for embed_documents and upsert (default: 200)
        """
        if not QDRANT_AVAILABLE:
            raise ImportError(
                "Qdrant dependencies not installed. Install with: pip install qdrant-client langchain-qdrant"
            )
        
        self.collection_name = collection_name
        self.embeddings_model = embeddings_model or embeddings_model
        self.tf_idf = tf_idf
        self.vectorizer = TfidfVectorizer() if tf_idf else None
        self.batch_size = batch_size
        
        # Initialize Qdrant client
        if qdrant_client:
            self.qdrant_client = qdrant_client
        else:
            host = host or "localhost"
            self.qdrant_client = QdrantClient(host=host, port=port)
        
        self.vectorstore = None
        self.initialize()
    
    def initialize(self):
        """Initialize or load the Qdrant vectorstore."""
        try:
            if self.vectorstore:
                return
            
            logger.info(f"Initializing Qdrant store with collection {self.collection_name}")
            
            # Create collection if it doesn't exist
            if not self.qdrant_client.collection_exists(self.collection_name):
                logger.info(f"Collection {self.collection_name} doesn't exist, creating it")
                # Get embedding dimension from the embeddings model
                test_embedding = self.embeddings_model.embed_query("test")
                embedding_dim = len(test_embedding)
                
                # Create collection with proper vector configuration
                self.qdrant_client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(
                        size=embedding_dim,
                        distance=Distance.COSINE
                    )
                )
                logger.info(f"Created collection {self.collection_name} with dimension {embedding_dim}")
            else:
                logger.info(f"Collection {self.collection_name} already exists")
            
            # Initialize the Langchain Qdrant wrapper
            # QdrantVectorStore uses 'embedding' (singular) parameter in newer versions
            try:
                # Try with 'embedding' parameter (most common)
                self.vectorstore = LangchainQdrant(
                    client=self.qdrant_client,
                    collection_name=self.collection_name,
                    embedding=self.embeddings_model,
                )
            except TypeError as e:
                error_str = str(e)
                # Try different parameter combinations based on the error
                if "embedding" in error_str and "embeddings" not in error_str:
                    # Try 'embeddings' (plural)
                    self.vectorstore = LangchainQdrant(
                        client=self.qdrant_client,
                        collection_name=self.collection_name,
                        embeddings=self.embeddings_model,
                    )
                else:
                    logger.error(f"Failed to initialize with known parameter names: {error_str}")
                    raise
            
            logger.info(f"Successfully initialized Qdrant store with collection {self.collection_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Qdrant store: {str(e)}")
            raise
    
    def compute_document_embeddings(self, documents: List[LangchainDocument]) -> List[List[float]]:
        """Compute embeddings for a list of documents.
        
        Args:
            documents: List of LangchainDocument objects
            
        Returns:
            List of embedding vectors for each document
        """
        try:
            texts = [doc.page_content for doc in documents]
            embeddings = self.embeddings_model.embed_documents(texts)
            return embeddings
        except Exception as e:
            logger.error(f"Error computing document embeddings: {str(e)}")
            return []
    
    def add_documents(self, docs: List[Any]) -> List[str]:
        """Add documents to the vectorstore.
        
        Args:
            docs: List of dictionaries containing 'metadata' and 'data' keys or LangchainDocument objects
            
        Returns:
            List of document IDs that were added
        """
        if not docs:
            logger.warning("No documents provided to add to the vectorstore.")
            return []
        
        documents, ids = [], []
        for doc in docs:
            if isinstance(doc, LangchainDocument):
                documents.append(doc)
                raw_id = doc.metadata.get("id", None)
                document_id = str(uuid4()) if raw_id is None else raw_id
                if doc.metadata.get("id", None) is None:
                    doc.metadata["id"] = document_id
                ids.append(_to_qdrant_point_id(doc.metadata.get("id", document_id)))
                continue
            else:
                if not isinstance(doc, dict):
                    logger.warning(f"Skipping invalid document format: {doc}")
                    continue
                
                if 'metadata' not in doc or 'data' not in doc:
                    logger.warning(f"Skipping document missing required fields: {doc}")
                    continue
                
                try:
                    document_id, document = create_langchain_doc_util(metadata=doc['metadata'], data=doc['data'])
                    if document and document_id:
                        documents.append(document)
                        ids.append(_to_qdrant_point_id(document_id))
                    else:
                        logger.warning(f"Failed to create document from doc: {doc}")
                except Exception as e:
                    logger.error(f"Error creating document from doc {doc}: {str(e)}")
                    continue
        
        if documents:
            # Filter complex metadata
            try:
                filtered_documents = filter_complex_metadata(documents)
                logger.info(f"Filtered complex metadata from {len(documents)} documents")
            except Exception as e:
                logger.warning(f"Error filtering complex metadata: {e}. Using original documents.")
                filtered_documents = documents
            
            # Batch upsert (LangChain Qdrant add_documents does not accept precomputed embeddings;
            # batching limits payload size and lets the store embed each batch in one go)
            batch_size = getattr(self, "batch_size", 200)
            added_ids = []
            for start in range(0, len(filtered_documents), batch_size):
                batch_docs = filtered_documents[start : start + batch_size]
                batch_ids = ids[start : start + batch_size]
                try:
                    self.vectorstore.add_documents(documents=batch_docs, ids=batch_ids)
                    added_ids.extend(batch_ids)
                except Exception as e:
                    logger.warning(f"Qdrant batch failed at offset {start} ({len(batch_docs)} docs): {e}")
            logger.info(f"Added {len(added_ids)} documents to the Qdrant vectorstore.")
            return added_ids
        else:
            logger.warning("No valid documents were found to add to the vectorstore.")
            return []
    
    def _apply_manual_filter(self, results: List[Tuple], where: Dict) -> List[Tuple]:
        """Apply ChromaDB-style filter to search results manually.
        
        Args:
            results: List of (document, score) tuples from search
            where: ChromaDB-style filter dictionary
            
        Returns:
            Filtered list of (document, score) tuples
        """
        if not where or not results:
            return results
        
        # Field mapping for LangChain's nested metadata structure
        FIELD_MAPPING = {
            'project_id': 'product_name',  # project_id -> metadata.product_name
            'product_name': 'product_name',
            'type': 'type',
            'mdl_type': 'mdl_type',
            'table_name': 'table_name',
            'name': 'name',
            'content_type': 'content_type',
            'category_name': 'category_name',
            'organization_id': 'organization_id',
        }
            
        def get_nested_value(doc_metadata: Dict, key: str) -> Any:
            """Get value from nested metadata structure."""
            # Check if metadata is nested under 'metadata' key
            if 'metadata' in doc_metadata and isinstance(doc_metadata['metadata'], dict):
                nested_meta = doc_metadata['metadata']
                # Map the key (e.g., project_id -> product_name)
                mapped_key = FIELD_MAPPING.get(key, key)
                return nested_meta.get(mapped_key)
            else:
                # Direct metadata access
                mapped_key = FIELD_MAPPING.get(key, key)
                return doc_metadata.get(mapped_key)
        
        def check_condition(metadata: Dict, key: str, value: Any) -> bool:
            """Check if a single condition matches."""
            actual_value = get_nested_value(metadata, key)
            
            if isinstance(value, dict):
                # Handle operators
                if '$eq' in value:
                    return actual_value == value['$eq']
                elif '$in' in value:
                    return actual_value in value['$in']
                elif '$ne' in value:
                    return actual_value != value['$ne']
                else:
                    # Unknown operator, try direct match
                    return actual_value == value
            else:
                # Simple equality
                return actual_value == value
        
        def matches_filter(metadata: Dict, filter_dict: Dict) -> bool:
            """Recursively check if metadata matches filter."""
            if '$and' in filter_dict:
                # All conditions must match
                return all(matches_filter(metadata, cond) for cond in filter_dict['$and'])
            elif '$or' in filter_dict:
                # At least one condition must match
                return any(matches_filter(metadata, cond) for cond in filter_dict['$or'])
            else:
                # Check all key-value conditions
                for key, value in filter_dict.items():
                    if key.startswith('$'):
                        continue  # Skip operators
                    if not check_condition(metadata, key, value):
                        return False
                return True
        
        # Filter results
        filtered_results = []
        for doc, score in results:
            if matches_filter(doc.metadata, where):
                filtered_results.append((doc, score))
        
        logger.info(f"Manual filtering: {len(results)} -> {len(filtered_results)} results")
        return filtered_results
    
    def _convert_chroma_filter_to_qdrant(self, where: Dict) -> Optional[Dict]:
        """Convert ChromaDB filter format to Qdrant filter format.
        
        ChromaDB format examples:
            {'project_id': 'Snyk'}  # Simple equality
            {'$and': [{'project_id': {'$eq': 'Snyk'}}, {'type': {'$in': ['TABLE_DESCRIPTION']}}]}
            {'$or': [{'status': 'active'}, {'status': 'pending'}]}
            
        Qdrant filter format (with LangChain nested metadata):
            {'must': [{'key': 'metadata.product_name', 'match': {'value': 'Snyk'}}]}
        
        Note: LangChain stores document metadata under a 'metadata' key in Qdrant payload.
        
        Args:
            where: ChromaDB-style filter dictionary
            
        Returns:
            Qdrant-style filter dictionary or None if conversion fails
        """
        if not where:
            return None
            
        try:
            from qdrant_client.models import Filter, FieldCondition, MatchValue, MatchAny
            
            # Field mapping for LangChain's nested metadata structure
            # ChromaDB uses top-level fields, Qdrant (via LangChain) nests them under 'metadata'
            FIELD_MAPPING = {
                'project_id': 'metadata.project_id',
                'product_name': 'metadata.product_name',
                'type': 'metadata.type',
                'mdl_type': 'metadata.mdl_type',
                'table_name': 'metadata.table_name',
                'name': 'metadata.name',
                'content_type': 'metadata.content_type',
                'category_name': 'metadata.category_name',
                'organization_id': 'metadata.organization_id',
                'entity_type': 'entity_type',  # XSOAR: stored at top level, not nested
                'artifact_type': 'artifact_type',  # LLM Safety: stored at top level, not nested
            }
            
            def map_field_name(key: str) -> str:
                """Map ChromaDB field name to Qdrant nested metadata field."""
                return FIELD_MAPPING.get(key, f'metadata.{key}')
            
            def convert_condition(key: str, value: Any) -> Optional[FieldCondition]:
                """Convert a single condition to Qdrant format."""
                # Map the field name to Qdrant's nested structure
                qdrant_key = map_field_name(key)
                
                if isinstance(value, dict):
                    # Handle operators like $eq, $in, $ne, etc.
                    if '$eq' in value:
                        return FieldCondition(key=qdrant_key, match=MatchValue(value=value['$eq']))
                    elif '$in' in value:
                        # Qdrant uses MatchAny for 'in' operator
                        return FieldCondition(key=qdrant_key, match=MatchAny(any=value['$in']))
                    elif '$ne' in value:
                        # Not equal - would need Filter with must_not
                        return None  # Skip for now, handle at filter level
                    else:
                        # Unknown operator, treat as simple match
                        return FieldCondition(key=qdrant_key, match=MatchValue(value=value))
                else:
                    # Simple value - direct equality
                    return FieldCondition(key=qdrant_key, match=MatchValue(value=value))
            
            def parse_filter_dict(filter_dict: Dict) -> Dict:
                """Recursively parse filter dictionary."""
                must_conditions = []
                should_conditions = []
                must_not_conditions = []
                
                if '$and' in filter_dict:
                    # Handle $and operator
                    for condition in filter_dict['$and']:
                        parsed = parse_filter_dict(condition)
                        if 'must' in parsed:
                            must_conditions.extend(parsed['must'])
                        if 'should' in parsed:
                            should_conditions.extend(parsed['should'])
                            
                elif '$or' in filter_dict:
                    # Handle $or operator
                    for condition in filter_dict['$or']:
                        parsed = parse_filter_dict(condition)
                        if 'must' in parsed:
                            should_conditions.extend(parsed['must'])
                        if 'should' in parsed:
                            should_conditions.extend(parsed['should'])
                            
                else:
                    # Handle simple key-value conditions
                    for key, value in filter_dict.items():
                        if key.startswith('$'):
                            continue  # Skip operators at this level
                        condition = convert_condition(key, value)
                        if condition:
                            must_conditions.append(condition)
                
                result = {}
                if must_conditions:
                    result['must'] = must_conditions
                if should_conditions:
                    result['should'] = should_conditions
                if must_not_conditions:
                    result['must_not'] = must_not_conditions
                    
                return result
            
            # Parse the filter
            qdrant_filter_dict = parse_filter_dict(where)
            
            # Convert to Filter object
            if qdrant_filter_dict:
                return Filter(**qdrant_filter_dict)
            
            return None
            
        except Exception as e:
            logger.error(f"Error converting ChromaDB filter to Qdrant: {e}")
            logger.error(f"Original filter: {where}")
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    def semantic_search(
        self,
        query: str,
        k: int = 5,
        where: Optional[Dict] = None,
        query_embedding: Optional[List[float]] = None
    ) -> List[Dict]:
        """Perform semantic search on the Qdrant store.
        
        Args:
            query: The search query string
            k: Number of results to return (default: 5)
            where: Optional metadata filter dictionary (ChromaDB or Qdrant format)
            query_embedding: Optional pre-computed query embedding vector
            
        Returns:
            List of dictionaries containing search results with scores
        """
        if not self.vectorstore:
            logger.warning("Qdrant vectorstore not initialized. Please initialize first.")
            return []
        
        try:
            logger.info(f"Query in semantic_search for {self.collection_name}: {query}")
            
            # Convert where clause to Qdrant filter format if provided
            filter_dict = None
            if where is not None and isinstance(where, dict) and where:
                # Try to convert ChromaDB filter to Qdrant filter
                filter_dict = self._convert_chroma_filter_to_qdrant(where)
                if filter_dict:
                    logger.info(f"Converted filter for Qdrant: {filter_dict}")
                else:
                    logger.warning(f"Could not convert filter to Qdrant format: {where}")
            
            # Check if collection is empty first to avoid unnecessary queries
            try:
                collection_info = self.vectorstore.client.get_collection(self.collection_name)
                if collection_info.points_count == 0:
                    logger.info(f"Collection {self.collection_name} is empty (0 points), skipping search")
                    return []
            except Exception as e:
                logger.warning(f"Could not check collection point count: {e}")
            
            # Perform similarity search with filter
            # Try to pass filter to Qdrant, fallback to manual filtering if not supported
            max_retries = 1  # Reduced from 2 to 1 since we're handling empty collections
            retry_count = 0
            results = []
            
            while retry_count <= max_retries and not results:
                try:
                    if filter_dict and retry_count == 0:
                        # First attempt: Try to use native Qdrant filtering
                        try:
                            logger.info(f"Attempt {retry_count + 1}: Trying Qdrant native filtering")
                            results = self.vectorstore.similarity_search_with_score(
                                query=query,
                                k=k,
                                filter=filter_dict
                            )
                            logger.info(f"✓ Qdrant native filtering succeeded, got {len(results)} results")
                        except TypeError as te:
                            # Filter parameter not supported in this version, do manual filtering
                            logger.warning(f"Qdrant filter parameter not supported, using manual filtering: {te}")
                            results = self.vectorstore.similarity_search_with_score(
                                query=query,
                                k=k * 3  # Get more results for manual filtering
                            )
                            # Apply manual filtering
                            results = self._apply_manual_filter(results, where)[:k]
                            logger.info(f"✓ Manual filtering succeeded, got {len(results)} results")
                    else:
                        # No filter or retry - just search and apply manual filter
                        logger.info(f"Attempt {retry_count + 1}: Trying search {'with manual filtering' if where else 'without filter'}")
                        results = self.vectorstore.similarity_search_with_score(
                            query=query,
                            k=k * 3 if where else k
                        )
                        if where:
                            results = self._apply_manual_filter(results, where)[:k]
                        else:
                            results = results[:k]
                        logger.info(f"✓ Search succeeded, got {len(results)} results")
                    
                    # If we got results OR we got 0 results without error, break the retry loop
                    # (0 results is valid - collection might just not have matching data)
                    break
                        
                except Exception as e:
                    retry_count += 1
                    error_msg = str(e)
                    
                    # Check for specific connection errors
                    if "Server disconnected" in error_msg or "Connection" in error_msg or "timeout" in error_msg.lower():
                        if retry_count <= max_retries:
                            logger.warning(f"Connection error on attempt {retry_count}/{max_retries + 1}: {error_msg}")
                            logger.warning(f"Retrying in {retry_count} seconds...")
                            import time
                            time.sleep(retry_count)  # Exponential backoff
                        else:
                            logger.error(f"Max retries reached. Qdrant connection failed: {e}")
                            import traceback
                            logger.error(traceback.format_exc())
                            return []
                    else:
                        # Non-connection error, don't retry
                        logger.error(f"Error in similarity search (non-connection): {e}")
                        import traceback
                        logger.error(traceback.format_exc())
                        return []
            
            # Format results
            formatted_results = []
            for doc, score in results:
                meta = getattr(doc, "metadata", {}) or {}
                
                # Handle nested metadata structure
                if isinstance(meta, dict) and "metadata" in meta and isinstance(meta["metadata"], dict):
                    actual_meta = meta["metadata"]
                    actual_meta = {**actual_meta, **{k: v for k, v in meta.items() if k != "metadata"}}
                    meta = actual_meta
                
                # LangChain's Qdrant wrapper should set page_content correctly
                # Simple fallback to text for backwards compatibility with old documents
                content = getattr(doc, "page_content", "") or getattr(doc, "text", "")
                
                formatted_results.append({
                    "content": content,
                    "metadata": meta,
                    "score": float(score),
                    "id": meta.get("id", None)
                })
            
            # Sort by score (lower is better for distance-based scores)
            formatted_results.sort(key=lambda x: x["score"])
            
            logger.info(f"Found {len(formatted_results)} Qdrant results for query: {query}")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error during Qdrant semantic search: {str(e)}")
            return []
    
    def delete_by_project_id(self, project_id: str) -> Dict[str, int]:
        """Delete all documents for a specific project ID.
        
        Args:
            project_id: The project ID to delete documents for
            
        Returns:
            Dictionary containing the number of documents deleted
        """
        try:
            logger.info(f"Deleting documents for project ID: {project_id}")
            
            # Use Qdrant filter to delete by project_id
            from qdrant_client.models import Filter, FieldCondition, MatchValue
            
            filter_dict = Filter(
                must=[FieldCondition(key="project_id", match=MatchValue(value=project_id))]
            )
            
            # Get documents matching the filter first to count them
            search_results = self.vectorstore.similarity_search(
                query="",  # Empty query, just using filter
                k=10000,  # Large number to get all matches
                filter=filter_dict
            )
            
            document_count = len(search_results)
            
            if document_count == 0:
                logger.info(f"No documents found for project ID: {project_id}")
                return {"documents_deleted": 0}
            
            # Delete using filter
            # Note: Qdrant delete by filter requires direct client access
            # Get point IDs first, then delete
            from qdrant_client.models import ScrollRequest
            scroll_result = self.qdrant_client.scroll(
                collection_name=self.collection_name,
                scroll_filter=filter_dict,
                limit=10000
            )
            point_ids = [point.id for point in scroll_result[0]]
            
            if point_ids:
                self.qdrant_client.delete(
                    collection_name=self.collection_name,
                    points_selector=point_ids
                )
            
            logger.info(f"Successfully deleted {document_count} documents for project ID: {project_id}")
            return {"documents_deleted": document_count}
            
        except Exception as e:
            error_msg = f"Error deleting documents for project ID {project_id}: {str(e)}"
            logger.error(error_msg)
            return {"documents_deleted": 0, "error": str(e)}

    def get_by_filter(self, where: Dict, limit: int = 500) -> List[Dict]:
        """Fetch all documents matching the filter (no semantic search). Used when semantic
        search returns 0 results so we can still return all tables/schemas for the project.
        Returns list of dicts with keys: content, metadata, score (1.0), id (same shape as semantic_search).
        """
        if not where:
            return []
        try:
            filter_dict = self._convert_chroma_filter_to_qdrant(where)
            if not filter_dict:
                return []
            scroll_result = self.qdrant_client.scroll(
                collection_name=self.collection_name,
                scroll_filter=filter_dict,
                limit=limit,
                with_payload=True,
            )
            points, _ = scroll_result
            formatted = []
            for point in points:
                payload = point.payload or {}
                # LangChain Qdrant may store page_content or content; metadata may be nested
                content = (
                    payload.get("page_content")
                    or payload.get("content")
                    or payload.get("text")
                    or ""
                )
                metadata = payload.get("metadata", payload)
                if isinstance(metadata, dict) is False:
                    metadata = payload
                formatted.append({
                    "content": content if isinstance(content, str) else str(content),
                    "metadata": metadata,
                    "score": 1.0,
                    "id": getattr(point.id, "uuid", str(point.id)) if point.id is not None else None,
                })
            logger.info(f"get_by_filter for {self.collection_name}: {len(formatted)} documents (filter-only, no semantic search)")
            return formatted
        except Exception as e:
            logger.warning(f"get_by_filter failed: {e}")
            return []


def create_langchain_doc_util(metadata: Dict, data: Dict) -> tuple[str, LangchainDocument]:
    """Create a Langchain document from metadata and data.
    
    Args:
        metadata: Dictionary containing document metadata
        data: Dictionary containing document content
        
    Returns:
        Tuple of (document_id, LangchainDocument) or (None, None) if invalid
    """
    try:
        # Handle None metadata
        if metadata is None:
            logger.warning("Metadata is None, using empty dict")
            metadata = {}
        
        # Handle None data
        if data is None:
            logger.warning("Data is None, using empty string for page_content")
            page_content = ""
        else:
            # Convert data to string, handling various data types
            if isinstance(data, str):
                page_content = data
            elif isinstance(data, dict):
                # Try to extract meaningful content from dict
                if 'content' in data:
                    page_content = str(data['content'])
                elif 'text' in data:
                    page_content = str(data['text'])
                else:
                    page_content = str(data)
            else:
                page_content = str(data)
        
        # Ensure page_content is not None
        if page_content is None:
            logger.warning("page_content is None after processing, using empty string")
            page_content = ""
        
        document_id = str(uuid4())
        document = LangchainDocument(
            page_content=page_content,
            metadata=metadata,
            id=document_id
        )
        
        return document_id, document
    except Exception as e:
        logger.error(f"Error creating Langchain document: {str(e)}")
        logger.error(f"Metadata: {metadata}")
        logger.error(f"Data: {data}")
        return None, None

class AsyncDocumentWriter:
    """Asynchronous document writer for Chroma document store."""
    
    def __init__(self, document_store: DocumentChromaStore, policy: Optional[DuplicatePolicy] = None):
        """Initialize the async document writer.
        
        Args:
            document_store: The Chroma document store instance
            policy: Optional duplicate policy (SKIP, OVERWRITE, or FAIL)
        """
        self.document_store = document_store
        self.policy = policy or DuplicatePolicy.OVERWRITE

    async def run(self, documents: List[LangchainDocument], policy: Optional[DuplicatePolicy] = None) -> Dict[str, int]:
        """Write documents to the Chroma store asynchronously.
        
        Args:
            documents: List of LangchainDocument to write
            policy: Optional duplicate policy (SKIP, OVERWRITE, or FAIL)
            
        Returns:
            Dictionary containing the number of documents written
        """
        if not documents:
            logger.warning("No documents provided to write")
            return {"documents_written": 0}

        try:
            # Handle duplicates based on policy
            if policy == DuplicatePolicy.SKIP:
                # Filter out documents that already exist
                existing_ids = set(self.document_store.collection.get()['ids'])
                documents = [doc for doc in documents if doc.metadata.get('id') not in existing_ids]
            elif policy == DuplicatePolicy.FAIL:
                # Check if any documents already exist
                existing_ids = set(self.document_store.collection.get()['ids'])
                duplicate_ids = [doc.metadata.get('id') for doc in documents if doc.metadata.get('id') in existing_ids]
                if duplicate_ids:
                    raise ValueError(f"Duplicate documents found with IDs: {duplicate_ids}")

            # Add documents to the store
            if documents:
                self.document_store.add_documents(documents)
                logger.info(f"Successfully wrote {len(documents)} documents to Chroma store")
                return {"documents_written": len(documents)}
            else:
                logger.info("No documents to write after applying duplicate policy")
                return {"documents_written": 0}
            
        except Exception as e:
            logger.error(f"Error writing documents to Chroma store: {str(e)}")
            return {"documents_written": 0}

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Initialize the persistent client
        logger.info(f"Initializing persistent client at {CHROMA_STORE_PATH}")
        client = chromadb.PersistentClient(path=CHROMA_STORE_PATH)
        
        # Create a test collection
        collection_name = "test_collection"
        doc_store = DocumentChromaStore(
            persistent_client=client,
            collection_name=collection_name
        )
        
        # Initialize the store
        doc_store.initialize()
        
        # Create some example documents
        example_docs = [
            {
                "metadata": {
                    "source": "test_doc_1",
                    "author": "John Doe",
                    "date": "2024-03-20",
                    "category": "AI"
                },
                "data": {
                    "title": "Sample Document 1",
                    "content": "This is a test document about artificial intelligence and machine learning.",
                    "tags": ["AI", "ML"]
                }
            },
            {
                "metadata": {
                    "source": "test_doc_2",
                    "author": "Jane Smith",
                    "date": "2024-03-21",
                    "category": "NLP"
                },
                "data": {
                    "title": "Sample Document 2",
                    "content": "This document discusses natural language processing and its applications.",
                    "tags": ["NLP", "AI"]
                }
            }
        ]
        
        # Add documents to the store
        logger.info("Adding example documents to the store")
        doc_store.add_documents(example_docs)
        
        # Test semantic search
        logger.info("Testing semantic search...")
        search_query = "What are the applications of artificial intelligence?"
        results = doc_store.semantic_search(search_query, k=2)
        
        # Print search results
        logger.info(f"\nSearch results for query: {search_query}")
        for idx, result in enumerate(results, 1):
            logger.info(f"\nResult {idx}:")
            logger.info(f"Score: {result['score']}")
            logger.info(f"Content: {result['content']}")
            logger.info(f"Metadata: {result['metadata']}")
        
        # Test semantic search with metadata filter
        logger.info("\nTesting semantic search with metadata filter...")
        filter_query = "What are the applications of artificial intelligence?"
        filter_results = doc_store.semantic_search(
            filter_query,
            k=2,
            where={"category": "AI"}
        )
        
        # Print filtered search results
        logger.info(f"\nFiltered search results for query: {filter_query}")
        for idx, result in enumerate(filter_results, 1):
            logger.info(f"\nResult {idx}:")
            logger.info(f"Score: {result['score']}")
            logger.info(f"Content: {result['content']}")
            logger.info(f"Metadata: {result['metadata']}")
        
        # Test semantic search with BM25
        logger.info("\nTesting semantic search with BM25 ranking...")
        bm25_query = "What are the applications of artificial intelligence?"
        bm25_results = doc_store.semantic_search_with_bm25(bm25_query, k=2)
        
        # Print BM25 search results
        logger.info(f"\nBM25 search results for query: {bm25_query}")
        for idx, result in enumerate(bm25_results, 1):
            logger.info(f"\nResult {idx}:")
            logger.info(f"Combined Score: {result['combined_score']}")
            logger.info(f"Vector Score: {result['vector_score']}")
            logger.info(f"BM25 Score: {result['bm25_score']}")
            logger.info(f"Content: {result['content']}")
            logger.info(f"Metadata: {result['metadata']}")
        
    except Exception as e:
        logger.error(f"Error during testing: {str(e)}")
        raise
