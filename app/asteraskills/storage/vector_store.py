"""
Vector Store Abstraction
Supports multiple vector store backends using the unified storage architecture from documents.py
"""
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import chromadb
from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document as LangchainDocument

from asteraskills.config.settings import get_settings, VectorStoreType
from asteraskills.storage.documents import DocumentChromaStore, DocumentVectorstore, DocumentQdrantStore

logger = logging.getLogger(__name__)


class VectorStoreClient(ABC):
    """Abstract base class for vector store clients"""
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the vector store client"""
        pass
    
    @abstractmethod
    async def get_collection(self, collection_name: str, create_if_not_exists: bool = True):
        """Get or create a collection"""
        pass
    
    @abstractmethod
    async def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> List[str]:
        """Add documents to a collection"""
        pass
    
    @abstractmethod
    async def query(
        self,
        collection_name: str,
        query_texts: Optional[List[str]] = None,
        query_embeddings: Optional[List[List[float]]] = None,
        n_results: int = 10,
        where: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Query the vector store"""
        pass
    
    @abstractmethod
    async def delete(
        self,
        collection_name: str,
        ids: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Delete documents from a collection"""
        pass
    
    @abstractmethod
    async def get_embeddings_model(self) -> OpenAIEmbeddings:
        """Get the embeddings model"""
        pass
    
    @abstractmethod
    def normalize_filter(self, where: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Normalize filter dictionary for the specific vector store backend.
        
        This method handles vector store-specific filter requirements:
        - Converts list values to appropriate operator format ($in for ChromaDB, etc.)
        - Handles multiple conditions with appropriate operators ($and, etc.)
        - Ensures filters are compatible with the vector store's query API
        
        Args:
            where: Filter dictionary with metadata conditions (may contain lists, operators, etc.)
            
        Returns:
            Normalized filter dictionary compatible with the vector store backend
        """
        pass


class ChromaVectorStoreClient(VectorStoreClient):
    """ChromaDB implementation using DocumentChromaStore from storage architecture"""
    
    def __init__(self, config: Dict[str, Any], embeddings_model: Optional[OpenAIEmbeddings] = None):
        """Initialize ChromaDB client using DocumentChromaStore"""
        self.config = config
        self._embeddings_model = embeddings_model
        
        # Initialize ChromaDB client
        if config.get("use_local", True):
            # Get persist_directory from config or settings, never use hardcoded fallback
            persist_directory = config.get("persist_directory")
            if not persist_directory:
                from asteraskills.config.settings import get_settings
                settings = get_settings()
                persist_directory = settings.CHROMA_STORE_PATH
            # Ensure path is absolute (resolve relative to BASE_DIR if needed)
            import os
            if not os.path.isabs(persist_directory):
                from asteraskills.config.settings import get_settings
                settings = get_settings()
                persist_directory = str(settings.BASE_DIR / persist_directory)
            self._client = chromadb.PersistentClient(path=persist_directory)
        else:
            self._client = chromadb.HttpClient(
                host=config.get("host", "localhost"),
                port=config.get("port", 8888)
            )
        
        # Store DocumentChromaStore instances per collection
        self._document_stores: Dict[str, DocumentChromaStore] = {}
        self._embeddings_model = embeddings_model or self._get_default_embeddings()
    
    @property
    def client(self):
        """Get the underlying ChromaDB client (for backward compatibility)"""
        return self._client
    
    def _get_default_embeddings(self) -> OpenAIEmbeddings:
        """Get default embeddings model"""
        settings = get_settings()
        return OpenAIEmbeddings(
            model=settings.EMBEDDING_MODEL,
            openai_api_key=settings.OPENAI_API_KEY
        )
    
    def _get_document_store(self, collection_name: str) -> DocumentChromaStore:
        """Get or create a DocumentChromaStore for a collection"""
        if collection_name not in self._document_stores:
            self._document_stores[collection_name] = DocumentChromaStore(
                persistent_client=self._client,
                collection_name=collection_name,
                embeddings_model=self._embeddings_model,
                tf_idf=self.config.get("tf_idf", False)
            )
        return self._document_stores[collection_name]
    
    async def initialize(self) -> None:
        """Initialize the client"""
        logger.info("ChromaDB client initialized using DocumentChromaStore")
    
    async def get_collection(self, collection_name: str, create_if_not_exists: bool = True):
        """Get or create a collection using DocumentChromaStore"""
        doc_store = self._get_document_store(collection_name)
        # Return the underlying collection for backward compatibility
        return doc_store.collection
    
    async def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> List[str]:
        """Add documents to a collection using DocumentChromaStore"""
        doc_store = self._get_document_store(collection_name)
        
        # Convert to LangchainDocument format
        metadatas = metadatas or [{}] * len(documents)
        if ids is None:
            import uuid
            ids = [str(uuid.uuid4()) for _ in documents]
        
        langchain_docs = []
        for doc_text, metadata, doc_id in zip(documents, metadatas, ids):
            metadata_with_id = {**metadata, "id": doc_id}
            langchain_docs.append(LangchainDocument(
                page_content=doc_text,
                metadata=metadata_with_id
            ))
        
        # Use DocumentChromaStore's add_documents method
        result_ids = doc_store.add_documents(langchain_docs)
        return result_ids if result_ids else ids
    
    async def query(
        self,
        collection_name: str,
        query_texts: Optional[List[str]] = None,
        query_embeddings: Optional[List[List[float]]] = None,
        n_results: int = 10,
        where: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Query the vector store using DocumentChromaStore"""
        doc_store = self._get_document_store(collection_name)
        
        if query_texts is None and query_embeddings is None:
            raise ValueError("Either query_texts or query_embeddings must be provided")
        
        # Use DocumentChromaStore's semantic_search method
        if query_texts:
            # Handle both string and list inputs
            if isinstance(query_texts, list):
                # Use the first query text for semantic search
                query = query_texts[0] if len(query_texts) > 0 else ""
            else:
                query = query_texts
            
            if not query:
                raise ValueError("query_texts must contain at least one non-empty query")
            
            results = doc_store.semantic_search(
                query=query,
                k=n_results,
                where=where
            )
            
            # Convert to expected format (ChromaDB query format)
            return {
                "ids": [[r.get("id")] for r in results] if results else [],
                "documents": [[r.get("content")] for r in results] if results else [],
                "metadatas": [[r.get("metadata")] for r in results] if results else [],
                "distances": [[r.get("score", 0.0)] for r in results] if results else []
            }
        else:
            # For query_embeddings, we need to use the collection directly
            # This is a fallback for direct embedding queries
            collection = doc_store.collection
            logger.info(f"Querying ChromaDB collection '{collection_name}' with n_results={n_results}")
            
            # Check collection count before querying
            try:
                count = collection.count()
                logger.info(f"Collection '{collection_name}' has {count} documents")
                if count == 0:
                    logger.warning(f"Collection '{collection_name}' is empty - query will return no results")
                elif n_results > count:
                    logger.warning(f"Requested {n_results} results but collection '{collection_name}' only has {count} documents")
            except Exception as e:
                logger.debug(f"Could not get count for collection '{collection_name}': {e}")
            
            results = collection.query(
                query_embeddings=query_embeddings,
                n_results=n_results,
                where=where
            )
            return results
    
    async def delete(
        self,
        collection_name: str,
        ids: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Delete documents from a collection using DocumentChromaStore"""
        doc_store = self._get_document_store(collection_name)
        
        if ids:
            doc_store.collection.delete(ids=ids)
        elif where:
            doc_store.collection.delete(where=where)
        else:
            raise ValueError("Either ids or where must be provided")
        
        return True
    
    async def get_embeddings_model(self) -> OpenAIEmbeddings:
        """Get the embeddings model"""
        return self._embeddings_model
    
    def normalize_filter(self, where: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Normalize filter dictionary for ChromaDB compatibility.
        
        ChromaDB-specific requirements:
        - List values must be converted to $in operator format
        - Multiple conditions should be wrapped in $and operator
        - Supports: $eq, $ne, $gt, $gte, $lt, $lte, $in, $nin, $and, $or
        
        Args:
            where: Filter dictionary with metadata conditions
            
        Returns:
            Normalized filter dictionary compatible with ChromaDB
        """
        if not where:
            return where
        
        # Check if filter already uses operators ($and, $or, etc.)
        has_operator = any(key.startswith("$") for key in where.keys())
        
        # If it already has operators, recursively normalize nested conditions
        if has_operator:
            normalized = {}
            for k, v in where.items():
                if k == "$and" and isinstance(v, list):
                    # Normalize each condition in $and
                    normalized["$and"] = [self.normalize_filter(cond) for cond in v if cond]
                elif k == "$or" and isinstance(v, list):
                    # Normalize each condition in $or
                    normalized["$or"] = [self.normalize_filter(cond) for cond in v if cond]
                else:
                    normalized[k] = v
            return normalized
        
        # Process simple key-value pairs: convert lists to $in, handle __contains
        formatted_conditions = {}
        for k, v in where.items():
            if not k.startswith("$"):
                # __contains suffix: array membership check (e.g. tactic_domains__contains: "persistence")
                if k.endswith("__contains"):
                    key = k[:-10]  # strip __contains
                    formatted_conditions[key] = {"$contains": v}
                elif isinstance(v, list) and len(v) > 0:
                    formatted_conditions[k] = {"$in": v}
                else:
                    formatted_conditions[k] = v
        
        # If only one condition, return as-is
        if len(formatted_conditions) == 1:
            return formatted_conditions
        
        # Multiple conditions: wrap in $and operator
        # Format: {"$and": [{"key1": "value1"}, {"key2": "value2"}, ...]}
        and_conditions = [{k: v} for k, v in formatted_conditions.items()]
        return {"$and": and_conditions}


class QdrantVectorStoreClient(VectorStoreClient):
    """Qdrant implementation using DocumentQdrantStore from storage architecture"""
    
    def __init__(self, config: Dict[str, Any], embeddings_model: Optional[OpenAIEmbeddings] = None):
        """Initialize Qdrant client using DocumentQdrantStore"""
        self.config = config
        self._embeddings_model = embeddings_model or self._get_default_embeddings()
        
        # Store DocumentQdrantStore instances per collection
        self._document_stores: Dict[str, DocumentQdrantStore] = {}
    
    def _get_default_embeddings(self) -> OpenAIEmbeddings:
        """Get default embeddings model"""
        settings = get_settings()
        return OpenAIEmbeddings(
            model=settings.EMBEDDING_MODEL,
            openai_api_key=settings.OPENAI_API_KEY
        )
    
    def _get_document_store(self, collection_name: str) -> DocumentQdrantStore:
        """Get or create a DocumentQdrantStore for a collection"""
        if collection_name not in self._document_stores:
            self._document_stores[collection_name] = DocumentQdrantStore(
                collection_name=collection_name,
                embeddings_model=self._embeddings_model,
                host=self.config.get("host", "localhost"),
                port=self.config.get("port", 6333),
                tf_idf=self.config.get("tf_idf", False)
            )
        return self._document_stores[collection_name]
    
    async def initialize(self) -> None:
        """Initialize the client"""
        logger.info("Qdrant client initialized using DocumentQdrantStore")
    
    async def get_collection(self, collection_name: str, create_if_not_exists: bool = True):
        """Get or create a collection using DocumentQdrantStore"""
        doc_store = self._get_document_store(collection_name)
        # Return the underlying Qdrant client for backward compatibility
        return doc_store.qdrant_client
    
    async def add_documents(
        self,
        collection_name: str,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> List[str]:
        """Add documents to a collection using DocumentQdrantStore"""
        doc_store = self._get_document_store(collection_name)
        
        # Convert to LangchainDocument format
        metadatas = metadatas or [{}] * len(documents)
        if ids is None:
            import uuid
            ids = [str(uuid.uuid4()) for _ in documents]
        
        langchain_docs = []
        for doc_text, metadata, doc_id in zip(documents, metadatas, ids):
            metadata_with_id = {**metadata, "id": doc_id}
            langchain_docs.append(LangchainDocument(
                page_content=doc_text,
                metadata=metadata_with_id
            ))
        
        # Use DocumentQdrantStore's add_documents method
        result_ids = doc_store.add_documents(langchain_docs)
        return result_ids if result_ids else ids
    
    async def query(
        self,
        collection_name: str,
        query_texts: Optional[List[str]] = None,
        query_embeddings: Optional[List[List[float]]] = None,
        n_results: int = 10,
        where: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Query the vector store using DocumentQdrantStore"""
        doc_store = self._get_document_store(collection_name)
        
        if query_texts is None and query_embeddings is None:
            raise ValueError("Either query_texts or query_embeddings must be provided")
        
        # Use DocumentQdrantStore's semantic_search method
        if query_texts:
            # Handle both string and list inputs
            if isinstance(query_texts, list):
                query = query_texts[0] if len(query_texts) > 0 else ""
            else:
                query = query_texts
            
            if not query:
                raise ValueError("query_texts must contain at least one non-empty query")
            
            # Use query_embedding if provided, otherwise None (will compute from query)
            query_embedding = query_embeddings[0] if query_embeddings and len(query_embeddings) > 0 else None
            
            results = doc_store.semantic_search(
                query=query,
                k=n_results,
                where=where,
                query_embedding=query_embedding
            )
            
            # Convert to expected format (ChromaDB query format for compatibility)
            return {
                "ids": [[r.get("id")] for r in results] if results else [],
                "documents": [[r.get("content")] for r in results] if results else [],
                "metadatas": [[r.get("metadata")] for r in results] if results else [],
                "distances": [[r.get("score", 0.0)] for r in results] if results else []
            }
        else:
            # For query_embeddings only, use the first embedding
            if query_embeddings and len(query_embeddings) > 0:
                results = doc_store.semantic_search(
                    query="",  # Empty query, using embedding
                    k=n_results,
                    where=where,
                    query_embedding=query_embeddings[0]
                )
                
                return {
                    "ids": [[r.get("id")] for r in results] if results else [],
                    "documents": [[r.get("content")] for r in results] if results else [],
                    "metadatas": [[r.get("metadata")] for r in results] if results else [],
                    "distances": [[r.get("score", 0.0)] for r in results] if results else []
                }
            else:
                raise ValueError("query_embeddings must contain at least one embedding")
    
    async def delete(
        self,
        collection_name: str,
        ids: Optional[List[str]] = None,
        where: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Delete documents from a collection using DocumentQdrantStore"""
        doc_store = self._get_document_store(collection_name)
        
        if ids:
            # Delete by IDs
            doc_store.qdrant_client.delete(
                collection_name=collection_name,
                points_selector=ids
            )
        elif where:
            # Delete by filter
            from qdrant_client.models import Filter, FieldCondition, MatchValue
            conditions = []
            for key, value in where.items():
                if value is not None:
                    conditions.append(
                        FieldCondition(key=key, match=MatchValue(value=value))
                    )
            if conditions:
                filter_dict = Filter(must=conditions)
                doc_store.qdrant_client.delete(
                    collection_name=collection_name,
                    points_selector=filter_dict
                )
        else:
            raise ValueError("Either ids or where must be provided")
        
        return True
    
    async def get_embeddings_model(self) -> OpenAIEmbeddings:
        """Get the embeddings model"""
        return self._embeddings_model
    
    def normalize_filter(self, where: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Normalize filter dictionary for Qdrant compatibility.
        
        Handles __contains suffix for array membership (e.g. tactic_domains__contains: "persistence")
        -> converts to {"tactic_domains": {"$in": ["persistence"]}} for DocumentQdrantStore.
        
        Args:
            where: Filter dictionary with metadata conditions
            
        Returns:
            Normalized filter dictionary compatible with ChromaDB format (DocumentQdrantStore converts)
        """
        if not where:
            return where
        # Handle __contains: array membership check
        formatted = {}
        for k, v in where.items():
            if k.endswith("__contains"):
                key = k[:-10]
                formatted[key] = {"$in": [v] if not isinstance(v, list) else v}
            else:
                formatted[k] = v
        return formatted


def get_vector_store_client(
    embeddings_model: Optional[OpenAIEmbeddings] = None,
    config: Optional[Dict[str, Any]] = None
) -> VectorStoreClient:
    """
    Factory function to get a vector store client based on settings
    
    Args:
        embeddings_model: Optional embeddings model
        config: Optional configuration override
        
    Returns:
        VectorStoreClient instance
    """
    settings = get_settings()
    config = config or settings.get_vector_store_config()
    
    vector_store_type = config.get("type", VectorStoreType.CHROMA)
    
    if vector_store_type == VectorStoreType.CHROMA:
        return ChromaVectorStoreClient(config, embeddings_model)
    elif vector_store_type == VectorStoreType.QDRANT:
        return QdrantVectorStoreClient(config, embeddings_model)
    else:
        raise ValueError(f"Unsupported vector store type: {vector_store_type}")

