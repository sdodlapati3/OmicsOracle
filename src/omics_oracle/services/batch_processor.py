"""
Batch processing service for OmicsOracle.

This service provides:
- Parallel processing of multiple queries
- Progress tracking and status updates
- Results aggregation and export
- Cost-efficient AI batch summarization
"""

import asyncio
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class BatchStatus(Enum):
    """Status of a batch processing job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class BatchQuery:
    """Individual query within a batch job."""
    id: str
    query: str
    max_results: int = 10
    include_sra: bool = False
    enable_ai: bool = True
    status: BatchStatus = BatchStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None


@dataclass
class BatchJob:
    """Batch processing job containing multiple queries."""
    id: str
    name: str
    queries: List[BatchQuery]
    status: BatchStatus = BatchStatus.PENDING
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_queries: int = 0
    completed_queries: int = 0
    failed_queries: int = 0
    progress_callback: Optional[Callable] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        self.total_queries = len(self.queries)
    
    @property
    def progress_percent(self) -> float:
        """Calculate completion percentage."""
        if self.total_queries == 0:
            return 0.0
        return (self.completed_queries + self.failed_queries) / self.total_queries * 100
    
    @property
    def is_complete(self) -> bool:
        """Check if batch job is complete."""
        return self.status in [BatchStatus.COMPLETED, BatchStatus.FAILED, BatchStatus.CANCELLED]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_queries": self.total_queries,
            "completed_queries": self.completed_queries,
            "failed_queries": self.failed_queries,
            "progress_percent": self.progress_percent,
            "queries": [
                {
                    "id": q.id,
                    "query": q.query,
                    "status": q.status.value,
                    "error": q.error,
                    "processing_time": q.processing_time
                }
                for q in self.queries
            ]
        }


class BatchProcessor:
    """Service for processing multiple queries in batch with AI summaries."""
    
    def __init__(self, max_workers: int = 3):
        """
        Initialize batch processor.
        
        Args:
            max_workers: Maximum number of concurrent processing threads
        """
        self.max_workers = max_workers
        self.active_jobs: Dict[str, BatchJob] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        logger.info(f"Batch processor initialized with {max_workers} workers")
    
    def create_batch_job(
        self, 
        queries: List[str], 
        name: Optional[str] = None,
        max_results_per_query: int = 10,
        enable_ai: bool = True
    ) -> str:
        """
        Create a new batch processing job.
        
        Args:
            queries: List of search queries to process
            name: Optional name for the batch job
            max_results_per_query: Maximum results per individual query
            enable_ai: Whether to enable AI summarization
            
        Returns:
            Batch job ID
        """
        job_id = str(uuid.uuid4())[:8]
        job_name = name or f"Batch Job {job_id}"
        
        # Create batch queries
        batch_queries = [
            BatchQuery(
                id=f"{job_id}_q{i:03d}",
                query=query.strip(),
                max_results=max_results_per_query,
                enable_ai=enable_ai
            )
            for i, query in enumerate(queries, 1)
            if query.strip()
        ]
        
        if not batch_queries:
            raise ValueError("No valid queries provided")
        
        # Create batch job
        batch_job = BatchJob(
            id=job_id,
            name=job_name,
            queries=batch_queries
        )
        
        self.active_jobs[job_id] = batch_job
        
        logger.info(f"Created batch job '{job_name}' with {len(batch_queries)} queries")
        return job_id
    
    async def process_batch_job(self, job_id: str) -> BatchJob:
        """
        Process a batch job asynchronously.
        
        Args:
            job_id: The batch job ID to process
            
        Returns:
            Completed batch job
        """
        if job_id not in self.active_jobs:
            raise ValueError(f"Batch job {job_id} not found")
        
        batch_job = self.active_jobs[job_id]
        
        if batch_job.status != BatchStatus.PENDING:
            raise ValueError(f"Batch job {job_id} is not in pending status")
        
        batch_job.status = BatchStatus.RUNNING
        batch_job.started_at = datetime.utcnow()
        
        logger.info(f"Starting batch job {job_id} with {len(batch_job.queries)} queries")
        
        try:
            # Process queries concurrently
            await self._process_queries_concurrent(batch_job)
            
            # Mark as completed
            batch_job.status = BatchStatus.COMPLETED
            batch_job.completed_at = datetime.utcnow()
            
            logger.info(f"Batch job {job_id} completed: {batch_job.completed_queries} successful, {batch_job.failed_queries} failed")
            
        except Exception as e:
            batch_job.status = BatchStatus.FAILED
            batch_job.completed_at = datetime.utcnow()
            logger.error(f"Batch job {job_id} failed: {e}")
            raise
        
        return batch_job
    
    async def _process_queries_concurrent(self, batch_job: BatchJob):
        """Process batch queries with concurrency control."""
        from ..pipeline.pipeline import OmicsOracle, ResultFormat
        
        # Create semaphore to limit concurrent queries
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def process_single_query(batch_query: BatchQuery):
            async with semaphore:
                try:
                    batch_query.status = BatchStatus.RUNNING
                    start_time = datetime.utcnow()
                    
                    # Initialize pipeline for this query
                    oracle = OmicsOracle()
                    
                    try:
                        # Process the query
                        result = await oracle.process_query(
                            query=batch_query.query,
                            max_results=batch_query.max_results,
                            result_format=ResultFormat.JSON
                        )
                        
                        # Store result
                        batch_query.result = {
                            "query_id": result.query_id,
                            "original_query": result.original_query,
                            "expanded_query": result.expanded_query,
                            "status": result.status.value,
                            "geo_ids": result.geo_ids,
                            "metadata": result.metadata,
                            "ai_summaries": result.ai_summaries if batch_query.enable_ai else None,
                            "entities": result.entities,
                            "duration": result.duration
                        }
                        
                        batch_query.status = BatchStatus.COMPLETED
                        batch_job.completed_queries += 1
                        
                    finally:
                        await oracle.close()
                    
                    # Calculate processing time
                    processing_time = (datetime.utcnow() - start_time).total_seconds()
                    batch_query.processing_time = processing_time
                    
                    logger.info(f"Query '{batch_query.query[:50]}...' completed in {processing_time:.2f}s")
                    
                except Exception as e:
                    batch_query.status = BatchStatus.FAILED
                    batch_query.error = str(e)
                    batch_job.failed_queries += 1
                    
                    logger.error(f"Query '{batch_query.query[:50]}...' failed: {e}")
        
        # Process all queries concurrently
        tasks = [process_single_query(query) for query in batch_job.queries]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_batch_job(self, job_id: str) -> Optional[BatchJob]:
        """Get batch job by ID."""
        return self.active_jobs.get(job_id)
    
    def list_batch_jobs(self) -> List[Dict[str, Any]]:
        """List all batch jobs with their status."""
        return [job.to_dict() for job in self.active_jobs.values()]
    
    def cancel_batch_job(self, job_id: str) -> bool:
        """
        Cancel a running batch job.
        
        Args:
            job_id: The batch job ID to cancel
            
        Returns:
            True if successfully cancelled
        """
        if job_id not in self.active_jobs:
            return False
        
        batch_job = self.active_jobs[job_id]
        
        if batch_job.status == BatchStatus.RUNNING:
            batch_job.status = BatchStatus.CANCELLED
            batch_job.completed_at = datetime.utcnow()
            logger.info(f"Batch job {job_id} cancelled")
            return True
        
        return False
    
    def cleanup_completed_jobs(self, older_than_hours: int = 24) -> int:
        """
        Clean up completed jobs older than specified hours.
        
        Args:
            older_than_hours: Remove jobs completed more than this many hours ago
            
        Returns:
            Number of jobs removed
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=older_than_hours)
        removed_count = 0
        
        jobs_to_remove = []
        for job_id, job in self.active_jobs.items():
            if (job.is_complete and 
                job.completed_at and 
                job.completed_at < cutoff_time):
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del self.active_jobs[job_id]
            removed_count += 1
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} completed batch jobs")
        
        return removed_count
    
    def export_batch_results(
        self, 
        job_id: str, 
        format: str = "json"
    ) -> Optional[Dict[str, Any]]:
        """
        Export batch job results in specified format.
        
        Args:
            job_id: The batch job ID
            format: Export format ('json', 'csv', 'summary')
            
        Returns:
            Exported data or None if job not found
        """
        batch_job = self.get_batch_job(job_id)
        if not batch_job:
            return None
        
        if format == "json":
            return {
                "job_info": batch_job.to_dict(),
                "results": [
                    {
                        "query": q.query,
                        "status": q.status.value,
                        "result": q.result,
                        "error": q.error,
                        "processing_time": q.processing_time
                    }
                    for q in batch_job.queries
                ]
            }
        
        elif format == "summary":
            successful_queries = [q for q in batch_job.queries if q.status == BatchStatus.COMPLETED]
            total_datasets = sum(len(q.result.get("geo_ids", [])) for q in successful_queries if q.result)
            total_processing_time = sum(q.processing_time or 0 for q in batch_job.queries)
            
            return {
                "job_summary": {
                    "name": batch_job.name,
                    "total_queries": batch_job.total_queries,
                    "successful": batch_job.completed_queries,
                    "failed": batch_job.failed_queries,
                    "total_datasets_found": total_datasets,
                    "total_processing_time": total_processing_time,
                    "average_time_per_query": total_processing_time / batch_job.total_queries if batch_job.total_queries > 0 else 0
                },
                "query_results": [
                    {
                        "query": q.query,
                        "status": q.status.value,
                        "datasets_found": len(q.result.get("geo_ids", [])) if q.result else 0,
                        "has_ai_summary": bool(q.result and q.result.get("ai_summaries")) if q.result else False,
                        "processing_time": q.processing_time,
                        "error": q.error
                    }
                    for q in batch_job.queries
                ]
            }
        
        return None
    
    def __del__(self):
        """Clean up executor on deletion."""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)
