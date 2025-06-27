"""
Batch processing routes for OmicsOracle web interface.

This module provides endpoints for:
- Creating and managing batch jobs
- Monitoring batch processing progress
- Exporting batch results
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..services.batch_processor import BatchProcessor

logger = logging.getLogger(__name__)

# Create batch router
batch_router = APIRouter()

# Global batch processor instance
batch_processor = BatchProcessor(max_workers=3)


class BatchJobRequest(BaseModel):
    """Request model for creating batch jobs."""

    name: Optional[str] = None
    queries: List[str] = []
    max_results_per_query: int = 10
    enable_ai: bool = True


class BatchJobResponse(BaseModel):
    """Response model for batch job information."""

    job_id: str
    message: str


@batch_router.post("/batch/create", response_model=BatchJobResponse)
async def create_batch_job(request: BatchJobRequest):
    """
    Create a new batch processing job.

    This endpoint allows users to submit multiple queries for batch processing
    with optional AI summarization.
    """
    try:
        if not request.queries:
            raise HTTPException(
                status_code=400, detail="At least one query must be provided"
            )

        if len(request.queries) > 50:  # Reasonable limit
            raise HTTPException(
                status_code=400,
                detail="Maximum 50 queries allowed per batch job",
            )

        # Create batch job
        job_id = batch_processor.create_batch_job(
            queries=request.queries,
            name=request.name,
            max_results_per_query=request.max_results_per_query,
            enable_ai=request.enable_ai,
        )

        logger.info(
            f"Created batch job {job_id} with {len(request.queries)} queries"
        )

        return BatchJobResponse(
            job_id=job_id,
            message=f"Batch job created with {len(request.queries)} queries",
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating batch job: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to create batch job: {str(e)}"
        )


@batch_router.post("/batch/{job_id}/start")
async def start_batch_job(job_id: str):
    """
    Start processing a batch job.

    This will begin processing all queries in the batch job asynchronously.
    """
    try:
        # Start processing in background
        import asyncio

        async def process_job():
            try:
                await batch_processor.process_batch_job(job_id)
            except Exception as e:
                logger.error(
                    f"Background batch processing failed for {job_id}: {e}"
                )

        # Start the job in background
        asyncio.create_task(process_job())

        return {
            "status": "success",
            "message": f"Batch job {job_id} started",
            "job_id": job_id,
        }

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error starting batch job {job_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to start batch job: {str(e)}"
        )


@batch_router.get("/batch/{job_id}/status")
async def get_batch_job_status(job_id: str):
    """
    Get the status and progress of a batch job.

    Returns detailed information about the batch job including
    progress, completed queries, and any errors.
    """
    try:
        batch_job = batch_processor.get_batch_job(job_id)

        if not batch_job:
            raise HTTPException(
                status_code=404, detail=f"Batch job {job_id} not found"
            )

        return {"status": "success", "job": batch_job.to_dict()}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting batch job status {job_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get batch job status: {str(e)}"
        )


@batch_router.get("/batch/{job_id}/results")
async def get_batch_job_results(job_id: str, format: str = "json"):
    """
    Get the results of a completed batch job.

    Supports different export formats:
    - json: Full results with all data
    - summary: High-level summary of results
    """
    try:
        results = batch_processor.export_batch_results(job_id, format)

        if results is None:
            raise HTTPException(
                status_code=404, detail=f"Batch job {job_id} not found"
            )

        return {"status": "success", "format": format, "results": results}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting batch job results {job_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get batch job results: {str(e)}"
        )


@batch_router.get("/batch/list")
async def list_batch_jobs():
    """
    List all batch jobs with their current status.

    Returns a summary of all batch jobs for monitoring purposes.
    """
    try:
        jobs = batch_processor.list_batch_jobs()

        return {"status": "success", "total_jobs": len(jobs), "jobs": jobs}

    except Exception as e:
        logger.error(f"Error listing batch jobs: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to list batch jobs: {str(e)}"
        )


@batch_router.delete("/batch/{job_id}/cancel")
async def cancel_batch_job(job_id: str):
    """
    Cancel a running batch job.

    This will stop processing of remaining queries in the batch.
    """
    try:
        success = batch_processor.cancel_batch_job(job_id)

        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"Batch job {job_id} not found or cannot be cancelled",
            )

        return {"status": "success", "message": f"Batch job {job_id} cancelled"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling batch job {job_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to cancel batch job: {str(e)}"
        )


@batch_router.post("/batch/cleanup")
async def cleanup_batch_jobs(older_than_hours: int = 24):
    """
    Clean up completed batch jobs older than specified hours.

    This helps manage storage and memory usage by removing old job data.
    """
    try:
        removed_count = batch_processor.cleanup_completed_jobs(older_than_hours)

        return {
            "status": "success",
            "removed_jobs": removed_count,
            "message": f"Cleaned up {removed_count} batch jobs older than {older_than_hours} hours",
        }

    except Exception as e:
        logger.error(f"Error cleaning up batch jobs: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to clean up batch jobs: {str(e)}"
        )
