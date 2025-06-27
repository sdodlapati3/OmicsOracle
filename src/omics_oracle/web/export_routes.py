"""
Export routes for OmicsOracle web interface.

This module provides export functionality including PDF reports.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Import our services
from ..services.pdf_export import pdf_service

logger = logging.getLogger(__name__)

# Create export router
export_router = APIRouter()


class ExportRequest(BaseModel):
    """Request model for export operations."""
    query_result: Dict[str, Any]
    format: str = "pdf"  # pdf, json, csv, txt
    include_metadata: bool = True
    include_ai_summaries: bool = True
    filename: str = None


class ExportResponse(BaseModel):
    """Response model for export operations."""
    export_id: str
    filename: str
    format: str
    status: str
    download_url: str = None
    file_size: int = None
    created_at: str


# Storage for export jobs (in production, use Redis or database)
export_jobs: Dict[str, Dict[str, Any]] = {}


@export_router.post("/export", response_model=ExportResponse)
async def create_export(request: ExportRequest, background_tasks: BackgroundTasks):
    """
    Create an export job for search results.
    
    This endpoint accepts search results and creates an export in the requested format.
    """
    try:
        # Generate export ID
        export_id = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(str(request.query_result)) % 10000:04d}"
        
        # Create export job
        export_job = {
            "id": export_id,
            "format": request.format,
            "status": "processing",
            "created_at": datetime.now().isoformat(),
            "query_result": request.query_result,
            "include_metadata": request.include_metadata,
            "include_ai_summaries": request.include_ai_summaries,
            "filename": request.filename
        }
        
        export_jobs[export_id] = export_job
        
        # Start background processing
        background_tasks.add_task(process_export, export_id)
        
        return ExportResponse(
            export_id=export_id,
            filename=f"export_{export_id}.{request.format}",
            format=request.format,
            status="processing",
            created_at=export_job["created_at"]
        )
        
    except Exception as e:
        logger.error(f"Error creating export: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create export: {str(e)}"
        )


@export_router.get("/export/{export_id}", response_model=ExportResponse)
async def get_export_status(export_id: str):
    """Get the status of an export job."""
    if export_id not in export_jobs:
        raise HTTPException(
            status_code=404,
            detail="Export job not found"
        )
        
    job = export_jobs[export_id]
    
    response = ExportResponse(
        export_id=export_id,
        filename=job.get("filename", f"export_{export_id}.{job['format']}"),
        format=job["format"],
        status=job["status"],
        created_at=job["created_at"]
    )
    
    if job["status"] == "completed" and "file_path" in job:
        response.download_url = f"/api/export/{export_id}/download"
        if Path(job["file_path"]).exists():
            response.file_size = Path(job["file_path"]).stat().st_size
            
    return response


@export_router.get("/export/{export_id}/download")
async def download_export(export_id: str):
    """Download a completed export file."""
    if export_id not in export_jobs:
        raise HTTPException(
            status_code=404,
            detail="Export job not found"
        )
        
    job = export_jobs[export_id]
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Export is not ready. Status: {job['status']}"
        )
        
    if "file_path" not in job:
        raise HTTPException(
            status_code=500,
            detail="Export file path not found"
        )
        
    file_path = Path(job["file_path"])
    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Export file not found"
        )
        
    # Determine media type
    media_type_map = {
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
        "txt": "text/plain"
    }
    
    media_type = media_type_map.get(job["format"], "application/octet-stream")
    
    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        filename=job.get("filename", f"export_{export_id}.{job['format']}")
    )


@export_router.delete("/export/{export_id}")
async def delete_export(export_id: str):
    """Delete an export job and its associated file."""
    if export_id not in export_jobs:
        raise HTTPException(
            status_code=404,
            detail="Export job not found"
        )
        
    job = export_jobs[export_id]
    
    # Delete file if it exists
    if "file_path" in job:
        file_path = Path(job["file_path"])
        if file_path.exists():
            try:
                file_path.unlink()
                logger.info(f"Deleted export file: {file_path}")
            except Exception as e:
                logger.error(f"Error deleting export file: {e}")
                
    # Remove job from memory
    del export_jobs[export_id]
    
    return {"message": "Export deleted successfully"}


@export_router.get("/exports")
async def list_exports():
    """List all export jobs."""
    exports = []
    for export_id, job in export_jobs.items():
        exports.append({
            "export_id": export_id,
            "format": job["format"],
            "status": job["status"],
            "created_at": job["created_at"],
            "filename": job.get("filename", f"export_{export_id}.{job['format']}")
        })
        
    return {"exports": exports}


async def process_export(export_id: str):
    """Background task to process export jobs."""
    try:
        job = export_jobs[export_id]
        logger.info(f"Processing export {export_id} in format {job['format']}")
        
        query_result = job["query_result"]
        export_format = job["format"]
        
        # Create exports directory
        exports_dir = Path("data/exports")
        exports_dir.mkdir(parents=True, exist_ok=True)
        
        if export_format == "pdf":
            # Generate PDF report
            output_path = exports_dir / f"report_{export_id}.pdf"
            file_path = pdf_service.generate_report(
                query_result=query_result,
                output_path=output_path,
                include_metadata=job["include_metadata"],
                include_ai_summaries=job["include_ai_summaries"]
            )
            
        elif export_format == "json":
            # Export as JSON
            import json
            output_path = exports_dir / f"data_{export_id}.json"
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(query_result, f, indent=2, ensure_ascii=False)
            file_path = output_path
            
        elif export_format == "csv":
            # Export as CSV
            import csv
            output_path = exports_dir / f"data_{export_id}.csv"
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if query_result.get('metadata'):
                    writer = csv.DictWriter(f, fieldnames=['id', 'title', 'organism', 'platform', 'sample_count', 'summary'])
                    writer.writeheader()
                    for dataset in query_result['metadata']:
                        writer.writerow({
                            'id': dataset.get('id', ''),
                            'title': dataset.get('title', ''),
                            'organism': dataset.get('organism', ''),
                            'platform': dataset.get('platform', ''),
                            'sample_count': dataset.get('sample_count', ''),
                            'summary': dataset.get('summary', '')
                        })
            file_path = output_path
            
        elif export_format == "txt":
            # Export as text
            output_path = exports_dir / f"report_{export_id}.txt"
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"OmicsOracle Export Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"Query: {query_result.get('original_query', 'N/A')}\n")
                f.write(f"Results: {len(query_result.get('metadata', []))} datasets\n\n")
                
                if query_result.get('ai_summaries') and job["include_ai_summaries"]:
                    f.write("AI Insights:\n")
                    f.write("-" * 20 + "\n")
                    import json
                    f.write(json.dumps(query_result['ai_summaries'], indent=2))
                    f.write("\n\n")
                    
                if query_result.get('metadata') and job["include_metadata"]:
                    f.write("Dataset Details:\n")
                    f.write("-" * 20 + "\n")
                    for i, dataset in enumerate(query_result['metadata'], 1):
                        f.write(f"{i}. {dataset.get('title', 'Untitled')}\n")
                        f.write(f"   ID: {dataset.get('id', 'N/A')}\n")
                        f.write(f"   Organism: {dataset.get('organism', 'Not specified')}\n")
                        f.write(f"   Summary: {dataset.get('summary', 'No summary')}\n\n")
            file_path = output_path
            
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
            
        # Update job status
        job["status"] = "completed"
        job["file_path"] = str(file_path)
        job["completed_at"] = datetime.now().isoformat()
        
        logger.info(f"Export {export_id} completed successfully: {file_path}")
        
    except Exception as e:
        logger.error(f"Error processing export {export_id}: {e}")
        if export_id in export_jobs:
            export_jobs[export_id]["status"] = "failed"
            export_jobs[export_id]["error"] = str(e)
