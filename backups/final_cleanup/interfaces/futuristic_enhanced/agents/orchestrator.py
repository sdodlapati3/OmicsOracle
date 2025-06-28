"""
Agent Orchestrator for Futuristic Interface

Coordinates multiple AI agents and manages job workflows
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Optional

from ..models.futuristic_models import AgentMessage, JobStatus, SearchJob, SystemMetrics
from .base import AgentRegistry, BaseAgent, MessageType

logger = logging.getLogger(__name__)


class AgentOrchestrator:
    """Orchestrates multiple agents for complex workflows"""

    def __init__(self):
        self.registry = AgentRegistry()
        self.active_jobs: Dict[str, SearchJob] = {}
        self.job_results: Dict[str, Dict] = {}
        self.is_running = False
        self.start_time = None
        self.total_jobs_processed = 0

    async def start(self) -> None:
        """Start the orchestrator"""
        self.is_running = True
        self.start_time = datetime.utcnow()
        logger.info("[ORCHESTRATOR] Agent Orchestrator started")

        # Start all registered agents
        for agent in self.registry.get_active_agents():
            asyncio.create_task(agent.start())

    async def stop(self) -> None:
        """Stop the orchestrator and all agents"""
        self.is_running = False
        logger.info("[STOP] Stopping Agent Orchestrator")

        # Stop all agents
        for agent in self.registry.get_active_agents():
            await agent.stop()

    async def register_agent(self, agent: BaseAgent) -> None:
        """Register a new agent"""
        self.registry.register_agent(agent)

        # If orchestrator is running, start the agent
        if self.is_running:
            asyncio.create_task(agent.start())

    async def process_user_message(self, data: dict, client_id: str) -> dict:
        """Process user message and coordinate agent responses"""
        try:
            message_type = data.get("type", "")

            if message_type == "search":
                return await self._handle_search_message(data, client_id)
            elif message_type == "analyze":
                return await self._handle_analysis_message(data, client_id)
            elif message_type == "visualize":
                return await self._handle_visualization_message(data, client_id)
            elif message_type == "status":
                return await self._handle_status_request(client_id)
            else:
                return {
                    "type": "error",
                    "message": f"Unknown message type: {message_type}",
                    "client_id": client_id,
                }

        except Exception as e:
            logger.error(f"Error processing user message: {e}")
            return {
                "type": "error",
                "message": "Failed to process request",
                "client_id": client_id,
            }

    async def _handle_search_message(self, data: dict, client_id: str) -> dict:
        """Handle search request"""
        query = data.get("query", "")
        search_type = data.get("search_type", "basic")
        filters = data.get("filters", {})

        # Create search job
        job = SearchJob(
            id=str(uuid.uuid4()),
            query=query,
            search_type=search_type,
            filters=filters,
            status=JobStatus.PROCESSING,
        )

        self.active_jobs[job.id] = job

        # Start background processing
        asyncio.create_task(self.process_search_job(job))

        return {
            "type": "search_started",
            "job_id": job.id,
            "message": "AI agents are processing your search",
            "estimated_time": 30,
            "client_id": client_id,
        }

    async def process_search_job(self, job: SearchJob) -> None:
        """Process a search job through multiple agents"""
        try:
            job.started_at = datetime.utcnow()
            job.progress = 10.0

            # Step 1: Search Agent
            search_agents = self.registry.get_agents_by_type("search")
            if not search_agents:
                raise Exception("No search agents available")

            search_agent = search_agents[0]
            search_message = AgentMessage(
                type=MessageType.SEARCH_REQUEST,
                sender_id="orchestrator",
                target_id=search_agent.agent_id,
                payload={
                    "job_id": job.id,
                    "query": job.query,
                    "search_type": job.search_type,
                    "filters": job.filters,
                },
            )

            await search_agent.send_message(search_message)
            job.progress = 30.0

            # Wait for search results (simplified - in production, use proper message handling)
            await asyncio.sleep(2)

            # Mock search results for demonstration
            search_results = [
                {
                    "id": f"result_{i}",
                    "title": f"Sample Paper {i} for '{job.query}'",
                    "abstract": f"This is a sample abstract for paper {i} related to {job.query}",
                    "authors": ["Dr. Sample", "Prof. Example"],
                    "source": "Mock Database",
                    "confidence_score": 0.8 + (i * 0.02),
                    "tags": ["mock", "sample"],
                    "metadata": {},
                }
                for i in range(min(10, 15))  # Mock 10-15 results
            ]

            job.progress = 60.0

            # Step 2: Analysis Agent
            analysis_agents = self.registry.get_agents_by_type("analysis")
            if analysis_agents:
                analysis_agent = analysis_agents[0]
                analysis_message = AgentMessage(
                    type=MessageType.ANALYZE_REQUEST,
                    sender_id="orchestrator",
                    target_id=analysis_agent.agent_id,
                    payload={
                        "job_id": job.id,
                        "data": search_results,
                        "analysis_type": "comprehensive",
                    },
                )

                await analysis_agent.send_message(analysis_message)
                await asyncio.sleep(1)

            job.progress = 80.0

            # Step 3: Visualization Agent
            visualizations = []
            viz_agents = self.registry.get_agents_by_type("visualization")
            if viz_agents:
                viz_agent = viz_agents[0]
                viz_message = AgentMessage(
                    type=MessageType.VISUALIZE_REQUEST,
                    sender_id="orchestrator",
                    target_id=viz_agent.agent_id,
                    payload={
                        "job_id": job.id,
                        "data": search_results,
                        "visualization_type": "comprehensive",
                    },
                )

                await viz_agent.send_message(viz_message)
                await asyncio.sleep(1)

            # Complete the job
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            job.progress = 100.0

            # Store results
            self.job_results[job.id] = {
                "job": job.dict(),
                "results": search_results,
                "insights": [
                    {
                        "type": "summary",
                        "title": "Search Complete",
                        "description": f"Found {len(search_results)} relevant results for '{job.query}'",
                        "confidence": 0.9,
                    }
                ],
                "visualizations": visualizations,
                "processing_time": (job.completed_at - job.started_at).total_seconds(),
            }

            self.total_jobs_processed += 1
            logger.info(f"[OK] Completed search job {job.id}")

        except Exception as e:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.utcnow()
            logger.error(f"[ERROR] Failed to process job {job.id}: {e}")

            self.job_results[job.id] = {
                "job": job.dict(),
                "error": str(e),
                "processing_time": (job.completed_at - job.started_at).total_seconds()
                if job.started_at
                else 0,
            }

    async def get_job_result(self, job_id: str) -> Optional[Dict]:
        """Get results for a specific job"""
        return self.job_results.get(job_id)

    async def _handle_analysis_message(self, data: dict, client_id: str) -> dict:
        """Handle analysis request"""
        # Implementation for direct analysis requests
        return {
            "type": "analysis_complete",
            "message": "Analysis functionality available through search",
            "client_id": client_id,
        }

    async def _handle_visualization_message(self, data: dict, client_id: str) -> dict:
        """Handle visualization request"""
        # Implementation for direct visualization requests
        return {
            "type": "visualization_complete",
            "message": "Visualization functionality available through search",
            "client_id": client_id,
        }

    async def _handle_status_request(self, client_id: str) -> dict:
        """Handle status request"""
        metrics = await self.get_system_metrics()

        return {
            "type": "status_response",
            "data": metrics.dict(),
            "client_id": client_id,
        }

    async def get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        active_agents = self.registry.get_active_agents()
        uptime_hours = 0.0

        if self.start_time:
            uptime_hours = (datetime.utcnow() - self.start_time).total_seconds() / 3600

        # Calculate average response time from recent jobs
        recent_jobs = list(self.job_results.values())[-10:]  # Last 10 jobs
        avg_response_time = 0.0
        if recent_jobs:
            total_time = sum(job.get("processing_time", 0) for job in recent_jobs)
            avg_response_time = total_time / len(recent_jobs)

        return SystemMetrics(
            active_agents=len(active_agents),
            pending_jobs=len([j for j in self.active_jobs.values() if j.status == JobStatus.PENDING]),
            processing_jobs=len([j for j in self.active_jobs.values() if j.status == JobStatus.PROCESSING]),
            completed_jobs_today=self.total_jobs_processed,
            average_response_time=avg_response_time,
            system_load=50.0,  # Mock value
            memory_usage=30.0,  # Mock value
            uptime=uptime_hours,
        )

    @property
    def active_agent_count(self) -> int:
        """Get count of active agents"""
        return len(self.registry.get_active_agents())
