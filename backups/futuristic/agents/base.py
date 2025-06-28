"""
Enhanced Base Agent Architecture for Futuristic Interface

This module provides the foundation for AI agents in the next-generation interface
with improved error handling, metrics, and lifecycle management
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentType(str, Enum):
    """Types of AI agents"""

    SEARCH = "search"
    ANALYSIS = "analysis"
    VISUALIZATION = "visualization"
    ORCHESTRATOR = "orchestrator"


class AgentStatus(str, Enum):
    """Agent status enumeration"""

    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    INITIALIZING = "initializing"
    STOPPING = "stopping"


class AgentMessage(BaseModel):
    """Message structure for agent communication"""

    id: Optional[str] = None
    type: str = ""
    payload: Dict[str, Any] = {}
    sender: str = ""
    recipient: str = ""
    timestamp: Optional[datetime] = None
    priority: int = 0


class AgentStatusReport(BaseModel):
    """Detailed agent status report"""

    agent_id: str
    agent_type: AgentType
    status: AgentStatus
    is_active: bool
    current_job: Optional[str] = None
    jobs_completed: int = 0
    average_processing_time: float = 0.0
    last_activity: Optional[datetime] = None
    capabilities: List[str] = []


class AgentMetrics(BaseModel):
    """Agent performance metrics"""

    jobs_completed: int = 0
    jobs_failed: int = 0
    average_processing_time: float = 0.0
    last_activity: Optional[datetime] = None
    uptime_seconds: float = 0.0


class BaseAgent(ABC):
    """Abstract base class for all AI agents"""

    def __init__(self, agent_id: str, agent_type: AgentType):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.is_active = False
        self.message_queue = asyncio.Queue()
        self.current_job = None
        self.jobs_completed = 0
        self.processing_times = []
        self.last_activity = datetime.utcnow()
        self.capabilities = []

    @abstractmethod
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process an incoming message and return a response"""
        pass

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the agent and its resources"""
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up agent resources"""
        pass

    async def start(self):
        """Start the agent's message processing loop"""
        if not await self.initialize():
            logger.error(f"Failed to initialize agent {self.agent_id}")
            return

        self.is_active = True
        logger.info(f"[AGENT] Agent {self.agent_id} started")

        try:
            await self._message_loop()
        except Exception as e:
            logger.error(f"Agent {self.agent_id} error: {e}")
        finally:
            self.is_active = False
            await self.cleanup()

    async def stop(self):
        """Stop the agent"""
        self.is_active = False
        logger.info(f"[STOP] Agent {self.agent_id} stopping")

    async def send_message(self, message: AgentMessage):
        """Add a message to this agent's queue"""
        await self.message_queue.put(message)
        self.last_activity = datetime.utcnow()

    async def _message_loop(self):
        """Main message processing loop"""
        while self.is_active:
            try:
                # Wait for message with timeout
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)

                # Process message and track performance
                start_time = asyncio.get_event_loop().time()
                response = await self.process_message(message)
                processing_time = asyncio.get_event_loop().time() - start_time

                # Update metrics
                self.processing_times.append(processing_time)
                if len(self.processing_times) > 100:  # Keep only last 100
                    self.processing_times.pop(0)

                self.jobs_completed += 1
                self.last_activity = datetime.utcnow()

                # Send response if generated
                if response:
                    await self._send_response(response)

            except asyncio.TimeoutError:
                # No message received, continue loop
                continue
            except Exception as e:
                logger.error(f"Agent {self.agent_id} processing error: {e}")
                await self._handle_error(e)

    async def _send_response(self, response: AgentMessage):
        """Send response message (to be implemented by orchestrator)"""
        logger.debug(f"Agent {self.agent_id} sending response: {response.type}")

    async def _handle_error(self, error: Exception):
        """Handle processing errors"""
        logger.error(f"Agent {self.agent_id} error: {error}")
        # Could implement error recovery logic here

    def get_status(self) -> AgentStatusReport:
        """Get current agent status"""
        avg_time = sum(self.processing_times) / len(self.processing_times) if self.processing_times else 0.0

        current_status = (
            AgentStatus.BUSY
            if self.is_active and self.current_job
            else (AgentStatus.IDLE if self.is_active else AgentStatus.ERROR)
        )

        return AgentStatusReport(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            status=current_status,
            is_active=self.is_active,
            current_job=self.current_job,
            jobs_completed=self.jobs_completed,
            average_processing_time=avg_time,
            last_activity=self.last_activity,
            capabilities=self.capabilities,
        )

    def can_handle(self, message_type: str) -> bool:
        """Check if agent can handle a specific message type"""
        return message_type in self.capabilities


class AgentCapability:
    """Standard agent capabilities"""

    # Search capabilities
    TEXT_SEARCH = "text_search"
    SEMANTIC_SEARCH = "semantic_search"
    INTELLIGENT_SEARCH = "intelligent_search"

    # Analysis capabilities
    STATISTICAL_ANALYSIS = "statistical_analysis"
    SENTIMENT_ANALYSIS = "sentiment_analysis"
    TOPIC_MODELING = "topic_modeling"

    # Visualization capabilities
    NETWORK_VISUALIZATION = "network_visualization"
    TIMELINE_VISUALIZATION = "timeline_visualization"
    STATISTICAL_CHARTS = "statistical_charts"

    # Extraction capabilities
    TEXT_EXTRACTION = "text_extraction"
    METADATA_EXTRACTION = "metadata_extraction"
    ENTITY_EXTRACTION = "entity_extraction"

    # Discovery capabilities
    PUBLICATION_DISCOVERY = "publication_discovery"
    CITATION_ANALYSIS = "citation_analysis"
    RELATIONSHIP_DISCOVERY = "relationship_discovery"


class MessageType:
    """Standard message types for agent communication"""

    # Job management
    START_JOB = "start_job"
    COMPLETE_JOB = "complete_job"
    CANCEL_JOB = "cancel_job"
    STATUS_UPDATE = "status_update"

    # Search operations
    SEARCH_REQUEST = "search_request"
    SEARCH_RESPONSE = "search_response"
    SEARCH_PROGRESS = "search_progress"

    # Analysis operations
    ANALYZE_REQUEST = "analyze_request"
    ANALYZE_RESPONSE = "analyze_response"
    ANALYSIS_COMPLETE = "analysis_complete"

    # Visualization operations
    VISUALIZE_REQUEST = "visualize_request"
    VISUALIZE_RESPONSE = "visualize_response"
    VISUALIZATION_READY = "visualization_ready"

    # System messages
    HEALTH_CHECK = "health_check"
    SHUTDOWN = "shutdown"
    ERROR = "error"


class AgentRegistry:
    """Registry for managing agents"""

    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.agents_by_type: Dict[AgentType, List[str]] = {}
        self.agents_by_capability: Dict[str, List[str]] = {}

    def register_agent(self, agent: BaseAgent):
        """Register an agent"""
        self.agents[agent.agent_id] = agent

        # Index by type
        if agent.agent_type not in self.agents_by_type:
            self.agents_by_type[agent.agent_type] = []
        self.agents_by_type[agent.agent_type].append(agent.agent_id)

        # Index by capabilities
        for capability in agent.capabilities:
            if capability not in self.agents_by_capability:
                self.agents_by_capability[capability] = []
            self.agents_by_capability[capability].append(agent.agent_id)

        logger.info(f"📝 Registered agent {agent.agent_id} of type {agent.agent_type}")

    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            agent = self.agents[agent_id]

            # Remove from type index
            if agent.agent_type in self.agents_by_type:
                self.agents_by_type[agent.agent_type].remove(agent_id)

            # Remove from capability index
            for capability in agent.capabilities:
                if capability in self.agents_by_capability:
                    self.agents_by_capability[capability].remove(agent_id)

            del self.agents[agent_id]
            logger.info(f"📝 Unregistered agent {agent_id}")

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)

    def get_agents_by_type(self, agent_type: AgentType) -> List[BaseAgent]:
        """Get all agents of a specific type"""
        agent_ids = self.agents_by_type.get(agent_type, [])
        return [self.agents[agent_id] for agent_id in agent_ids if agent_id in self.agents]

    def get_agents_by_capability(self, capability: str) -> List[BaseAgent]:
        """Get all agents with a specific capability"""
        agent_ids = self.agents_by_capability.get(capability, [])
        return [self.agents[agent_id] for agent_id in agent_ids if agent_id in self.agents]

    def get_active_agents(self) -> List[BaseAgent]:
        """Get all active agents"""
        return [agent for agent in self.agents.values() if agent.is_active]

    def get_all_statuses(self) -> List[AgentStatusReport]:
        """Get status of all agents"""
        return [agent.get_status() for agent in self.agents.values()]
