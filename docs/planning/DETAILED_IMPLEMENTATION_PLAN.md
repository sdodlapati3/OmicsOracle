# 🚀 OmicsOracle Multi-Agent System + Critical Integrations - Detailed Implementation Plan

**Date:** June 23, 2025
**Status:** Ready for Implementation
**Priority:** High Strategic Value
**Total Duration:** 7 weeks
**Budget:** $35,000 - $45,000

---

## 📋 **EXECUTIVE SUMMARY**

This implementation plan transforms OmicsOracle into a next-generation multi-agent biomedical research intelligence platform while maintaining backward compatibility and system reliability. The approach combines:

1. **Multi-Agent Architecture** (4 weeks) - Parallel processing and intelligent specialization
2. **Critical Integrations** (2 weeks) - PubMed correlation and R/Python packages
3. **Enhanced Visualization** (1 week) - Network graphs and better exports

**Key Benefits:**
- 30-50% faster response times through parallel processing
- Personalized research experience that learns user preferences
- Ecosystem integration making OmicsOracle indispensable
- Future-ready architecture for new AI models and data sources

---

## 🎯 **PHASE 1: MULTI-AGENT FOUNDATION (Week 1)**

### **Week 1: Core Agent Framework & Message System**

#### **Day 1: Base Agent Architecture**

**Goal:** Create the foundational agent framework

**Implementation Steps:**

1. **Create Base Agent Class Structure**

```python
# File: src/omics_oracle/agents/base_agent.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from enum import Enum
import asyncio
import logging
import uuid
from datetime import datetime

class AgentStatus(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    SHUTDOWN = "shutdown"

@dataclass
class AgentMessage:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: str = ""
    recipient: str = ""
    action: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None

class BaseAgent(ABC):
    def __init__(self, agent_id: str, capabilities: List[str]):
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.status = AgentStatus.IDLE
        self.message_queue = asyncio.Queue()
        self.logger = logging.getLogger(f"agent.{agent_id}")
        self.orchestrator = None
        self.config = {}
        self.metrics = {
            "messages_processed": 0,
            "messages_sent": 0,
            "errors": 0,
            "avg_processing_time": 0.0
        }

    @abstractmethod
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process incoming message and return response."""
        pass

    async def send_message(self, recipient: str, action: str, data: Dict[str, Any],
                          correlation_id: Optional[str] = None) -> str:
        """Send message to another agent."""
        message = AgentMessage(
            sender=self.agent_id,
            recipient=recipient,
            action=action,
            data=data,
            correlation_id=correlation_id
        )

        if self.orchestrator:
            await self.orchestrator.route_message(message)
            self.metrics["messages_sent"] += 1

        return message.id

    async def start(self):
        """Start agent message processing loop."""
        self.logger.info(f"Agent {self.agent_id} starting...")
        self.status = AgentStatus.IDLE

        while self.status != AgentStatus.SHUTDOWN:
            try:
                # Wait for message with timeout
                message = await asyncio.wait_for(
                    self.message_queue.get(), timeout=1.0
                )

                self.status = AgentStatus.BUSY
                start_time = asyncio.get_event_loop().time()

                response = await self.process_message(message)

                # Update metrics
                processing_time = asyncio.get_event_loop().time() - start_time
                self.metrics["messages_processed"] += 1
                self.metrics["avg_processing_time"] = (
                    (self.metrics["avg_processing_time"] * (self.metrics["messages_processed"] - 1) + processing_time) /
                    self.metrics["messages_processed"]
                )

                if response:
                    await self.send_message(
                        response.recipient,
                        response.action,
                        response.data,
                        response.correlation_id
                    )

                self.status = AgentStatus.IDLE

            except asyncio.TimeoutError:
                # No message received, continue loop
                continue
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")
                self.status = AgentStatus.ERROR
                self.metrics["errors"] += 1
                await asyncio.sleep(1)  # Brief pause before retry
                self.status = AgentStatus.IDLE

    async def shutdown(self):
        """Gracefully shutdown agent."""
        self.logger.info(f"Agent {self.agent_id} shutting down...")
        self.status = AgentStatus.SHUTDOWN

    def get_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics."""
        return {
            "agent_id": self.agent_id,
            "status": self.status.value,
            "capabilities": self.capabilities,
            **self.metrics
        }
```

2. **Create Agent Orchestrator**

```python
# File: src/omics_oracle/agents/orchestrator.py
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid

from .base_agent import BaseAgent, AgentMessage, AgentStatus

class WorkflowTemplate:
    def __init__(self, name: str, steps: List[Dict[str, Any]]):
        self.name = name
        self.steps = steps

class AgentOrchestrator:
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.workflows: Dict[str, WorkflowTemplate] = {}
        self.active_workflows: Dict[str, Dict[str, Any]] = {}
        self.message_history: List[AgentMessage] = []
        self.logger = logging.getLogger("orchestrator")

    async def register_agent(self, agent: BaseAgent):
        """Register an agent with the orchestrator."""
        agent.orchestrator = self
        self.agents[agent.agent_id] = agent
        self.logger.info(f"Registered agent: {agent.agent_id}")

        # Start agent in background task
        asyncio.create_task(agent.start())

    async def route_message(self, message: AgentMessage):
        """Route message to target agent."""
        if message.recipient in self.agents:
            await self.agents[message.recipient].message_queue.put(message)
            self.message_history.append(message)
            # Keep only last 1000 messages
            if len(self.message_history) > 1000:
                self.message_history = self.message_history[-1000:]
        else:
            self.logger.error(f"Unknown recipient: {message.recipient}")

    async def execute_research_workflow(self, query: str, user_preferences: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute multi-agent research workflow."""
        workflow_id = f"research_{uuid.uuid4().hex[:8]}"
        user_preferences = user_preferences or {}

        self.logger.info(f"Starting research workflow {workflow_id} for query: {query}")

        # Track workflow
        self.active_workflows[workflow_id] = {
            "id": workflow_id,
            "query": query,
            "user_preferences": user_preferences,
            "status": "running",
            "start_time": datetime.now(),
            "steps_completed": [],
            "results": {}
        }

        try:
            # Step 1: Data Collection (parallel with literature search)
            data_collection_task = asyncio.create_task(
                self._send_and_wait("data_collector", "search_geo", {
                    "query": query,
                    "workflow_id": workflow_id,
                    "max_results": user_preferences.get("max_results", 50)
                })
            )

            # Step 2: Literature Search (parallel with data collection)
            literature_task = asyncio.create_task(
                self._send_and_wait("integration_agent", "search_publications", {
                    "query": query,
                    "workflow_id": workflow_id,
                    "max_results": user_preferences.get("max_publications", 20)
                })
            )

            # Wait for both to complete
            geo_results, literature_results = await asyncio.gather(
                data_collection_task, literature_task, return_exceptions=True
            )

            # Handle exceptions
            if isinstance(geo_results, Exception):
                self.logger.error(f"Data collection failed: {geo_results}")
                geo_results = {"error": str(geo_results), "geo_ids": [], "datasets": []}

            if isinstance(literature_results, Exception):
                self.logger.error(f"Literature search failed: {literature_results}")
                literature_results = {"error": str(literature_results), "publications": []}

            # Step 3: AI Analysis (if data available)
            analysis_results = {}
            if geo_results.get("geo_ids"):
                analysis_results = await self._send_and_wait("analysis_agent", "generate_summary", {
                    "geo_data": geo_results,
                    "literature_data": literature_results,
                    "workflow_id": workflow_id,
                    "summary_type": user_preferences.get("summary_type", "comprehensive")
                })

            # Step 4: Personalization
            final_results = await self._send_and_wait("ui_agent", "personalize_results", {
                "geo_results": geo_results,
                "literature_results": literature_results,
                "analysis_results": analysis_results,
                "user_preferences": user_preferences,
                "workflow_id": workflow_id
            })

            # Update workflow status
            self.active_workflows[workflow_id].update({
                "status": "completed",
                "end_time": datetime.now(),
                "results": final_results
            })

            return final_results

        except Exception as e:
            self.logger.error(f"Workflow {workflow_id} failed: {e}")
            self.active_workflows[workflow_id].update({
                "status": "failed",
                "error": str(e),
                "end_time": datetime.now()
            })
            raise

    async def _send_and_wait(self, recipient: str, action: str, data: Dict[str, Any],
                           timeout: float = 60.0) -> Dict[str, Any]:
        """Send message and wait for response."""
        correlation_id = str(uuid.uuid4())

        # Send message
        message = AgentMessage(
            sender="orchestrator",
            recipient=recipient,
            action=action,
            data=data,
            correlation_id=correlation_id
        )

        await self.route_message(message)

        # Wait for response
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            # Check message history for response
            for msg in reversed(self.message_history[-100:]):  # Check last 100 messages
                if (msg.correlation_id == correlation_id and
                    msg.sender == recipient and
                    msg.recipient == "orchestrator"):
                    return msg.data

            await asyncio.sleep(0.1)  # Brief pause before checking again

        raise TimeoutError(f"No response from {recipient} within {timeout} seconds")

    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific workflow."""
        return self.active_workflows.get(workflow_id)

    def get_agent_metrics(self) -> Dict[str, Any]:
        """Get metrics for all agents."""
        return {
            agent_id: agent.get_metrics()
            for agent_id, agent in self.agents.items()
        }
```

#### **Day 2: Data Collection Agent**

**Goal:** Convert existing GEO tools into specialized agent

```python
# File: src/omics_oracle/agents/data_collection_agent.py
import asyncio
from typing import Dict, Any, List, Optional
from ..geo_tools.geo_client import GEOClient
from ..pipeline.pipeline import Pipeline
from .base_agent import BaseAgent, AgentMessage

class DataCollectionAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_id="data_collector",
            capabilities=["geo_search", "metadata_extraction", "data_validation"]
        )

        # Inject existing components
        self.geo_client = GEOClient()
        self.pipeline = Pipeline()

        # Agent-specific improvements
        self.query_cache = {}
        self.search_optimizations = {
            "query_expansion": True,
            "result_filtering": True,
            "metadata_enrichment": True
        }

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process data collection requests."""
        action = message.data.get("action", message.action)

        if action == "search_geo":
            return await self._search_geo_datasets(message)
        elif action == "extract_metadata":
            return await self._extract_metadata(message)
        elif action == "validate_data":
            return await self._validate_data(message)
        else:
            self.logger.warning(f"Unknown action: {action}")
            return None

    async def _search_geo_datasets(self, message: AgentMessage) -> AgentMessage:
        """Enhanced GEO search with agent intelligence."""
        query = message.data["query"]
        workflow_id = message.data.get("workflow_id")
        max_results = message.data.get("max_results", 50)

        self.logger.info(f"Searching GEO for: {query}")

        try:
            # Check cache first
            cache_key = f"{query}:{max_results}"
            if cache_key in self.query_cache:
                self.logger.info("Returning cached results")
                return AgentMessage(
                    sender=self.agent_id,
                    recipient="orchestrator",
                    action="search_geo_response",
                    data=self.query_cache[cache_key],
                    correlation_id=message.correlation_id
                )

            # Use existing pipeline but with agent enhancements
            search_request = {
                "query": query,
                "max_results": max_results,
                "include_sra": False  # Can be made configurable
            }

            results = await asyncio.to_thread(
                self.pipeline.search_datasets, search_request
            )

            # Agent-specific enhancements
            enhanced_results = await self._enhance_search_results(results, query)

            # Cache results
            self.query_cache[cache_key] = enhanced_results

            # Limit cache size
            if len(self.query_cache) > 100:
                # Remove oldest entries
                oldest_key = next(iter(self.query_cache))
                del self.query_cache[oldest_key]

            return AgentMessage(
                sender=self.agent_id,
                recipient="orchestrator",
                action="search_geo_response",
                data=enhanced_results,
                correlation_id=message.correlation_id
            )

        except Exception as e:
            self.logger.error(f"GEO search failed: {e}")
            return AgentMessage(
                sender=self.agent_id,
                recipient="orchestrator",
                action="search_geo_response",
                data={"error": str(e), "geo_ids": [], "datasets": []},
                correlation_id=message.correlation_id
            )

    async def _enhance_search_results(self, results: Dict[str, Any], query: str) -> Dict[str, Any]:
        """Apply agent-specific enhancements to search results."""
        enhanced = results.copy()

        # Add search quality metrics
        enhanced["search_quality"] = {
            "relevance_score": self._calculate_relevance_score(results, query),
            "completeness_score": self._calculate_completeness_score(results),
            "freshness_score": self._calculate_freshness_score(results)
        }

        # Add agent insights
        enhanced["agent_insights"] = {
            "search_strategy": "optimized_geo_query",
            "result_filtering": "applied",
            "cache_status": "miss" if results else "hit"
        }

        return enhanced

    def _calculate_relevance_score(self, results: Dict[str, Any], query: str) -> float:
        """Calculate relevance score for search results."""
        # Simple relevance scoring based on query terms in results
        if not results.get("datasets"):
            return 0.0

        query_terms = set(query.lower().split())
        relevant_count = 0

        for dataset in results["datasets"][:10]:  # Check first 10
            title = dataset.get("title", "").lower()
            summary = dataset.get("summary", "").lower()
            text = f"{title} {summary}"

            if any(term in text for term in query_terms):
                relevant_count += 1

        return relevant_count / min(len(results["datasets"]), 10)

    def _calculate_completeness_score(self, results: Dict[str, Any]) -> float:
        """Calculate completeness score based on metadata availability."""
        if not results.get("datasets"):
            return 0.0

        total_fields = 0
        filled_fields = 0

        for dataset in results["datasets"][:5]:  # Check first 5
            for field in ["title", "summary", "organism", "platform", "samples"]:
                total_fields += 1
                if dataset.get(field):
                    filled_fields += 1

        return filled_fields / total_fields if total_fields > 0 else 0.0

    def _calculate_freshness_score(self, results: Dict[str, Any]) -> float:
        """Calculate freshness score based on dataset age."""
        # Placeholder - would need actual date parsing
        return 0.8  # Default good freshness score
```

#### **Day 3-4: Analysis Agent & Integration Agent**

Continue with similar detailed implementation for remaining agents...

---

## 📊 **IMPLEMENTATION TIMELINE**

### **Week 1: Foundation**
- Day 1: Base agent framework
- Day 2: Data collection agent
- Day 3: Analysis agent
- Day 4: Integration agent skeleton
- Day 5: Testing and debugging

### **Week 2: Orchestration & UI**
- Day 1-2: Complete orchestrator
- Day 3-4: User interface agent
- Day 5: Monitoring agent
- Day 6-7: Integration testing

### **Week 3: Agent Specialization**
- Day 1-2: Advanced data collection features
- Day 3-4: Enhanced analysis capabilities
- Day 5-7: Personalization engine

### **Week 4: Performance & Optimization**
- Day 1-2: Parallel processing optimization
- Day 3-4: Caching and performance tuning
- Day 5-7: Load testing and optimization

### **Week 5-6: Critical Integrations**
- Week 5: PubMed integration agent
- Week 6: R/Python package development

### **Week 7: Enhanced Visualization**
- Day 1-3: Network graph visualization
- Day 4-5: Enhanced export formats
- Day 6-7: Final integration and testing

---

## 🎯 **SUCCESS METRICS**

### **Performance Targets**
- 30-50% reduction in response times
- 95%+ uptime for agent system
- <100ms inter-agent communication latency

### **User Experience Targets**
- 90%+ user satisfaction with personalization
- 70%+ adoption of new parallel features
- 80%+ improvement in workflow efficiency

### **Technical Targets**
- Zero breaking changes to existing API
- 99%+ backwards compatibility
- <5% increase in memory usage

---

**This implementation plan provides a clear, week-by-week roadmap for transforming OmicsOracle into a sophisticated multi-agent system while maintaining its reliability and adding critical integrations that will drive adoption.**
