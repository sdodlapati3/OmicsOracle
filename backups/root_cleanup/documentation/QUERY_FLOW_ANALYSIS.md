# OmicsOracle Query Flow Analysis & Consolidation Plan

## 🔍 Complete Query Process Flow (Start.sh → Results)

### 📋 Current Architecture Overview

Based on comprehensive analysis, here's the complete flow from server startup to frontend results:

### 🚀 1. Server Startup Flow (`start.sh`)

```bash
start.sh
├── Validates environment (NCBI_EMAIL, OPENAI_API_KEY)
├── Starts Backend: uvicorn src.omics_oracle.presentation.web.main:app --port 8000
└── Starts Frontend: uvicorn interfaces.futuristic_enhanced.main:app --port 8001
```

### 🏗️ 2. Backend Initialization (`src/omics_oracle/presentation/web/main.py`)

```python
create_app() → FastAPI app
├── Setup CORS middleware
├── setup_middleware() → Custom middleware
├── setup_dependencies() → Dependency injection
├── setup_routes() → API route registration
└── setup_websockets() → WebSocket endpoints
```

**Routes Registered:**
- `/health` → Health checks
- `/api/v1/search` → Legacy search API
- `/api/v1/analysis` → Analysis endpoints
- `/api/v2/*` → Advanced search with caching/microservices
- `/docs` → API documentation

### 🎨 3. Frontend Initialization (`interfaces/futuristic_enhanced/main.py`)

```python
startup_event() → Initialize OmicsOracle Pipeline
├── Set NCBI_EMAIL environment variable
├── Create Config() object
├── Initialize UnifiedGEOClient(config)
├── Initialize PromptInterpreter, BiomedicalNER, SynonymMapper
├── Initialize SummarizationService(config)
└── Store pipeline in app.state.pipeline
```

### 🔄 4. Query Processing Flow

#### A. Frontend API Request (`/api/search`)
```
User Query → SearchRequest → search_datasets()
├── Log search to frontend via WebSocket
├── Validate pipeline availability
├── Call process_search_query(query, max_results)
└── Return SearchResponse with results
```

#### B. Core Query Processing (`process_search_query()`)
```python
process_search_query(query, max_results)
├── Check pipeline availability
├── Try enhanced_query_handler (if available)
│   ├── perform_multi_strategy_search()
│   ├── Get components (disease, tissue, organism, data_type)
│   └── Create alternative queries if needed
├── Fallback: pipeline.process_query() [ASYNC]
├── Extract geo_ids and metadata from result
├── Process each dataset:
│   ├── Get metadata for GEO ID
│   ├── Clean organism, platform, relevance_score
│   ├── Format publication date
│   ├── Generate AI summary via ai_summary_manager
│   └── Create dataset_info dict
├── Sort by data quality (title, summary, relevance)
└── Return formatted results
```

#### C. Core Pipeline Processing (`src/omics_oracle/pipeline/pipeline.py`)
```python
OmicsOracle.process_query(query, max_results)
├── Parse query via PromptInterpreter
├── Extract biomedical entities via BiomedicalNER
├── Map synonyms via EnhancedBiologicalSynonymMapper
├── Search GEO via UnifiedGEOClient.search_geo_series()
├── Retrieve metadata via UnifiedGEOClient.get_geo_metadata()
├── Generate AI summaries via SummarizationService
└── Return QueryResult with geo_ids, metadata, ai_summaries
```

#### D. GEO Data Retrieval (`src/omics_oracle/geo_tools/geo_client.py`)
```python
UnifiedGEOClient.search_geo_series(query)
├── Setup NCBI direct client with rate limiting
├── Call NCBI E-utilities esearch API
├── Parse XML response for GEO IDs
├── Convert NCBI IDs to GSE format
└── Return geo_ids list

UnifiedGEOClient.get_geo_metadata(geo_id)
├── **CACHE REMOVED** - Always fetch fresh
├── Call GEOparse.get_GEO() for metadata parsing
├── Extract title, summary, organism, platform, samples
├── **CACHE REMOVED** - No storage, return fresh data
└── Return metadata dict
```

#### E. AI Summary Generation (`src/omics_oracle/services/summarizer.py`)
```python
SummarizationService.summarize_dataset(metadata, query_context)
├── **CACHE REMOVED** - Always generate fresh
├── Prepare/clean metadata for LLM processing
├── Generate summary components based on type:
│   ├── _generate_overview() → OpenAI GPT-4o-mini
│   ├── _generate_methodology_summary() → Technical details
│   ├── _generate_significance_summary() → Research impact
│   └── _generate_technical_summary() → Platform/samples info
├── **CACHE REMOVED** - No storage, return fresh summaries
└── Return summary dict or None
```

---

## 📊 Core Files & Folders Involved in Query Process

### 🎯 **Essential Query Processing Files** (Keep & Optimize)

#### Startup & Configuration
- `start.sh` - Universal startup script ✅
- `src/omics_oracle/core/config.py` - Configuration management ✅
- `.env` - Environment variables ✅

#### Backend API (Clean Architecture)
- `src/omics_oracle/presentation/web/main.py` - Backend FastAPI app ✅
- `src/omics_oracle/presentation/web/routes/` - API endpoints ✅
  - `health.py` - Health checks ✅
  - `search.py` - Core search API ✅
  - `v2.py` - Advanced features ✅

#### Frontend Interface
- `interfaces/futuristic_enhanced/main.py` - Frontend FastAPI app ✅
- `interfaces/futuristic_enhanced/static/` - Frontend assets ✅

#### Core Pipeline
- `src/omics_oracle/pipeline/pipeline.py` - Main OmicsOracle class ✅
- `src/omics_oracle/nlp/prompt_interpreter.py` - Query parsing ✅
- `src/omics_oracle/nlp/biomedical_ner.py` - Entity extraction ✅

#### GEO Data Access
- `src/omics_oracle/geo_tools/geo_client.py` - **PRIMARY** UnifiedGEOClient ✅

#### AI Services
- `src/omics_oracle/services/summarizer.py` - AI summary generation ✅
- `src/omics_oracle/services/ai_summary_manager.py` - Centralized AI management ✅

### ⚠️ **Redundant/Consolidation Candidates**

#### Duplicate Main Files
- `src/omics_oracle/api/main.py` - **REDUNDANT** (151 lines) ❌
- `src/omics_oracle/web/main.py` - **REDUNDANT** (174 lines) ❌
- `src/omics_oracle/cli/main.py` - **CLI ONLY** (keep for command-line) ✅

#### Duplicate GEO Clients
- `src/omics_oracle/geo_tools/client.py` - **ALREADY REMOVED** ✅
- `src/omics_oracle/infrastructure/external_apis/geo_client.py` - **MIGRATE FEATURES** ⚠️

#### Multiple Interface Versions
- `interfaces/futuristic/` - **REDUNDANT** old version ❌
- `interfaces/futuristic_enhanced/` - **KEEP** current version ✅

#### Clean Architecture Complexity
- `src/omics_oracle/infrastructure/` - **PARTIAL USE** - Some useful, some redundant ⚠️
- `src/omics_oracle/application/` - **PARTIAL USE** ⚠️
- `src/omics_oracle/domain/` - **PARTIAL USE** ⚠️

---

## 🧹 Consolidation Plan

### Phase 1: Remove Clear Redundancies

#### Delete Redundant Main Files
```bash
# These are NOT used by start.sh
rm src/omics_oracle/api/main.py           # 151 lines saved
rm src/omics_oracle/web/main.py           # 174 lines saved
rm -rf interfaces/futuristic/             # ~800 lines saved
```

#### Delete Unused Services
```bash
# After verifying no active usage
rm -rf src/omics_oracle/agents/           # If not used in query flow
rm -rf src/omics_oracle/integrations/     # If redundant
```

### Phase 2: Consolidate GEO Clients

#### Enhance Primary Client
```python
# src/omics_oracle/geo_tools/geo_client.py (PRIMARY)
# Add best features from infrastructure/external_apis/geo_client.py:
# - Health check methods
# - Advanced XML parsing
# - Modern error handling
```

#### Remove Infrastructure Client
```bash
rm src/omics_oracle/infrastructure/external_apis/geo_client.py
# Update dependencies to use UnifiedGEOClient
```

### Phase 3: Clean Architecture Optimization

#### Keep Essential Clean Architecture
```bash
# Keep these (actively used):
src/omics_oracle/presentation/web/        # Current backend
src/omics_oracle/infrastructure/configuration/
src/omics_oracle/infrastructure/dependencies/
```

#### Evaluate/Consolidate
```bash
# Analyze usage and consolidate:
src/omics_oracle/application/             # Use cases - keep essential
src/omics_oracle/domain/                  # Domain models - keep essential
src/omics_oracle/infrastructure/caching/ # Keep for debugging (no serving)
```

### Phase 4: Service Consolidation

#### AI Services
```python
# Already consolidated into:
# - summarizer.py (core service)
# - ai_summary_manager.py (centralized manager)
```

#### Search Services
```python
# Consolidate multiple search implementations into:
# - pipeline.py (core pipeline)
# - Enhanced query handler (if used)
```

---

## 📈 Consolidation Benefits

### 🎯 Code Reduction
- **Remove ~1,500+ redundant lines**
- **Eliminate 3+ duplicate main.py files**
- **Remove 1 entire interface directory**
- **Consolidate 2 GEO client implementations**

### 🧹 Simplified Architecture
- **Single source of truth for each component**
- **Clear startup process (start.sh → 2 main.py files)**
- **Unified API structure**
- **Single GEO client implementation**

### 🚀 Improved Maintainability
- **Fewer files to maintain**
- **Clear query processing flow**
- **No duplicate functionality**
- **Consistent patterns throughout**

### ⚡ Better Performance
- **Reduced import overhead**
- **Cleaner dependency tree**
- **Optimized startup time**
- **Fresh data guaranteed (cache removed)**

---

## 🎯 Final Target Architecture

### Core Query Processing Stack
```
start.sh
├── Backend: src/omics_oracle/presentation/web/main.py
│   ├── Routes: src/omics_oracle/presentation/web/routes/
│   ├── Pipeline: src/omics_oracle/pipeline/pipeline.py
│   ├── GEO Client: src/omics_oracle/geo_tools/geo_client.py
│   ├── AI Services: src/omics_oracle/services/
│   └── NLP: src/omics_oracle/nlp/
└── Frontend: interfaces/futuristic_enhanced/main.py
    ├── Static: interfaces/futuristic_enhanced/static/
    └── Search API: /api/search → process_search_query()
```

### Eliminated Redundancy
- ❌ Multiple main.py files
- ❌ Duplicate GEO clients
- ❌ Old interface versions
- ❌ Cache serving (kept for debugging only)
- ❌ Unused service directories

**Result**: Clean, lean, fast, and accurate OmicsOracle with ~25% less code and 100% fresh results.
