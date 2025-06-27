# OmicsOracle 🧬🔮

**AI-Powered Genomics Data Summary Agent**

OmicsOracle is an intelligent data summary agent designed to process, analyze, and summarize genomics and omics data, with a focus on GEO (Gene Expression Omnibus) metadata summarization. The system provides AI-driven insights, automated data processing, and comprehensive summaries for researchers and bioinformaticians.

## 🚀 Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd OmicsOracle

# Set up virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-web.txt
pip install -r requirements-dev.txt

# Set up environment variables
cp .env.example .env.local

# Start the application (full-stack)
./start.sh

# Or start specific components:
./start.sh --backend-only    # API server only
./start.sh --frontend-only   # Web interface only
./start.sh --dev            # Development mode with hot reload
```

### 🌐 Access Points

After starting:
- **Web Interface**: http://localhost:8001 (futuristic enhanced UI)
- **API Server**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

For detailed startup options, see [STARTUP_GUIDE.md](STARTUP_GUIDE.md)

## 📋 Features

- **GEO Metadata Parser**: Intelligent parsing of GEO database entries
- **AI-Powered Summarization**: Automated generation of dataset summaries
- **Multi-format Support**: Support for various omics data formats
- **Pattern Recognition**: Identification of trends and patterns in metadata
- **Search & Discovery**: Advanced search capabilities across datasets
- **Batch Processing**: Efficient processing of multiple datasets
- **Real-time Monitoring**: Live updates on processing status
- **API Integration**: RESTful API for programmatic access

## 🧪 Testing and Validation Framework

OmicsOracle includes a comprehensive testing and validation framework that ensures the system functions correctly at each stage:

- **[Event Flow Visualization](/docs/EVENT_FLOW_README.md)**: Visual representation of system event flow and test coverage
- **[Event Flow and Validation Map](/docs/EVENT_FLOW_VALIDATION_MAP.md)**: Detailed mapping of events to test files
- **[Event Flow Charts](/docs/EVENT_FLOW_CHART.md)**: Simplified Mermaid diagrams of the system flow
- **[Search System Technical Documentation](/docs/SEARCH_SYSTEM_TECHNICAL_DOCUMENTATION.md)**: Architecture and implementation details of the search system

### Comprehensive Testing Suite

The project includes a robust testing framework with several specialized tools:

```bash
# Run all comprehensive tests at once
./run_all_tests.sh

# Run specific test components
python test_endpoints_comprehensive.py  # Test all API endpoints
python validate_enhanced_query_handler.py  # Validate the enhanced query handling
python validate_advanced_search.py  # Validate advanced search features
python search_performance_monitor.py  # Monitor search system performance
python search_error_analyzer.py --logs server.log  # Analyze search system errors
```

### Query Tracing and Validation

OmicsOracle includes a sophisticated query tracing system that monitors and reports on query processing:

- **Component Extraction**: Identifies diseases, tissues, organisms, and data types in queries
- **Synonym Expansion**: Expands biomedical terms with common synonyms
- **Multi-Strategy Search**: Falls back to alternative queries when needed
- **Trace Reports**: Generates detailed reports of query processing in Markdown format
- **Performance Monitoring**: Tracks query execution time and resource usage
- **Error Analysis**: Identifies patterns in errors to guide improvements

### Advanced Search Features

The system includes advanced search capabilities for improved result quality:

- **Semantic Ranking**: Ranks results based on biomedical relevance to the query
- **Result Clustering**: Groups results into meaningful categories
- **Query Reformulation**: Suggests alternative query formulations to users
- **Context-Aware Filtering**: Filters results based on biomedical context

```bash
# Test the advanced search features
python integrate_search_enhancer.py --demo

# Run the advanced search feature validation
python validate_advanced_search.py
```

This framework provides complete observability from server startup to frontend display, with appropriate tests for each component.

## 🛠️ Technology Stack

- **Backend**: Python 3.11+, FastAPI, LangChain
- **AI/ML**: OpenAI API, scikit-learn, BioPython
- **Databases**: MongoDB, ChromaDB, Redis
- **Frontend**: React.js / Streamlit
- **DevOps**: Docker, Kubernetes, GitHub Actions

## 📁 Project Structure

```
OmicsOracle/
├── src/omics_oracle/          # Main application code
├── frontend/                  # Web interface
├── tests/                     # Test suites
├── docs/                      # Documentation
├── data/                      # Data files and examples
├── notebooks/                 # Jupyter notebooks
├── scripts/                   # Utility scripts
├── config/                    # Configuration files
└── deployment/                # Deployment configurations
```

## 📚 Documentation

OmicsOracle's documentation is organized in the `docs/` directory:

- **[Search System Technical Documentation](/docs/SEARCH_SYSTEM_TECHNICAL_DOCUMENTATION.md)**: Comprehensive technical details of the query handling and search system
- **[Search System Case Study](/docs/SEARCH_SYSTEM_CASE_STUDY.md)**: Real-world examples demonstrating the effectiveness of the search system
- **[Documentation Index](/docs/README.md)**: Complete listing of all available documentation
- **[Event Flow Visualization](/docs/EVENT_FLOW_README.md)**: Visual representation of system event flow and test coverage

For API documentation, visit the interactive API docs when the server is running:
- http://localhost:8000/docs

## 🧪 Development

### Prerequisites

- Python 3.11 or higher
- Node.js 18+ (for frontend)
- Docker and Docker Compose
- Git

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run tests
pytest

# Start development server (full-stack with hot reload)
./start.sh --dev

# Or start individual components:
./start.sh --backend-only     # Backend API only
./start.sh --frontend-only    # Frontend UI only
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/omics_oracle

# Run specific test suite
pytest tests/unit/
pytest tests/integration/
```

## 🔧 Configuration

Copy `.env.example` to `.env` and configure the following:

```bash
# API Configuration
OPENAI_API_KEY=your_openai_api_key
MONGODB_URL=mongodb://localhost:27017
REDIS_URL=redis://localhost:6379

# Application Settings
DEBUG=true
LOG_LEVEL=INFO
MAX_WORKERS=4
```

## 🐳 Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run in production mode
docker-compose -f docker-compose.prod.yml up
```

## 📊 Current Status

**Development Phase**: Foundation & Infrastructure
**Version**: 0.1.0-alpha
**Last Updated**: June 22, 2025

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for detailed progress and roadmap.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- GEO Database team for providing comprehensive genomics data
- BioPython community for excellent bioinformatics tools
- OpenAI for advanced language model capabilities
- The broader genomics and bioinformatics research community

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/OmicsOracle/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/OmicsOracle/discussions)

---

**Built with ❤️ for the genomics research community**
