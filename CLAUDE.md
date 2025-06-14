# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a dual-mode MCP (Model Context Protocol) server for medical device threat extraction and CVSS scoring. It operates both as:
1. **MCP Server**: For Claude Desktop integration via stdio protocol
2. **HTTP API Server**: Standalone FastAPI server with Firebase authentication

The system specializes in analyzing Japanese medical device security threats and extracting standardized CVSS v3.1 scores and security features.

## Core Architecture

### Dual Server Architecture
- `mcp_threat_extraction/server.py`: Contains both MCP server (`Server("threat-extraction")`) and FastAPI app (`app`) definitions
- The MCP server uses stdio protocol for Claude Desktop integration
- The FastAPI server provides HTTP endpoints with Firebase authentication
- Both servers share the same core tool functions (`call_tool()`) for threat analysis

### Authentication System
- `mcp_threat_extraction/auth.py`: Firebase Admin SDK integration
- Supports 3 configuration methods: file path, JSON string, or individual environment variables
- `DISABLE_AUTH=true` bypasses authentication for development
- All HTTP endpoints except `/`, `/tools`, and `/auth/status` require authentication

### Core Analysis Engine
- `threat_extraction.py`: Main CVSS calculation logic using LangChain + OpenAI/Anthropic
- `semantic_normalizer_optimized.py`: SentenceTransformer-based feature normalization
- `cvss_logic.py`: CVSS scoring algorithms
- `threat_data.py`: Medical device-specific threat categories and data types

## Development Commands

### Environment Setup
```bash
# Install dependencies
uv sync

# Setup environment variables
cp .env.example .env
# Edit .env with your API keys and Firebase config
```

### Running the Servers

#### MCP Server (Claude Desktop)
```bash
# Test MCP server directly
python mcp_threat_extraction/server.py

# Add to Claude Desktop config:
# "command": "uv", "args": ["run", "python", "/path/to/server.py"]
```

#### HTTP Server
```bash
# Development mode
uvicorn mcp_threat_extraction.server:app --reload

# Production mode
uvicorn mcp_threat_extraction.server:app --host 0.0.0.0 --port 8000 --workers 4

# With authentication disabled
DISABLE_AUTH=true uvicorn mcp_threat_extraction.server:app --reload
```

### Testing
```bash
# Test MCP functionality
python test_server.py

# Test semantic normalizer
python test_normalizer.py

# Test HTTP API (requires running server)
python test_http_client.py

# Test with authentication
python test_http_client.py --token YOUR_FIREBASE_ID_TOKEN
```

### Docker Deployment
```bash
# Build and run with Docker Compose (uses CPU-only PyTorch)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

**Note**: Docker builds use CPU-only PyTorch via uv's `extra-index-url` configuration in `pyproject.toml` to avoid NVIDIA/CUDA dependencies.

## Environment Variables

### Required
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`: For LLM-based CVSS analysis

### Firebase Authentication (for HTTP server)
Choose one configuration method:
1. **File path**: `FIREBASE_SERVICE_ACCOUNT_KEY=/path/to/key.json`
2. **JSON string**: `FIREBASE_SERVICE_ACCOUNT_KEY='{"type":"service_account",...}'`
3. **Individual vars**: `FIREBASE_PROJECT_ID`, `FIREBASE_PRIVATE_KEY`, `FIREBASE_CLIENT_EMAIL`

### Optional
- `DISABLE_AUTH=true`: Disable authentication for development
- `ALLOWED_ORIGINS=*`: CORS configuration
- `USE_SMALL_MODEL=true`: Use smaller SentenceTransformer model for memory-constrained environments (e.g., Render free tier)

## Key Architectural Decisions

### Lazy Loading Pattern
- Semantic normalizer (`OptimizedSemanticNormalizer`) uses lazy initialization via `get_semantic_normalizer()`
- Heavy ML models are only loaded when first accessed
- Improves startup time and memory usage

### Shared Tool Functions
- Core tool logic in `call_tool()` function is shared between MCP and HTTP servers
- HTTP endpoints wrap MCP tools and add authentication + user tracking
- Response format maintained between both protocols

### Authentication Integration
- Firebase authentication is HTTP-server specific
- MCP server remains unauthenticated for Claude Desktop compatibility
- `lifespan` context manager handles Firebase initialization at startup

### Error Handling Strategy
- Authentication errors return 401 with clear messages
- Firebase initialization failures fall back to disabled auth mode in development
- Tool execution errors are captured and returned as structured JSON responses

## Testing Strategy

### Integration Testing
- `test_http_client.py` provides comprehensive HTTP API testing
- Supports both authenticated and unauthenticated testing modes
- Tests all four core tools: extract_cvss, extract_cvss_batch, extract_data_types, normalize_features

### MCP Testing
- `test_server.py` tests the MCP server functionality directly
- `test_normalizer.py` tests semantic normalization in isolation

## Code Quality Tools

Run linting and type checking if available:
```bash
# Check for available linting tools
npm run lint 2>/dev/null || ruff check . 2>/dev/null || echo "No linter found"
npm run typecheck 2>/dev/null || mypy . 2>/dev/null || echo "No type checker found"
```