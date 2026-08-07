"""
SafeSOC — MCP Tool Registry
Typed tool definitions the investigation assistant orchestrates calls
to (SS-045), one per intent (SS-044). See mcp/tools.py for the actual
tool implementations; this module just re-exports the registry.
"""

from app.mcp.tools import MCPTool, TOOLS

__all__ = ["MCPTool", "TOOLS"]
