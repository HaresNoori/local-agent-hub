from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hub.mcp_server import mcp

mcp.run(transport="stdio")
