"""
Minimal FastMCP server used as a test fixture.

Exposes 4 tools and 1 resource so every test module has realistic
capability data to operate on. Import TEST_SERVER or call
get_test_server() to obtain the FastMCP instance.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mcpsafe-test-server")


@mcp.tool()
def echo(message: str) -> str:
    """Echo the message back unchanged."""
    return message


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def get_file(path: str) -> str:
    """Read a file by path."""
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def multiply(x: float, y: float) -> float:
    """Multiply two numbers."""
    return x * y


@mcp.resource("config://settings")
def get_settings() -> str:
    """Application configuration."""
    return '{"version": "1.0.0", "debug": false}'


TEST_SERVER = mcp


def get_test_server() -> FastMCP:
    """Return the shared FastMCP test server instance."""
    return TEST_SERVER
 
if __name__ == "__main__": 
    mcp.run(transport="stdio") 
