import typer
from . import __version__
from .contracts import ModelResponse, ToolCall

app = typer.Typer(help="VulnForge research framework")

@app.callback()
def main() -> None:
    """VulnForge CLI."""

@app.command()
def doctor() -> None:
    response = ModelResponse(text="contract OK", tool_calls=[ToolCall(id="demo-1", name="inspect", arguments={"path": "/health"})])
    typer.echo(f"VulnForge {__version__}: {response.text}; {len(response.tool_calls)} typed tool call(s)")

if __name__ == "__main__":
    app()
