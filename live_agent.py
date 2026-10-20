
"""Live Qwen -> VulnForge Agent -> Tool -> Qwen test."""

import asyncio
import json

from vulnforge.agent.engine import ResearchAgent
from vulnforge.providers.ollama_provider import OllamaProvider
from vulnforge.tools.gateway import demo_gateway


async def main():
    print("=" * 55)
    print("VULNFORGE - LIVE OLLAMA AGENT TEST")
    print("=" * 55)

    provider = OllamaProvider(
        model="qwen2.5-coder:7b"
    )

    gateway = demo_gateway()

    agent = ResearchAgent(
        provider=provider,
        gateway=gateway,
        max_rounds=5,
        max_tool_calls=3,
    )

    prompt = (
        "You are investigating an authorized synthetic "
        "demo application. "
        "You have an inspect tool available. "
        "Call the inspect tool with path '/health' "
        "to obtain an observation. "
        "Do not invent the result. "
        "After receiving the tool result, summarize "
        "the observed application health status. "
        "Do not call any additional tools."
    )

    print("\nStarting local model investigation...\n")

    run = await agent.run(prompt)

    print("Run status:", run.status)

    print("\nExecution trace:")

    successful_inspections = 0

    for index, step in enumerate(run.steps, start=1):
        print(f"\nStep {index}: {step['type'].upper()}")

        if step["type"] == "model":
            print("Model text:", step.get("text"))

            for call in step.get("tool_calls", []):
                print(
                    "Requested tool:",
                    call["name"]
                )
                print(
                    "Arguments:",
                    json.dumps(call["arguments"])
                )

        elif step["type"] == "tool":
            print("Tool:", step["name"])
            print(
                "Observation:",
                json.dumps(
                    step["observation"],
                    indent=2
                )
            )

            observation = step["observation"]

            if (
                step["name"] == "inspect"
                and observation.get("ok") is True
                and observation.get("result", {}).get(
                    "path"
                ) == "/health"
            ):
                successful_inspections += 1

    print("\n" + "=" * 55)
    print("FINAL RESULT")
    print("=" * 55)

    print("Status:", run.status)
    print("Input tokens:", run.input_tokens)
    print("Output tokens:", run.output_tokens)
    print("Final answer:", run.answer)

    if (
        successful_inspections >= 1
        and run.status == "completed"
        and run.answer
    ):
        print(
            "\nPASS: Live agent executed a permitted "
            "tool and completed."
        )
    else:
        print(
            "\nINCOMPLETE: Review the execution trace."
        )


if __name__ == "__main__":
    asyncio.run(main())
