# VulnForge

### Autonomous Vulnerability Research & Multi-Model Security Benchmarking Framework

**An experimental offensive-security research framework for investigating how effectively different AI models can autonomously discover, investigate, and validate software vulnerabilities under controlled, reproducible conditions.**

![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Research](https://img.shields.io/badge/Focus-Offensive_AI_Security-8B5CF6?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Early_Development-F59E0B?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-macOS_%7C_Linux-333333?style=for-the-badge)
![Architecture](https://img.shields.io/badge/Architecture-Modular-0F766E?style=for-the-badge)

---

## 01. Overview

**VulnForge** is an independent research and engineering project exploring the intersection of artificial intelligence, autonomous agents, vulnerability research, and offensive cybersecurity.

The central idea is straightforward:

> Can an AI model operate as an independent security researcher—observing an unfamiliar software environment, identifying weaknesses, developing hypotheses, selecting appropriate tests, interpreting evidence, and validating vulnerabilities without relying entirely on predefined scanning signatures?

VulnForge aims to investigate this question experimentally.

Rather than functioning as a conventional vulnerability scanner or a chatbot that explains security findings, the framework is being designed around **model-directed security investigation**.

Different AI models will receive equivalent experimental conditions and independently investigate intentionally vulnerable software environments.

Their performance will be measured through observable security outcomes rather than subjective assessments of general intelligence.

The project is currently under active development. Its initial provider adapters, typed contracts, controlled agent-loop foundation, and offline tests have been implemented. Full autonomous vulnerability discovery and independent validation remain development objectives.

---

## 02. Research Motivation

### The Changing Security Landscape

Modern software is increasingly interconnected, API-driven, and dependent on complex identity, authorization, and application workflows.

At the same time, advances in large language models are creating a new class of software systems capable of planning, using tools, interpreting observations, and performing multi-step tasks.

These capabilities introduce an important question for cybersecurity research:

**What happens when the ability to investigate software vulnerabilities becomes increasingly autonomous?**

Traditional security automation is generally built around predefined rules, signatures, heuristics, and scripted workflows.

Autonomous AI systems introduce a different possibility.

A model may be capable of examining an unfamiliar application, reasoning about its behavior, proposing security hypotheses, and adapting its investigation based on observed results.

However, generating a convincing vulnerability explanation is fundamentally different from discovering a real vulnerability.

Likewise, producing a plausible proof of concept is not equivalent to demonstrating exploitability.

VulnForge is motivated by the need to evaluate these distinctions through reproducible experimentation.

### Real-World Security Implications

The growing use of AI in cybersecurity raises questions about both legitimate security research and the potential misuse of increasingly capable autonomous systems.

Examples of relevant research concerns include:

- AI-assisted vulnerability discovery in unfamiliar software.
- Automated reasoning about exposed application interfaces.
- Multi-step investigation of authentication and authorization weaknesses.
- AI-generated security test cases and proof-of-concept candidates.
- Adaptive investigation based on runtime feedback.
- The reliability of autonomous vulnerability claims.
- The possibility of increasingly scalable AI-assisted offensive operations.
- The security consequences of autonomous agents interacting with external tools and APIs.

These developments deserve rigorous empirical study.

**VulnForge does not assume that current AI models can reliably perform these tasks. Its purpose is to test what they can actually accomplish, where they fail, and how their behavior differs.**

All active security testing is restricted to isolated, intentionally vulnerable, or explicitly authorized environments.

---

## 03. Core Research Hypothesis

The primary hypothesis behind VulnForge is:

> **Given equivalent tools, environmental access, operational constraints, and evaluation criteria, different AI models will demonstrate measurable differences in their ability to autonomously discover, investigate, and independently validate software vulnerabilities.**

This hypothesis contains several important research questions.

**H1 — Autonomous Discovery**

Can an AI model identify a previously undisclosed-to-the-model vulnerability in an unfamiliar application without being given its exact location?

**H2 — Adaptive Investigation**

Can a model modify its testing strategy based on observations rather than following a fixed sequence of predefined checks?

**H3 — Evidence-Based Verification**

Can an autonomous system distinguish a plausible vulnerability hypothesis from a security weakness supported by reproducible evidence?

**H4 — Model Capability Variance**

How do frontier and locally executed open-weight models differ in discovery accuracy, tool usage, investigation depth, false positives, and resource efficiency?

**H5 — Operational Efficiency**

How much time, computation, token consumption, and API expenditure are required for a model to produce independently verified findings?

**H6 — Generalization**

Can models transfer their investigative capabilities across different vulnerability classes, software architectures, and previously unseen seeded defects?

These hypotheses will be evaluated progressively as the framework develops.

No hypothesis is considered validated merely because a model generates a convincing explanation.

---

## 04. Research Philosophy

VulnForge follows five engineering principles.

### Autonomy Over Static Automation

The model should make meaningful investigative decisions.

It should determine what to inspect, what hypotheses to pursue, which permitted tests to execute, and whether additional evidence is required.

### Evidence Over Assertions

A vulnerability claim is not proof.

Findings must be supported by objective observations, controlled reproduction, and independent validation.

### Reproducibility Over Demonstration-Only Results

Experiments should be repeatable with documented configurations, target states, model versions, and execution budgets.

### Measurement Over Model Rankings

No single arbitrary score can adequately represent security-research capability.

Discovery accuracy, verification success, false positives, runtime, cost, and resource consumption should remain separately measurable.

### Controlled Research Over Unrestricted Exploitation

Autonomous testing must operate within explicit authorization boundaries, restricted tool interfaces, and isolated experimental environments.

---

## 05. The Autonomous Research Lifecycle

The intended investigation process follows eight stages:

**Observe → Analyze → Hypothesize → Plan → Test → Validate → Adapt → Report**

| Stage | Responsibility |
|---|---|
| Observe | Inspect the authorized software environment |
| Analyze | Interpret application behavior and available evidence |
| Hypothesize | Form potential vulnerability explanations |
| Plan | Select permitted investigative actions |
| Test | Execute controlled security tests |
| Validate | Evaluate findings against independent evidence |
| Adapt | Refine investigation based on results |
| Report | Produce structured technical findings |

The research agent will be responsible for selecting investigative actions.

Deterministic software components will enforce execution policies, manage experiments, preserve evidence, and independently evaluate results.

This separation is essential for producing trustworthy benchmarks.

---

## 06. Proposed System Architecture

```text
                    RESEARCHER / OPERATOR
                              |
                              v
                     EXPERIMENT MANAGER
                              |
                              v
                     MULTI-MODEL ROUTER
                              |
                +-------------+-------------+
                |             |             |
                v             v             v
             OpenAI         Claude      Open-Weight
                |             |             |
                +-------------+-------------+
                              |
                              v
                   AUTONOMOUS RESEARCH AGENT
                              |
                              v
                    CONTROLLED TOOL GATEWAY
                              |
                              v
                     ISOLATED TARGET LAB
                              |
                              v
                       EVIDENCE STORE
                              |
                              v
                    INDEPENDENT VALIDATOR
                              |
                              v
                     BENCHMARKING ENGINE
                              |
                              v
                      RESEARCH REPORTS
```

This represents the intended architecture, not a claim that every component is already implemented.

The system is being developed as a modular Python application rather than a collection of independently deployed services.

---

## 07. Multi-Model Research

The initial experimental design targets three model categories.

| Model category | Provider | Purpose |
|---|---|---|
| Frontier model | OpenAI | Cloud-based autonomous security investigation |
| Frontier model | Anthropic Claude | Independent cloud-model comparison |
| Open-weight model | Qwen Coder via Ollama | Locally executed research baseline |

The initial local model candidate is **Qwen2.5-Coder 7B Instruct**, selected for practical execution on an Apple Silicon machine with 16 GB unified memory.

The framework is designed around a standardized model-provider interface.

This allows models to be replaced without rewriting the central research engine.

Provider-specific behavior, tool-call formats, usage accounting, and response structures are normalized before being processed by the agent.

The initial benchmark will compare three selected model configurations, not attempt to establish a universal ranking of AI systems.

---

## 08. Experimental Design

The first major experiment will involve one intentionally vulnerable local application.

Each model will independently investigate the same target.

To improve experimental fairness:

1. Each experiment begins from a reset target state.
2. Models receive equivalent task instructions.
3. Models receive the same logical tool capabilities.
4. Execution limits are standardized.
5. Observations and actions are recorded.
6. Findings are evaluated by an independent validation mechanism.
7. Results are compared using separately reported metrics.

The initial target will focus on an authorization weakness such as Broken Object Level Authorization (BOLA/IDOR), using synthetic users and data.

The framework will eventually support multiple seeded vulnerabilities, patched controls, and unfamiliar benchmark targets.

### Evidence Requirements

A submitted finding should include:

- A clearly stated vulnerability hypothesis.
- The affected component or endpoint.
- The permitted test methodology.
- Relevant request and response evidence.
- Observed security impact.
- Reproduction conditions.
- Independent validation outcome.

A model's self-reported confidence is not sufficient to establish validity.

---

## 09. Benchmarking Dimensions

VulnForge aims to evaluate autonomous security research across multiple independent dimensions.

| Dimension | Research measurement |
|---|---|
| Discovery effectiveness | Number of genuine vulnerabilities identified |
| Precision | Proportion of submitted findings that are valid |
| False positives | Incorrect or unsupported vulnerability claims |
| Verification | Independently confirmed findings |
| Reproducibility | Consistency across repeated trials |
| Autonomous behavior | Successful model-directed investigation |
| Tool efficiency | Useful actions relative to total tool usage |
| Time efficiency | Time required to produce verified findings |
| Token consumption | Input and output token usage |
| Monetary cost | API expenditure per experiment |
| Resource consumption | Local compute and memory requirements |
| Category performance | Results across vulnerability classes |

Metrics will be defined precisely before formal benchmarking.

Where ground-truth vulnerability labels are available, the evaluation may also measure recall.

Initial experiments will be treated as exploratory results rather than statistically conclusive evidence.

---

## 10. Technical Stack

The current and proposed technology stack includes:

| Component | Technology |
|---|---|
| Core language | Python 3.12+ |
| Model integrations | OpenAI SDK, Anthropic SDK, Ollama |
| Data contracts | Pydantic |
| HTTP operations | HTTPX |
| CLI | Typer |
| Testing | pytest |
| Package management | uv |
| Isolated laboratories | Docker / Docker Compose |
| Experiment storage | SQLite and structured JSON |
| Reporting | Markdown / JSON |

Technology choices may evolve as experimental requirements become clearer.

---

## 11. Current Development Status

**Current development stage: v0.2.1 — Foundation and Agent Execution Infrastructure**

### Implemented

- [x] Initial Python package structure.
- [x] Typed model-response and tool-call contracts.
- [x] OpenAI provider adapter foundation.
- [x] Anthropic provider adapter foundation.
- [x] Ollama provider adapter foundation.
- [x] CLI diagnostic functionality.
- [x] Bounded multi-turn agent execution foundation.
- [x] Controlled tool registration and argument validation.
- [x] Basic execution trace collection.
- [x] Offline mocked-provider tests.
- [x] Initial GitHub repository and version control.

### Next Development Milestones

- [ ] Live local-model integration.
- [ ] Live OpenAI and Anthropic provider verification.
- [ ] Provider reliability and tool-calling compatibility tests.
- [ ] Reproducible isolated vulnerable application.
- [ ] Policy-enforced HTTP investigation tools.
- [ ] Autonomous vulnerability investigation workflow.
- [ ] Independent vulnerability verification oracle.
- [ ] Experiment orchestration and reset mechanisms.
- [ ] Structured benchmark data collection.
- [ ] Comparative research report generation.

**Verification note:** The initial nine automated tests have passed in the local development environment. These tests validate foundation behavior, not real-world vulnerability discovery capability.

---

## 12. Development Roadmap

| Phase | Focus | Intended outcome |
|---|---|---|
| Phase 1 | Foundation | Typed contracts, CLI, provider abstraction |
| Phase 2 | Agent execution | Controlled multi-turn reasoning and tool usage |
| Phase 3 | Model integration | Three operational model providers |
| Phase 4 | Experimental laboratory | Reproducible vulnerable application |
| Phase 5 | Autonomous investigation | Model-directed security testing |
| Phase 6 | Independent validation | Evidence-backed vulnerability confirmation |
| Phase 7 | Benchmarking | Repeated experiments and comparative metrics |
| Phase 8 | Research reporting | Reproducible technical reports and analysis |

Future research may expand toward web/API business-logic vulnerabilities, historical CVE benchmarks, source-code analysis, LLM application security, RAG systems, agentic AI security, MCP authorization boundaries, and multi-step security reasoning.

These are research directions, not currently implemented capabilities.

---

## 13. Local Development

### Requirements

- Python 3.12+
- Git
- uv
- macOS or Linux development environment

Docker and Ollama will be required for later local laboratory and model-inference milestones.

### Clone

```bash
git clone https://github.com/singhshreyash75-eng/VulnForge.git
cd VulnForge
```

### Create an Environment

```bash
uv venv --python 3.12 --managed-python .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
uv pip install -e '.[dev]'
```

### Run Diagnostics

```bash
vulnforge doctor
```

### Run Tests

```bash
python -m pytest -q
```

At the current development stage, these commands verify the foundational framework.

They do not launch a complete vulnerability research experiment.

---

## 14. Security, Authorization & Responsible Research

VulnForge is intended exclusively for controlled security research, education, and explicitly authorized testing.

The project is designed around the following constraints:

- Active testing is restricted to authorized targets.
- Initial experiments use local, intentionally vulnerable environments.
- Synthetic credentials and test data are used.
- Tool execution is bounded and policy-controlled.
- Network access is restricted to approved laboratory targets.
- Destructive or self-propagating behavior is outside the project's scope.
- Security findings require independent verification.
- Future external research must respect program scope and coordinated disclosure requirements.

The framework is not intended to provide unrestricted autonomous exploitation against third-party systems.

---

## 15. Research Questions for the Security Community

Beyond implementation, VulnForge aims to contribute to broader discussions about the security implications of increasingly autonomous AI systems.

Several questions motivate this work:

**Can autonomous models discover security weaknesses that conventional scanners overlook?**

**How reliably can models reason about complex authorization and business-logic vulnerabilities?**

**Does increased model capability translate into better verified security outcomes, or merely more convincing vulnerability narratives?**

**How much human intervention remains necessary for accurate autonomous security research?**

**Can independent validation mechanisms reduce hallucinated or unsupported findings?**

**What experimental conditions are necessary for meaningful comparisons between frontier and open-weight models?**

**How might autonomous vulnerability research change the economics and accessibility of offensive security capabilities?**

**What technical safeguards are necessary when AI agents gain the ability to execute security-relevant tools?**

These are open research questions.

VulnForge will approach them through measured experimentation rather than assuming any particular conclusion.

---

## 16. Long-Term Technical Vision

The long-term objective is to develop a modular experimental framework capable of evaluating increasingly sophisticated autonomous security-research behavior.

Potential research directions include:

- Multi-model vulnerability investigation.
- Adaptive test generation.
- Multi-step attack-path reasoning.
- Source-code and runtime analysis.
- Autonomous investigation of LLM applications.
- RAG security evaluation.
- Agentic workflow and tool authorization testing.
- MCP security research.
- Reproducible historical vulnerability benchmarks.
- Previously unseen seeded vulnerability challenges.
- Cross-model evidence corroboration.
- Hardware and firmware-oriented security experiments.

Each expansion will depend on successful validation of earlier capabilities.

The priority is technical correctness, measurable results, and reproducible research.

---

## 17. Project Authorship

**Shreyash Singh**

B.Tech Computer Science & Engineering  
Specialization: Cybersecurity  
University of Petroleum and Energy Studies (UPES)

**Research Interests**

Offensive AI Security · AI Red Teaming · Autonomous Vulnerability Research · Agentic AI Security · Web/API Security · Security Automation

**GitHub:** [singhshreyash75-eng](https://github.com/singhshreyash75-eng)

---

## 18. Final Perspective

> The future of autonomous security research should not be evaluated by how convincingly an AI model describes vulnerabilities, but by whether it can independently discover, investigate, and validate them through reproducible evidence.

**VulnForge is an attempt to turn that question into a measurable engineering experiment.**

---

*VulnForge is an independent educational and experimental security research project. Development is ongoing, and its architecture, benchmarks, and findings will evolve as implementation progresses.*
