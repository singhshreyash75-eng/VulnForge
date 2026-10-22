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

**VulnForge** is an independent offensive-AI-security research and engineering project exploring the intersection of autonomous agents, software vulnerability discovery, controlled exploitation research, and empirical security benchmarking.

The central question is:

> Can an AI model operate as an independent security researcher—observing an unfamiliar software environment, identifying weaknesses, developing hypotheses, selecting appropriate tests, interpreting evidence, and validating vulnerabilities without relying entirely on predefined scanning signatures?

VulnForge aims to investigate this question experimentally.

Unlike conventional vulnerability scanners or LLM-powered security assistants that summarize scanner output, VulnForge is designed around **model-directed, observation-driven security investigation**.

Different AI models will independently investigate software environments under equivalent experimental conditions. Their performance will be measured through actual security outcomes, independently verified evidence, and reproducible experiments.

### Beyond a Single Vulnerable Application

The research vision extends beyond testing a single intentionally vulnerable application.

VulnForge is being developed toward a **multi-target benchmark corpus** incorporating:

- Intentionally vulnerable software applications.
- Patched and non-vulnerable application variants.
- Historical vulnerable versions of real-world open-source software.
- Reproducible applications derived from documented security weaknesses.
- Labeled vulnerability-detection datasets.
- Previously unseen seeded security challenges.

This allows the framework to investigate not only whether an AI model discovers a vulnerability, but also whether it correctly rejects unsupported hypotheses when no known vulnerability is present.

**The objective is to measure independent security-research capability—not to engineer successful outcomes or merely generate vulnerability reports.**

### Current Development State

VulnForge is under active development.

Its Python research-engine foundation, model-provider adapters, controlled multi-turn execution, local Qwen integration, and initial Docker-based vulnerability laboratory have been implemented.

The first local model-driven tool-execution experiment has succeeded. The initial vulnerable and patched application modes have also been exercised through integration tests.

The restricted HTTP gateway has also enabled Qwen to inspect the live local document API. Early exploratory runs demonstrate successful tool use but missed the seeded cross-owner authorization defect. Offline coverage-analysis and oracle evaluation tests have passed; structured finding submission, claim-level adjudication, multi-target benchmarking, and cloud-model comparisons remain development objectives.

---

## 02. Research Motivation

### The Changing Security Landscape

Modern software ecosystems are increasingly interconnected, API-driven, and dependent on complex authentication, authorization, and application workflows.

At the same time, advances in large language models are enabling systems that can reason about unfamiliar environments, select tools, execute multi-step workflows, and adapt their behavior based on observations.

These capabilities raise a fundamental cybersecurity question:

**What happens when vulnerability investigation becomes increasingly autonomous?**

Traditional security automation relies heavily on predefined signatures, scripted checks, heuristics, and known vulnerability patterns.

Autonomous AI systems introduce a different possibility.

Instead of merely executing predefined tests, an AI model may be capable of:

- Inspecting unfamiliar software interfaces.
- Understanding application functionality.
- Reasoning about potential security weaknesses.
- Developing vulnerability hypotheses.
- Selecting context-appropriate security tests.
- Interpreting HTTP responses and runtime observations.
- Adapting investigative strategies.
- Producing evidence-backed security findings.

However, the ability to generate plausible security explanations does not necessarily imply the ability to discover or validate genuine vulnerabilities.

A model may confidently report a nonexistent vulnerability, overlook an exploitable weakness, misunderstand application behavior, or fail to execute a technically valid test.

**VulnForge is motivated by the need to measure these differences objectively.**

### AI-Assisted Offensive Security and Real-World Implications

The security community is increasingly examining the implications of AI-assisted offensive operations, autonomous vulnerability discovery, and agentic security tooling.

Relevant concerns include:

- AI-assisted reconnaissance and application inspection.
- Automated vulnerability hypothesis generation.
- Model-directed security test selection.
- Adaptive investigation of authentication and authorization weaknesses.
- AI-generated proof-of-concept candidates.
- Multi-step vulnerability reasoning.
- The reliability of model-generated security findings.
- Potential scaling of AI-assisted offensive workflows.
- The risks introduced by autonomous agents with executable tools.
- The implications of increasingly accessible offensive automation.

These developments raise important questions for both offensive and defensive security research.

Could autonomous models discover weaknesses that conventional scanners miss?

Could smaller open-weight models perform meaningful vulnerability research without expensive cloud infrastructure?

Could an autonomous model distinguish a genuine security weakness from an apparently suspicious but secure application behavior?

And how should security researchers objectively evaluate these capabilities?

VulnForge approaches these questions as **testable research hypotheses**, not predetermined conclusions.

The framework does not assume that any model is inherently effective at offensive security.

Its purpose is to measure what models can accomplish, where they fail, and how reliably their findings can be independently verified.

All active experiments are restricted to controlled, isolated, or explicitly authorized environments.

---

## 03. Core Research Hypothesis

The primary hypothesis behind VulnForge is:

> **Given equivalent tools, environmental access, operational constraints, and evaluation criteria, different AI models will demonstrate measurable differences in their ability to autonomously discover, investigate, and independently validate software vulnerabilities across both vulnerable and non-vulnerable software environments.**

This hypothesis is divided into several research questions.

### H1 — Autonomous Vulnerability Discovery

Can an AI model identify a vulnerability in an unfamiliar software environment without being told its exact location or implementation?

### H2 — Adaptive Investigation

Can a model modify its investigation strategy based on observed application behavior instead of following a fixed sequence of predefined tests?

### H3 — Evidence-Based Verification

Can an autonomous system distinguish between a plausible vulnerability hypothesis and a security weakness supported by reproducible technical evidence?

### H4 — False-Positive Resistance

Can an AI model recognize secure application behavior and avoid reporting unsupported vulnerabilities?

### H5 — Model Capability Variance

How do frontier and locally executed open-weight models differ in discovery accuracy, investigation depth, tool-selection quality, false-positive rates, and autonomous task completion?

### H6 — Operational Efficiency

How much time, computation, token consumption, and API expenditure are required to produce independently verified findings?

### H7 — Cross-Target Generalization

Can models transfer their investigative capabilities across different application architectures, vulnerability categories, historical software versions, and previously unseen targets?

### H8 — Tool-Calling Reliability

How reliably can models generate valid tool requests, interpret execution results, and complete multi-step investigations under restricted execution policies?

### H9 — Vulnerability Prevalence and Investigation Behavior

How does model behavior change when an investigated target contains no known vulnerability?

Does the model terminate with an evidence-based inconclusive result, correctly reject a hypothesis, or manufacture an unsupported finding?

### H10 — Frontier vs Open-Weight Research Capability

Under clearly documented hardware and resource constraints, how do local open-weight models compare with cloud-hosted frontier models in verified security outcomes and cost efficiency?

These hypotheses will be evaluated progressively.

**A model's confidence, reasoning narrative, or generated proof of concept is not sufficient evidence of successful vulnerability discovery.**

---

## 04. Research Philosophy

VulnForge follows seven engineering and research principles.

### Autonomy Over Static Automation

The model should make meaningful investigative decisions.

It should determine what to inspect, which hypotheses to pursue, what permitted tests to execute, and whether additional investigation is justified.

### Evidence Over Assertions

A vulnerability claim is not proof.

Findings must be supported by objective observations, controlled reproduction, and independent validation.

### Reproducibility Over Demonstration-Only Results

Experiments should be repeatable with documented model versions, target configurations, execution limits, software dependencies, and environmental conditions.

### Measurement Over Arbitrary Rankings

No single composite score adequately represents autonomous security-research capability.

Discovery effectiveness, false positives, verification success, runtime, token usage, and cost should remain separately measurable.

### Generalization Over Benchmark Memorization

The framework should evaluate models on unfamiliar targets and previously unseen security challenges wherever possible.

Historical vulnerabilities and public benchmark datasets are valuable, but results must account for possible training-data contamination.

### Controlled Research Over Unrestricted Exploitation

Autonomous security testing must operate within explicit authorization boundaries, restricted tools, isolated environments, and auditable execution policies.

### Non-Intervention Over Forced Success

The benchmark engine must not steer a model toward a known vulnerability, repeat an experiment until it succeeds, or silently repair its investigative decisions. Missed vulnerabilities, premature termination, unsupported claims, and inconclusive results are first-class research outcomes. Coverage analysis and ground-truth validation occur independently of model decision-making. Any assisted investigation must be labeled and evaluated as a separate experimental condition.

---

## 05. The Autonomous Research Lifecycle

VulnForge is designed around the following research process:

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

The model is responsible for investigative decisions.

Deterministic software components are responsible for execution boundaries, experiment orchestration, evidence preservation, and independent validation.

A model may conclude that:

- A vulnerability is supported by available evidence.
- A suspected vulnerability is not reproducible.
- The observed behavior appears consistent with expected security controls.
- The available evidence is insufficient to reach a conclusion.

**An investigation that produces no vulnerability finding is not automatically a failed experiment.**

Likewise, the absence of a reported vulnerability does not prove that an unfamiliar application is secure.

---

## 06. Proposed System Architecture

```text
                     RESEARCHER / OPERATOR
                               |
                               v
                      EXPERIMENT MANAGER
                               |
                               v
                    BENCHMARK CORPUS MANAGER
                               |
               +---------------+---------------+
               |               |               |
               v               v               v
          Seeded Labs     Historical CVEs   Labeled Datasets
               |               |               |
               +---------------+---------------+
                               |
                               v
                       TARGET SANDBOX
                               |
                               v
                       MULTI-MODEL ROUTER
                               |
            +------------------+------------------+
            |                  |                  |
            v                  v                  v
          OpenAI             Claude             Gemini
            |                  |                  |
            +------------------+------------------+
                               |
                          Open-Weight
                         Qwen / Ollama
                               |
                               v
                    AUTONOMOUS RESEARCH AGENT
                               |
                               v
                     CONTROLLED TOOL GATEWAY
                               |
                               v
                    ISOLATED TARGET INSTANCE
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

The diagram represents the intended architecture. It does not imply that every component is currently implemented.

Each model will conduct an independent experiment against a freshly initialized target environment. The model router selects one provider per trial; it does not pool model reasoning or share previous model findings across trials.

The benchmark corpus manager will maintain target metadata, software versions, execution configurations, and evaluator-only ground truth.

The research agent will interact with the target through a policy-enforced tool gateway.

The independent validator will determine whether submitted findings correspond to objectively reproducible security weaknesses.

The benchmarking engine will compare experimental outcomes without collapsing every measurement into one arbitrary ranking.

VulnForge is being developed as a modular Python application, not a collection of premature microservices.

---

## 07. Multi-Model Research

The expanded experimental architecture targets four model-provider families.

| Model category | Provider | Research purpose |
|---|---|---|
| Frontier model | OpenAI | Autonomous security investigation and tool-use evaluation |
| Frontier model | Anthropic Claude | Independent frontier-model comparison |
| Frontier model | Google Gemini | Additional model-family comparison |
| Open-weight model | Qwen via Ollama | Locally executed security-research baseline |

### Local Open-Weight Baseline

The initial local model is **Qwen2.5-Coder 7B Instruct**, executed through Ollama on Apple Silicon hardware with 16 GB unified memory.

This model provides a practical baseline for investigating how a smaller locally executed coding model performs relative to cloud-hosted frontier systems.

The local configuration also enables development and debugging without per-token cloud API expenditure.

### Standardized Provider Interface

The framework uses a common provider contract to normalize:

- Model identification.
- Structured responses.
- Tool-call requests.
- Tool-result messages.
- Token accounting.
- Provider-specific response formats.
- Execution errors.
- Model configuration metadata.

The provider abstraction allows model implementations to be changed without rewriting the research engine.

### Tool-Calling Compatibility

Early local experiments identified a distinction between selecting a correct tool and generating a correctly structured tool call.

The initial Qwen configuration produced valid-looking tool requests as JSON text rather than native structured tool-call objects.

A controlled JSON normalization fallback was subsequently introduced.

This motivates separate evaluation of:

**Tool-selection accuracy:** Whether a model selects an appropriate investigative tool.

**Tool-call compliance:** Whether a model follows the required invocation protocol.

Native tool calling and compatibility-fallback behavior should be recorded separately during formal benchmarking.

### Experimental Fairness

Models will receive equivalent logical tool capabilities, target access, and evaluation criteria.

However, frontier and open-weight models may differ substantially in model size, inference hardware, context windows, and operating costs.

These differences will be documented rather than ignored.

The project does not aim to establish a universal ranking of AI models. Results will be scoped to tested versions, targets, prompts, tools, inference settings, and budgets. A larger model is not assumed to outperform a smaller model on every task.

---

## 08. Experimental Design & Benchmark Corpus

VulnForge is evolving toward a reusable benchmark corpus containing multiple target types and security conditions.

The benchmark corpus is intended to support both runtime vulnerability investigation and labeled vulnerability-detection experiments.

### Track A — Controlled Vulnerability Laboratories

Intentionally vulnerable applications executed in isolated environments.

Examples include:

- Synthetic web applications.
- Seeded API authorization defects.
- Intentionally vulnerable training applications.
- Patched versions of the same software.
- Negative-control scenarios.

These targets provide controlled conditions and clearly defined expected behavior.

### Track B — Real-World-Derived Software

Reproducible software environments derived from publicly documented vulnerabilities and historical open-source releases.

Potential target sources include:

- Historical vulnerable software versions.
- Corresponding patched releases.
- Documented CVE reproductions.
- Open-source applications with reproducible security defects.
- Software versions selected for controlled comparative analysis.

These environments will be executed locally or within explicitly authorized research infrastructure.

Public source availability does not automatically authorize active testing against a live deployment.

### Track C — Labeled Security Datasets

Established datasets may provide larger collections of known vulnerable and non-vulnerable examples.

Candidate resources include:

- OWASP Benchmark Project.
- NIST Software Assurance Reference Dataset (SARD).
- Juliet Test Suites.
- Other reproducible, labeled software-security benchmarks.

These datasets are particularly useful for vulnerability identification, classification, and false-positive evaluation.

They are not automatically equivalent to runtime exploitability benchmarks.

### Vulnerable and Non-Vulnerable Targets

The corpus will intentionally include both positive and negative examples.

| Target condition | Expected research behavior |
|---|---|
| Known vulnerability present | Investigate and identify supported findings |
| Vulnerability patched | Avoid reporting the original weakness |
| Secure negative control | Reject unsupported hypotheses |
| Ambiguous behavior | Report uncertainty and limitations |
| Unknown ground truth | Preserve evidence without claiming verified accuracy |

This distinction is essential for measuring precision, recall, false-positive rates, and false-negative rates.

### Independent Experiment Protocol

Each model experiment should:

1. Start from a reproducible target state.
2. Receive equivalent instructions and permitted tools.
3. Operate within standardized execution limits.
4. Independently select investigative actions.
5. Collect actual application observations.
6. Submit structured findings.
7. Have those findings independently validated.
8. Preserve evidence and execution traces.
9. Record token usage, runtime, and cost.
10. Produce reproducible experimental results.

Ground-truth labels and validator logic must remain inaccessible to the research agent during an experiment. The model is free to end with no finding, a missed vulnerability, or an inconclusive result; the evaluator records these outcomes rather than redirecting the model toward the answer.

### Exploratory Runs vs Formal Benchmarks

Development runs may use revised prompts, additional diagnostics, or experimental tool adapters to test the infrastructure. They must be labeled **exploratory** and must not be pooled with formal benchmark trials.

Formal trials will use a preregistered or versioned protocol: fixed neutral instructions, equivalent permitted tools, target resets, predetermined repetition counts, model/version identifiers, and explicit budgets. Retries are allowed only under a documented, provider-neutral failure policy, not because a model missed the vulnerability.

### Model Variability and Failure Analysis

A model can complete a tool-using workflow yet fail to test the relevant authorization boundary. It can also generate plausible but unsupported conclusions. These outcomes are recorded separately as execution success, investigation coverage, finding submission, and independently verified discovery.

Repeated trials will estimate variation within a model configuration. Reports will include counts and uncertainty intervals when sample sizes permit, rather than extrapolating from one successful or failed run. Public historical benchmarks will be marked for possible training-data exposure, and held-out cases will be preferred for generalization studies.

### Evidence Requirements

A submitted finding should include:

- Vulnerability hypothesis.
- Affected software component.
- Relevant endpoint or functionality.
- Test methodology.
- Request and response evidence.
- Observed security impact.
- Reproduction conditions.
- Verification outcome.
- Limitations and uncertainty.

A model-generated explanation alone does not constitute proof.

---

## 09. Benchmarking Dimensions

VulnForge aims to measure autonomous security research across independent evaluation dimensions.

| Dimension | Research measurement |
|---|---|
| Discovery effectiveness | Genuine vulnerabilities identified |
| True positives | Correctly identified known vulnerabilities |
| False positives | Unsupported or incorrect findings |
| True negatives | Correctly rejected non-vulnerable cases |
| False negatives | Known vulnerabilities not identified |
| Precision | Valid findings relative to all reported findings |
| Recall | Identified vulnerabilities relative to known positives |
| False-positive rate | Incorrect positives relative to known negatives |
| Verification success | Findings confirmed by independent validators |
| Reproducibility | Consistency across repeated experiments |
| Autonomous completion | Investigations completed without intervention |
| Tool-selection quality | Relevance of selected investigative actions |
| Tool-call compliance | Correct execution protocol usage |
| Tool efficiency | Useful actions relative to total actions |
| Time efficiency | Time required to complete an investigation |
| Token consumption | Input and output token usage |
| API cost | Monetary expenditure per experiment |
| Compute requirements | Local memory and inference resources |
| Category performance | Outcomes across vulnerability classes |

### Core Classification Metrics

Where reliable ground truth is available:

**Precision = TP / (TP + FP)**

**Recall = TP / (TP + FN)**

**False-Positive Rate = FP / (FP + TN)**

**Accuracy = (TP + TN) / (TP + TN + FP + FN)**

These measurements require clearly defined evaluation units and independently established labels.

For unknown real-world software, an investigation producing no finding cannot automatically be counted as a true negative.

### Repeated Trials

Formal experiments should include repeated runs to evaluate variability.

Where practical, the benchmark will record:

- Model version and configuration.
- Sampling parameters.
- Context limits.
- Experiment duration.
- Tool budgets.
- Target version.
- Target initialization state.
- Trial identifiers.
- Independent verification results.

Initial demonstrations will be treated as exploratory research. Benchmark tables must distinguish **no finding**, **unsupported claim**, **verified finding**, **missed known defect**, **invalid run**, and **inconclusive outcome**. A model observing a suspicious response is not credited with a discovery unless its submitted finding identifies the relevant weakness and satisfies the evaluator-defined evidence criteria.

Larger-scale conclusions will require sufficiently diverse targets, repeated trials, and appropriate statistical analysis.

---

## 10. Technical Stack

The current and proposed technology stack includes:

| Component | Technology |
|---|---|
| Core language | Python 3.12+ |
| Model integrations | OpenAI SDK, Anthropic SDK, Ollama |
| Planned additional provider | Google GenAI SDK |
| Data contracts | Pydantic |
| HTTP investigation | HTTPX |
| CLI | Typer |
| Testing | pytest |
| Package management | uv |
| Isolated laboratories | Docker / Docker Compose |
| Vulnerable API targets | FastAPI |
| Experiment storage | Structured JSON and planned SQLite |
| Reporting | Markdown / JSON |
| Future deployment | Containerized, access-controlled research environment |

The project prioritizes maintainability, explicit interfaces, reproducibility, and testability.

Technology choices may evolve as experimental requirements become clearer.

---

## 11. Current Development Status

**Current stage: Milestone 4.3 — HTTP Investigation and Evaluation Foundations**

### Implemented

- [x] Initial Python package structure.
- [x] Typed model-response and tool-call contracts.
- [x] OpenAI provider adapter foundation.
- [x] Anthropic provider adapter foundation.
- [x] Ollama provider adapter foundation.
- [x] CLI diagnostic functionality.
- [x] Bounded multi-turn research-agent foundation.
- [x] Controlled tool registration and argument validation.
- [x] Basic execution trace collection.
- [x] Offline mocked-provider tests.
- [x] Local Qwen2.5-Coder 7B inference through Ollama.
- [x] Live local-model tool-execution experiment.
- [x] Strict JSON tool-call compatibility fallback.
- [x] Docker-based synthetic document API.
- [x] Vulnerable and patched application modes.
- [x] Initial benchmark target manifest and evaluator ground truth.
- [x] Initial Docker laboratory integration tests.
- [x] Restricted local HTTP inspection tool and real Qwen HTTP investigation runs.
- [x] Offline-tested investigation coverage analyzer.
- [x] Initial independent authorization oracle implementation and offline evaluator tests.
- [x] GitHub version control and milestone-based commits.

### In Progress

- [ ] Structured model-submitted finding contracts and claim-level adjudication.
- [ ] Full live oracle acceptance checks for both target modes.
- [ ] Versioned experimental protocols and standardized run manifests.
- [ ] Reliable model-run labeling (native tool calls versus JSON fallback).
- [ ] Formal vulnerable-versus-patched model comparison with repeated trials.

### Planned

- [ ] Live OpenAI API verification.
- [ ] Live Anthropic Claude API verification.
- [ ] Google Gemini provider integration.
- [ ] Multi-model experiment orchestration.
- [ ] Automated target initialization and reset.
- [ ] Expanded benchmark corpus.
- [ ] Historical vulnerable software targets.
- [ ] Negative-control benchmark expansion.
- [ ] Structured benchmark analytics.
- [ ] Comparative technical reporting.
- [ ] Controlled deployment environment.

### Verification Notes

The initial offline agent tests have passed.

A local Qwen experiment successfully selected and executed a permitted simulated inspection tool, received the observation, and generated a final response.

The initial Docker target has been exercised in vulnerable and patched modes using automated HTTP integration checks. Qwen has also performed live HTTP investigations against the target; early runs missed the seeded cross-owner defect or drew insufficiently supported conclusions. This is recorded as exploratory evidence of model limitations, not a software failure to conceal.

The five offline evaluation tests for coverage and discovery-status logic passed. Live end-to-end oracle correctness and claim-level grading must still be verified before formal benchmarking.

These achievements validate important infrastructure components.

They do not yet establish successful autonomous vulnerability discovery, multi-model benchmarking, or independently verified real-world security findings.

---

## 12. Development Roadmap

| Phase | Focus | Intended outcome |
|---|---|---|
| Phase 1 | Foundation | Python contracts, CLI, provider abstraction |
| Phase 2 | Agent execution | Controlled multi-turn model-driven tool usage |
| Phase 3 | Experimental laboratory | Docker target, vulnerable/patched modes, corpus metadata |
| Phase 4 | Autonomous HTTP investigation | Real model-directed application inspection |
| Phase 5 | Independent validation | Evidence-backed vulnerability adjudication |
| Phase 6 | Cloud-model integration | OpenAI, Claude, and Gemini verification |
| Phase 7 | Experiment orchestration | Independent runs, target resets, resource accounting |
| Phase 8 | Expanded benchmark corpus | Multiple applications, negative controls, historical defects |
| Phase 9 | Benchmarking and analytics | Repeated trials, comparative metrics, cost analysis |
| Phase 10 | Reporting | Reproducible technical and research reports |
| Phase 11 | Controlled deployment | Securely hosted research interface and isolated execution |

### Initial Research Milestone

The first major research demonstration will compare selected AI models against the same controlled application.

Each model will independently investigate the environment, submit evidence-backed findings, and have those findings independently evaluated.

### Expanded Research Milestone

The subsequent objective is to evaluate multiple models across a diverse corpus of vulnerable and non-vulnerable software environments.

This will support investigation of generalization, false-positive resistance, repeatability, and performance across vulnerability categories.

---

## 13. Local Development

### Requirements

- Python 3.12+
- Git
- uv
- Docker Desktop or compatible Docker Engine
- Ollama for local inference
- macOS or Linux development environment

Cloud API credentials are optional for the local development workflow.

### Clone

```bash
git clone https://github.com/singhshreyash75-eng/VulnForge.git
cd VulnForge
```

### Create an Environment

```bash
uv python install 3.12
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

### Run Offline Tests

```bash
python -m pytest tests/test_agent.py tests/test_contracts.py tests/test_providers.py tests/test_transcripts.py -q
```

### Start the Local Model

```bash
ollama pull qwen2.5-coder:7b
ollama serve
```

If Ollama is already running as a background service, starting another server process is unnecessary.

### Start the Vulnerable Laboratory

```bash
LAB_MODE=vulnerable docker compose -f lab/docker-compose.yml up -d --build
```

Verify:

```bash
curl http://127.0.0.1:18080/health
```

### Run Laboratory Integration Tests

```bash
LAB_MODE=vulnerable python -m pytest tests/test_document_api.py -v
```

### Switch to Patched Mode

```bash
docker compose -f lab/docker-compose.yml down

LAB_MODE=patched docker compose -f lab/docker-compose.yml up -d --force-recreate

LAB_MODE=patched python -m pytest tests/test_document_api.py -v
```

### Local Agent Demonstration

```bash
python live_agent.py
```

This command runs the existing local model-driven simulated-tool demonstration.

To run the current evaluated HTTP investigation, first start the matching target mode, then execute:

```bash
python investigate_lab.py --mode vulnerable
```

For the patched target, recreate it with `LAB_MODE=patched` and use `--mode patched`. The evaluator output does not itself prove that the model submitted a correct finding.

Offline evaluator checks:

```bash
python -m pytest tests/test_evaluation.py -v
```

**Development note:** Laboratory integration tests require the target application to be running in the corresponding mode. They should not be confused with offline unit tests.

---

## 14. Security, Authorization & Responsible Research

VulnForge is intended exclusively for controlled security research, education, and explicitly authorized testing.

The framework follows these principles:

- Active testing is restricted to authorized targets.
- Initial experiments use isolated software environments.
- Synthetic credentials and data are used wherever possible.
- Models interact through explicitly permitted tools.
- Network destinations and execution capabilities are restricted.
- Resource consumption and execution time are bounded.
- Destructive and self-propagating behavior is excluded.
- Security findings require independent verification.
- External research must respect program authorization and disclosure requirements.

### Real-World Software Research

Historical vulnerable applications and open-source software may be downloaded and reproduced in local laboratory environments.

The public availability of a repository, website, or API does not automatically authorize active vulnerability testing against its deployed infrastructure.

Likewise, running an AI agent inside a sandbox does not automatically isolate an external website from that agent's requests.

Future experiments will distinguish between locally reproduced software and explicitly authorized external targets.

### Research Isolation

The intended isolation architecture includes:

- Registered target environments.
- Restricted network access.
- Allowlisted tool interfaces.
- Controlled HTTP methods and destinations.
- Execution budgets.
- Resource limits.
- Auditable experiment traces.
- Environment resets between experiments.
- Separation of agent-visible data and evaluator-only ground truth.

Security controls will be tested independently rather than assumed effective because a container is present. In particular, loopback port binding alone does not prevent a container from initiating outbound connections; deployment must enforce separate network-egress restrictions.

---

## 15. Research Questions for the Security Community

VulnForge aims to contribute to broader discussions about the capabilities, limitations, and security implications of autonomous AI systems.

Several questions motivate this work:

**Can autonomous AI models discover genuine software vulnerabilities without predefined scanner signatures?**

**Can models identify business-logic and authorization weaknesses that require contextual reasoning?**

**How effectively can autonomous models investigate unfamiliar real-world-derived software?**

**Do frontier models consistently outperform smaller open-weight models in verified security outcomes?**

**Can models reliably distinguish vulnerable software from patched or non-vulnerable applications?**

**How often do autonomous systems produce false-positive security findings?**

**Does increased model capability translate into better verified results, or merely more convincing vulnerability narratives?**

**How much human intervention remains necessary for trustworthy autonomous security research?**

**What experimental conditions are required for fair comparisons across different model providers?**

**How should tool-calling reliability and investigation quality be measured independently?**

**Can autonomous security-research systems become more cost-efficient without sacrificing verification quality?**

**What safeguards are necessary as AI agents gain access to increasingly capable security tools?**

**How might autonomous vulnerability discovery influence the future economics and accessibility of offensive security research?**

These are open research questions.

VulnForge will investigate them through controlled experiments, reproducible evidence, and transparent reporting.

---

## 16. Long-Term Technical Vision

The long-term objective is to develop a modular experimental framework capable of evaluating increasingly sophisticated autonomous security-research behavior.

The framework should evolve from a single controlled demonstration into a reusable environment for comparative AI security research.

### Expanded Benchmarking

Potential directions include:

- Multi-application vulnerability benchmarks.
- Historical CVE reproduction environments.
- Vulnerable-versus-patched software comparisons.
- Previously unseen seeded security challenges.
- Secure negative-control targets.
- Cross-model vulnerability corroboration.
- Repeated experimental trials.
- Model reliability and failure-mode analysis.

### Advanced Autonomous Investigation

Future capabilities may include:

- Adaptive security test generation.
- Multi-step attack-path reasoning.
- Source-code and runtime analysis.
- Web/API business-logic vulnerability research.
- Context-aware authorization testing.
- Evidence-driven hypothesis refinement.
- Independent reproduction of model-generated findings.

### AI Application Security

Additional research directions include:

- LLM application security.
- Prompt-injection resilience.
- RAG system security.
- Agentic workflow security.
- MCP and tool-authorization testing.
- Cross-agent trust boundaries.
- Model and tool-output manipulation research.

### Future Deployment

VulnForge may eventually be deployed as a controlled, self-hosted research environment.

The intended deployment would provide:

- An authenticated researcher interface.
- Experiment configuration and execution.
- Model selection.
- Benchmark target selection.
- Isolated target environments.
- Controlled experiment monitoring.
- Evidence and trace inspection.
- Comparative result visualization.
- Technical report access.

Deployment must preserve isolation between the research interface, agent execution, target environments, and evaluator-only ground truth.

The objective is to make experiments reproducible and accessible to authorized researchers—not to expose unrestricted autonomous testing capabilities.

### Longer-Term Research

Hardware and firmware-oriented security research may be explored after the software-based research framework has demonstrated reliable functionality.

Every expansion will depend on successful verification of earlier capabilities.

**The priority remains technical correctness, measurable outcomes, and reproducible research.**

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

The project is built around a simple research principle:

**Autonomy must be observable. Vulnerabilities must be verifiable. Benchmarks must be reproducible. Failures must be reported without intervention or selective omission.**

VulnForge is not designed to make every AI model succeed. It is designed to discover, through controlled experiments, what each model can and cannot do under specified conditions.

---

*VulnForge is an independent educational and experimental security research project. Development is ongoing, and its architecture, benchmarks, and findings will evolve as implementation progresses.*
