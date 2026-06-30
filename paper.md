---
title: 'CyberSiren: An open, instrumented multi-service pipeline for multi-modal phishing detection'
tags:
  - phishing detection
  - email security
  - machine learning
  - microservices
  - reproducible research
  - Go
  - Python
authors:
  - name: Saifelden M. Ismail
    orcid: 0009-0002-8867-6533
    corresponding: true
    affiliation: 1
  - name: Aser O. Ibrahim
    affiliation: 1
  - name: Omar A. Mahmoud
    orcid: 0009-0003-9266-4102
    affiliation: 1
affiliations:
  - name: Department of Communications and Information Engineering, Zewail City of Science and Technology, Giza, Egypt
    index: 1
date: 30 June 2026
bibliography: paper.bib
---

# Summary

`CyberSiren` is an open, end-to-end pipeline for detecting phishing in email. It
ingests raw messages and scores each modality of a message — the URLs it carries, its
text, its sender and header metadata, and its attachments — with a dedicated engine, then
recombines those signals into a single verdict at a decision-fusion stage. The system is
implemented as eleven event-driven Go and Python microservices over a Kafka-API broker,
and it is instrumented end to end with Prometheus metrics, OpenTelemetry traces exported
to Jaeger, and structured logs, so that every message can be followed across the pipeline.

Three detection engines are fully implemented and independently runnable: a four-stage URL
analysis stack (a deterministic domain guard, a gradient-boosted lexical model, a
threat-intelligence lookup, and a fusion sidecar over live host enrichment), a fine-tuned
DistilBERT [@sanh2019distilbert] email-text classifier served through ONNX Runtime, and a
scheduled threat-intelligence synchronizer that ingests public feeds. The repository ships
the trained models, the supervised corpora used to build them, a leakage-controlled
whole-system benchmark, a Docker Compose demonstration stack with auto-provisioned
dashboards, versioned container images, and a test suite (over one hundred Go and Python
tests) run in continuous integration.

# Statement of need

Research on phishing detection is difficult to reproduce and to deploy. Published detectors
are typically released as a notebook and a metrics table, without an end-to-end system, the
assembled training data, or an evaluation harness; this makes it hard to compare methods on
equal footing or to study how a detector behaves once it is wired into a realistic pipeline.
Multi-modal approaches that combine URL, text, and sender signals are especially
under-served by available tooling, because evaluating fusion requires the upstream engines,
the message bus, and the data plumbing to exist together.

`CyberSiren` addresses this gap by providing a complete, open, instrumented reference
implementation rather than a single model. Researchers and practitioners can run the
individual engines, reproduce the released benchmarks, swap in their own models behind the
same service interfaces, and observe behaviour through the built-in tracing and metrics.

# State of the field

Recent phishing-detection research is dominated by two largely separate lines: lexical and
structural URL classifiers built on public corpora [@prasad2024phiusiil], and
transformer-based email-text classifiers [@altan2025dualpath]. Most are released as
standalone models evaluated on a single static corpus, and the difficulty of distinguishing
phishing from ordinary spam is itself an active concern [@toth2025phish]. Tooling that
integrates several modalities behind a deployable, observable service — and that ships the
data and harness needed to study decision-level fusion or evaluation methodology — is scarce.
`CyberSiren` complements these point solutions with an integrated, reproducible platform that
exposes the full pipeline rather than a single scoring function.

# Software design

The pipeline is organized as independent services that communicate over Kafka topics keyed
by a message identifier, so each stage scales and fails independently. A parser extracts the
URLs, text, headers, and attachments of a message and emits an analysis plan; the modality
engines score their channel in parallel and publish a well-defined score envelope; an
aggregator collects the channels behind a synchronization barrier; and a decision engine
combines them with a configurable blender (calibrated probabilistic-OR, weighted average, or
hand-set noisy-OR), maps the result to a verdict, and fingerprints the campaign. Each engine
is a replaceable unit behind a stable interface: the URL engine calls a Python inference
sidecar over HTTP, and the email engine runs a Go wrapper in front of an ONNX Runtime
process, so models can be retrained and swapped without touching the surrounding services.
Persistence uses PostgreSQL with materialized views and a Valkey cache, and every service
emits Prometheus metrics and OpenTelemetry traces. The repository includes Dockerfiles,
a Docker Compose demonstration profile, Kubernetes manifests, and continuous integration that
builds versioned container images and runs the Go and Python test suites.

# Research impact statement

`CyberSiren` lowers the barrier to reproducible, deployment-realistic phishing-detection
research. Its released corpora, a campaign-aware dataset splitter (splitting at the level of
message campaigns rather than individual messages, to prevent template leakage across train
and test), a held-out real-phishing evaluation slice, and a whole-system benchmark let others
reproduce results and benchmark new methods behind stable service interfaces; its
instrumentation exposes runtime behaviour that model-only releases hide. The platform also
makes common evaluation pitfalls concrete and reproducible — for example, how strongly a
reported held-out result depends on the train/test splitting procedure and on the particular
slice of "real" phishing chosen for evaluation — which supports more careful measurement
practice in the subfield. The software underpins a graduation research project and an
associated preprint [@cybersiren2026preprint], and is released so that its engines, datasets,
and benchmarks can be reused and scrutinized by others.

# AI usage disclosure

The authors used Claude (Anthropic) for code and test scaffolding, documentation drafting,
and copy-editing. All architectural decisions, the system design, the machine-learning
methodology, and the experimental work were made and carried out by the human authors, who
reviewed and take full responsibility for all outputs. No generative AI was used in the
author–reviewer review conversation.

# Acknowledgements

We thank Dr. Mohamed Samir for his academic supervision, and the engineers at Zinad for
advisory support. The authors received no financial support for this work.

# References
