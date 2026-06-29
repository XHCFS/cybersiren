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
text, its sender/header metadata, and its attachments — with a dedicated engine, then
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
dashboards, and a test suite (over one hundred Go and Python tests) run in continuous
integration.

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
The project also makes common evaluation pitfalls concrete and reproducible: it ships a
**campaign-aware** dataset-splitting procedure (splitting at the level of message campaigns
rather than individual messages, to prevent template leakage across train and test) and a
held-out real-phishing evaluation slice, which together expose how strongly reported
generalization depends on the splitting and slicing choices. Making these artifacts and
procedures openly available lowers the barrier to deployment-realistic, reproducible
phishing-detection research.

The software has been used as the basis of a graduation research project and an associated
preprint [@cybersiren2026preprint], and is released so that its engines, datasets, and
benchmarks can be reused and scrutinized.

# Functionality

- **Modality engines.** Independently runnable URL, email-text, and threat-intelligence
  services, each with a documented score envelope, plus designed stubs for header and
  attachment analysis.
- **Decision fusion.** A configurable aggregator and decision engine that combine channel
  scores (calibrated probabilistic-OR, weighted average, or hand-set noisy-OR) into a
  verdict with campaign fingerprinting.
- **Reproducible data and benchmarks.** Released supervised corpora, a campaign-aware
  splitter, a held-out real-phishing slice, and a whole-system benchmark.
- **Observability.** Prometheus, OpenTelemetry/Jaeger, and structured logging across all
  services, with auto-provisioned Grafana dashboards.
- **Deployment.** A Docker Compose demonstration profile and Kubernetes manifests; trained
  models exported to ONNX for CPU serving.

# Acknowledgements

We thank Dr. Mohamed Samir for his academic supervision, and the engineers at Zinad for
advisory support. The authors received no financial support for this work.

# References
