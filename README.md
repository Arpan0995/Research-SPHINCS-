# SPHINCS+ Experiments (Java)

This repository contains a Java/Maven project that demonstrates **practical ways to mitigate the main pain points of the SPHINCS+ digital signature algorithm**, particularly the large signature size and slower signing speeds compared with classical algorithms such as RSA or ECDSA.  The code includes reproducible experiments and a discussion of results.

## Background and Motivation

SPHINCS+ is a stateless, hash‑based signature scheme designed to remain secure against quantum computers.  As of August 2024 it has been finalized as **FIPS 205**, making it an officially approved digital signature standard.  Unlike traditional signatures, SPHINCS+ signatures are *large*—a level‑1 (`128s`) signature is 7 856 bytes, while a level‑5 (`256f`) signature is 49 856 bytes.  Key sizes are small (32–64 bytes public, 64–128 bytes secret), but the signature size and signing cost can be problematic for bandwidth‑constrained applications or protocols that embed signatures in certificates or tokens.

### The `s` vs `f` trade‑off

SPHINCS+ defines two profiles for each security level:

* **`s` (small) variants** – produce *smaller* signatures but have a slower signing operation.
* **`f` (fast) variants** – sign faster at the cost of significantly larger signatures.

For example, at level 1 the `128s` signature is 7 856 bytes while the `128f` signature is 17 088 bytes; verification cost is similar for both.  Choosing the right profile is an important design decision when integrating SPHINCS+ into systems.

## Experiments in this repository

The project demonstrates two complementary approaches to reduce the cost of using SPHINCS+ in applications:

1. **Parameter benchmarking** – measure the key sizes, signature sizes, and signing/verification times for all common SPHINCS+ parameter sets (`128s`, `128f`, `192s`, `192f`, `256s`, `256f`, and their SHAKE/SHA2 variants).  The `ParameterBenchmark` class produces a CSV file with the results and an optional bar chart (if XChart is available on the classpath).  It also compresses signatures with gzip to illustrate that hash‑based signatures are essentially incompressible.

2. **Merkle batch signing** – demonstrate how to amortize the cost of a SPHINCS+ signature when signing many messages together.  Messages are hashed into a binary Merkle tree using SHA‑256, the **root** is signed with SPHINCS+, and each message carries the shared signature plus its authentication path.  When batching, the per‑message overhead becomes `(signature_length / N) + (log₂ N × 32)` bytes.  For example, with `N = 64` and the `128s` parameter set (7 856 bytes), the average cost per message is roughly `(7856/64) + 6×32 = 315` bytes.

### Running the experiments

Java 17+ and Maven are required.  To build and run all experiments:

```
mvn -q -DskipTests package
mvn -q exec:java
# results will be written into the `results/` directory
```

After execution you will find:

* `results/sphincs_param_bench.csv` – CSV table of key lengths, signature lengths, and signing/verification timings for each parameter set.
* `results/sig_sizes.png` – Bar chart of signature sizes (if the XChart library is on the classpath).
* `results/merkle_batching_summary.csv` – Summary of per‑message overhead for the batch signing demonstration.

## How this project mitigates SPHINCS+ issues

* **Reduce signature size** – choose the `s` variants when possible; use Merkle batch signing to amortize one SPHINCS+ signature across many messages; avoid embedding signatures inline when a detached signature or reference suffices.
* **Manage signing cost** – use the `f` variants for high‑throughput signers; design systems that verify more often than they sign (verification is relatively inexpensive compared with signing for SPHINCS+).
* **Use compact encodings** – encode signatures in binary formats (e.g., COSE/CBOR) rather than verbose textual formats; consider carrying only the signature and a hash of the message when possible.

## Repository structure

```
sphincsplus-experiments-java/
├── pom.xml                    # Maven build file
├── README.md                  # This description
└── src/main/java/dev/arpan/sphincs/
    ├── ExperimentsRunner.java # Entrypoint that runs all experiments
    ├── ParameterBenchmark.java# Benchmark of key/signature sizes and timings
    ├── MerkleBatchSigner.java # Batch/Merkle signing demonstration
    └── Charts.java            # Utility to generate a bar chart of signature sizes
```

The `results` directory will be created automatically when running the experiments.  Feel free to extend the experiments, integrate other compression schemes, or explore additional mitigation strategies.
