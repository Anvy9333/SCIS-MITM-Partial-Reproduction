# SCIS MITM Partial Reproduction

Reduced experimental reproduction of the SCIS-based meet-in-the-middle pipeline from:

> Chen, Guo, List, Shi, Zhang: *Scrutinizing the Security of AES-Based Hashing and One-Way Functions*, ASIACRYPT 2025

This code was produced as part of the INFO-F514 course project at ULB.

---

## What this is

The paper introduces **Single-Color Initial Structure (SCIS)**, a technique that solves the neutral word generation bottleneck in MITM attacks on AES, enabling the first classical one-block collision attack on 7-round AES-MMO/MP at complexity $2^{60}$.

We do not claim a full reproduction of the 7-round attack (which requires $2^{40}$ operations and ~11 hours on an i9). Instead, we validate the core mechanisms of the SCIS-MITM pipeline at reduced scale ($2^{24}$ operations, a few minutes on any modern CPU).

---

## Files

```
.
├── aes.c       # AES-128 encryption and AES-MMO compression function
├── aes.h       # Header
└── scis.c      # Four validation experiments
```

---

## Build and run

```bash
gcc aes.c scis.c -o scis
./scis
```
## Experiments

### Experiment 1 — Partial match filter rate
Enumerates $2^{24}$ messages with fixed gec/gic and checks how many satisfy `H[4] = 0x00`. Expected: ~$2^{16}$ survivors (1/256 rate).

### Experiment 2 — Tblue indexing uniformity
For each of the 256 gic values, checks that blue candidates are distributed uniformly across buckets. Expected: ~256 entries per bucket.

### Experiment 3 — Full reduced pipeline
Runs the complete SCIS-MITM pipeline at reduced scale: builds $T_{blue}$, enumerates red candidates, counts surviving pairs. Expected: ~$2^{dB+dR-dM} = 2^8 = 256$ total candidates.

### Experiment 4 — Filter rate scaling with dM *(personal contribution)*
The paper always uses $d_M = 8$. We verify that the acceptance rate scales as $2^{-d_M}$ by testing both $d_M = 8$ and $d_M = 16$. This directly validates the generality of the complexity formula from Section 4.3, which the paper itself never tests experimentally.

| dM | Expected | Observed | Ratio |
|----|----------|----------|-------|
| 8  | 65536    | 65707    | 1.003 |
| 16 | 256      | 268      | 1.047 |

Both ratios are close to 1.000, confirming $2^{-d_M}$ scaling holds.

---

## Parameters vs the paper

| Parameter | Paper | This code |
|-----------|-------|-----------|
| Enumeration | $2^{40}$ | $2^{24}$ |
| Runtime | ~11h (i9 3.6GHz) | ~5 min |
| dB / dR / dM | 8 / 8 / 8 | 8 / 8 / 8 |
| AES-MMO | full | full  |
| Filter logic | identical | identical |
| gec/gic structure | identical | identical |

The parameters are reduced but the pipeline logic is kept identical to the paper.

---


INFO-F514 — Protocols, Cryptanalysis and Mathematical Cryptology  
Université Libre de Bruxelles, 2024–2025
