# Awesome Fintech AI Infrastructure

> Curated list of resources for AI infrastructure in regulated financial environments.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

## Articles

Operator perspective on running AI infrastructure in regulated environments:

- [vSAN for Mixed Workloads: OSA vs ESA Policy Design](https://errorbudget.io/articles/vsan-mixed-workloads-policy-design)
- [vGPU on Dell VxRail: 18 Months in Production](https://errorbudget.io/articles/vgpu-dell-vxrail-production-patterns)
- [DCGM Monitoring at Scale: The Alerts That Actually Matter](https://errorbudget.io/articles/dcgm-monitoring-at-scale)
- [19 Auditor Questions for AI Infrastructure](https://errorbudget.io/articles/auditor-questions-ai-deployment)
- [NVAIE Licensing Math Nobody Talks About](https://errorbudget.io/articles/nvaie-licensing-math)
- [HPE Synergy GPU Expansion Patterns](https://errorbudget.io/articles/hpe-synergy-gpu-expansion)
- [AI Memory Crunch and Infrastructure Budgets](https://errorbudget.io/articles/ai-memory-crunch-infrastructure-budgets)
- [Fintech Backup Architecture Patterns](https://errorbudget.io/articles/fintech-backup-architecture-patterns)
- [VMware Private AI Foundation: Operator Notes](https://errorbudget.io/articles/vmware-private-ai-fintech-notes)

## Free Tools

Browser-based calculators and utilities:

- [vSAN Capacity Calculator](https://tools.errorbudget.io/vsan) — Model usable capacity under OSA/ESA with different RAID policies
- [Error Budget Calculator](https://tools.errorbudget.io/error-budget) — Convert SLO targets to downtime budgets
- [Subnet Calculator](https://tools.errorbudget.io/subnet)
- [JWT Decoder](https://tools.errorbudget.io/jwt)
- [JSON Formatter](https://tools.errorbudget.io/json)
- [Base64 Encoder/Decoder](https://tools.errorbudget.io/base64)
- [Hash Generator](https://tools.errorbudget.io/hash)
- [Timestamp Converter](https://tools.errorbudget.io/timestamp)
- [HTTP Status Codes](https://tools.errorbudget.io/http-status)
- [Common Ports Reference](https://tools.errorbudget.io/ports)

## Topics

### VMware Infrastructure
- vSAN OSA (Original Storage Architecture)
- vSAN ESA (Express Storage Architecture)
- vSphere clustering for AI workloads
- VMware Private AI Foundation
- Storage policy design

### NVIDIA AI Stack
- NVAIE (NVIDIA AI Enterprise) licensing
- vGPU vs MIG partitioning strategies
- DCGM monitoring
- GPU allocation for multi-tenant environments
- A100, H100, H200 deployment patterns

### Hardware Platforms
- Dell VxRail with vGPU
- HPE Synergy 12000 frame
- HPE ProLiant Gen11/Gen12 with PCIe GPUs

### Regulated Environments
- PCI DSS for AI infrastructure
- ISO 27001 considerations
- Banking regulatory compliance
- Audit defense patterns
- Data classification for AI training

### Operations
- Backup architecture (CDP, snapshots, air-gap)
- Capacity planning for mixed workloads
- Memory and storage procurement in constrained markets
- Incident response for AI infrastructure

## Newsletter

Monthly operator notes on AI infrastructure: [Subscribe](https://buttondown.com/duc)

## Contributing

Open an issue or pull request to suggest additional resources. Focus on operator perspective, not vendor marketing.

## License

[MIT](LICENSE) — Free to share and adapt.

---

Maintained by [@errorbudgetio](https://twitter.com/errorbudgetio) at [errorbudget.io](https://errorbudget.io)
