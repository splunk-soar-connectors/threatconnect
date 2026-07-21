**Unreleased**

* Refresh development validation tooling. [PSAAS-32854]

* Verify ThreatConnect server certificates by default for new and existing assets without an explicit setting.
* Escape hunt-action values before using them in ThreatConnect Query Language filters.
* Retain the ThreatConnect polling checkpoint when an indicator cannot be saved.
* Retrieve all ThreatConnect indicator pages needed for each polling window.
* Ingest malformed CIDR and Registry Key indicators without halting later poll results. [PSAAS-32854]
