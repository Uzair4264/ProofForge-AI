"""Claim-to-evidence provenance graph (the Gap-1 DAG).

Nodes are evidence ids and claim ids; edges are ``ProvenanceLink`` objects,
always directed Claim -> Evidence. In v0 claims depend only on evidence (never
on other claims), so the graph is trivially acyclic; ``cycle_check`` still
guards against accidental claim->claim edges.
"""

from __future__ import annotations

from ..core.types import Claim, Evidence, ProvenanceLink


class ProvenanceGraph:
    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}
        self._claims: dict[str, Claim] = {}
        self._links: list[ProvenanceLink] = []

    # -- construction ------------------------------------------------------ #
    def add_evidence(self, evidence: Evidence) -> None:
        self._evidence[evidence.id] = evidence

    def add_claim(self, claim: Claim) -> None:
        self._claims[claim.id] = claim

    def add_link(self, link: ProvenanceLink) -> None:
        self._links.append(link)

    @classmethod
    def build(
        cls,
        evidence: list[Evidence],
        claims: list[Claim],
        links: list[ProvenanceLink] | None = None,
    ) -> "ProvenanceGraph":
        graph = cls()
        for ev in evidence:
            graph.add_evidence(ev)
        for cl in claims:
            graph.add_claim(cl)
        # Derive links from claim.evidence_ids if none supplied explicitly.
        if links:
            for link in links:
                graph.add_link(link)
        else:
            for cl in claims:
                for ev_id in cl.evidence_ids:
                    graph.add_link(ProvenanceLink(claim_id=cl.id, evidence_id=ev_id))
        return graph

    # -- queries ----------------------------------------------------------- #
    def is_orphan(self, claim: Claim) -> bool:
        return len(claim.evidence_ids) == 0

    def orphans(self) -> list[Claim]:
        return [c for c in self._claims.values() if self.is_orphan(c)]

    def evidence_for(self, claim: Claim) -> list[Evidence]:
        return [self._evidence[e] for e in claim.evidence_ids if e in self._evidence]

    def claims_using(self, evidence: Evidence) -> list[Claim]:
        return [c for c in self._claims.values() if evidence.id in c.evidence_ids]

    def missing_evidence_refs(self) -> list[tuple[str, str]]:
        """Return (claim_id, evidence_id) pairs that reference unknown evidence."""
        missing: list[tuple[str, str]] = []
        for claim in self._claims.values():
            for ev_id in claim.evidence_ids:
                if ev_id not in self._evidence:
                    missing.append((claim.id, ev_id))
        return missing

    def cycle_check(self) -> bool:
        """Return True if the graph is acyclic.

        Any link whose target is a claim id implies a claim->claim dependency,
        which is disallowed in v0 and reported as a cycle risk.
        """
        for link in self._links:
            if link.evidence_id in self._claims:
                return False
        return True

    @property
    def claims(self) -> list[Claim]:
        return list(self._claims.values())

    @property
    def evidence(self) -> list[Evidence]:
        return list(self._evidence.values())
