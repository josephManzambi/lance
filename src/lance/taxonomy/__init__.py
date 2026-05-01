"""External benchmark taxonomies that LANCE Findings can be cross-referenced with.

This package holds optional metadata schemas that map LANCE results to
third-party taxonomies (e.g. the ART benchmark from Zou et al., arXiv:2507.20526).
The primary framework mappings (OWASP ASI, MITRE ATLAS, CSA AICM) live in
``lance.mappings`` and are loaded directly into ``FrameworkMapping``; this
package is for richer, structured cross-references.
"""
