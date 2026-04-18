"""AWS deployment context probe.

Given an IAM role ARN that an agent assumes, analyze the effective permissions
and identify exposed resources. Read-only — never mutates AWS state.

Status: stub. Implementation pending v0.1.
"""

from __future__ import annotations

from lance.models.finding import DeploymentContext


async def probe_iam_role(role_arn: str) -> DeploymentContext:
    """Probe an IAM role for blast-radius analysis.

    Uses boto3 with the caller's default credentials. Requires iam:GetRole,
    iam:ListAttachedRolePolicies, iam:GetRolePolicy, iam:SimulatePrincipalPolicy.
    """
    raise NotImplementedError("probe_iam_role — pending v0.1.")
