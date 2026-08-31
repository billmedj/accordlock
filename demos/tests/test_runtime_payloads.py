import tempfile
import time
import unittest
from pathlib import Path

from accordlock_demos.canonical import json_digest, length_prefixed_domain_digest
from accordlock_demos.runtime import (
    TASK_POLICY_DOMAIN,
    build_approved_session,
    build_proposal,
    canonical_workspace,
)


class RuntimePayloadTests(unittest.TestCase):
    def test_session_and_plan_commit_the_exact_objective_arguments_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session = build_approved_session(canonical_workspace(Path(temporary)), int(time.time()))
        self.assertEqual(
            session["task_policy_hash"],
            length_prefixed_domain_digest(TASK_POLICY_DOMAIN, session["task_policy"]),
        )
        proposal = build_proposal(
            session,
            extension_id="developer",
            tool_name="read",
            arguments={"path": ".env", "line": None, "limit": None},
            checkpoint_text="untrusted instruction",
            tool_call_id="call-1",
            recorded_at=1,
        )
        self.assertEqual(proposal["arguments_sha256"], json_digest(proposal["arguments"]))
        checkpoint = proposal["agent_plan_checkpoint"]
        self.assertEqual(checkpoint["material_sha256"], json_digest(checkpoint["material"]))
        self.assertEqual(checkpoint["material"]["tool_requests"][0]["id"], "call-1")


if __name__ == "__main__":
    unittest.main()
