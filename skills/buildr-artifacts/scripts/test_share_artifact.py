#!/usr/bin/env python3
"""Tests for Buildr artifact sharing configuration."""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).with_name("share_artifact.py")
SPEC = importlib.util.spec_from_file_location("share_artifact", SCRIPT_PATH)
share_artifact = importlib.util.module_from_spec(SPEC)
sys.modules["share_artifact"] = share_artifact
assert SPEC.loader is not None
SPEC.loader.exec_module(share_artifact)


class EnvVarTest(unittest.TestCase):
    def test_aws_cli_env_uses_artifact_prefixed_aws_vars(self) -> None:
        env = share_artifact.aws_cli_env(
            {
                "ARTIFACT_AWS_REGION": "us-west-2",
                "ARTIFACT_AWS_ACCESS_KEY_ID": "artifact-key",
                "ARTIFACT_AWS_SECRET_ACCESS_KEY": "artifact-secret",
                "ARTIFACT_AWS_SESSION_TOKEN": "artifact-token",
            }
        )

        self.assertEqual(env["AWS_REGION"], "us-west-2")
        self.assertEqual(env["AWS_ACCESS_KEY_ID"], "artifact-key")
        self.assertEqual(env["AWS_SECRET_ACCESS_KEY"], "artifact-secret")
        self.assertEqual(env["AWS_SESSION_TOKEN"], "artifact-token")

    def test_aws_cli_env_defaults_region_when_artifact_region_is_unset(self) -> None:
        env = share_artifact.aws_cli_env({})

        self.assertEqual(env["AWS_REGION"], "us-east-1")

    def test_aws_cli_env_preserves_normal_aws_region_as_fallback(self) -> None:
        env = share_artifact.aws_cli_env({"AWS_REGION": "eu-central-1"})

        self.assertEqual(env["AWS_REGION"], "eu-central-1")

    def test_bucket_and_base_url_use_artifact_prefix(self) -> None:
        with temporary_env(
            ARTIFACT_S3_BUCKET="custom-bucket",
            ARTIFACT_BASE_URL="https://cdn.example.test/",
        ):
            self.assertEqual(share_artifact.bucket_name(), "custom-bucket")
            self.assertEqual(share_artifact.base_url(), "https://cdn.example.test")


class temporary_env:
    def __init__(self, **updates: str) -> None:
        self.updates = updates
        self.originals: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for key, value in self.updates.items():
            self.originals[key] = os.environ.get(key)
            os.environ[key] = value

    def __exit__(self, *args: object) -> None:
        for key, value in self.originals.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
