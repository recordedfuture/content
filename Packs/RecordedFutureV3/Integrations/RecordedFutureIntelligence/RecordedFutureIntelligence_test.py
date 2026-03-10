from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import pytest

import RecordedFutureIntelligence


DEFAULT_INTEGRATION_PARAMS = {
    "ip_suspicious_threshold": 25,
    "ip_bad_threshold": 65,
    "domain_suspicious_threshold": 25,
    "domain_bad_threshold": 65,
    "url_suspicious_threshold": 25,
    "url_bad_threshold": 65,
    "file_suspicious_threshold": 25,
    "file_bad_threshold": 65,
    "cve_suspicious_threshold": 25,
    "cve_bad_threshold": 65,
    "collective_insights": "On",
    "integrationReliability": "B - Usually reliable",
}


@dataclass
class StubLookupClient:
    lookup_response: dict[str, Any]
    captured_lookup_payloads: list[dict[str, Any]] = field(
        default_factory=list
    )
    whoami_error: Exception | None = None

    def lookup_reputation(
        self,
        *,
        lookup_payload: dict[str, Any],
    ) -> dict[str, Any]:
        self.captured_lookup_payloads.append(lookup_payload)
        return self.lookup_response

    def whoami(self) -> dict[str, Any]:
        if self.whoami_error is not None:
            raise self.whoami_error
        return {"status": "ok"}


class NotFoundLookupClient(RecordedFutureIntelligence.Client):
    def __init__(self) -> None:
        super().__init__(
            base_url="https://example.com",
            verify=True,
            headers={},
            proxy=False,
        )

    def _http_request(self, **kwargs):  # pyright: ignore[reportIncompatibleMethodOverride]
        del kwargs
        raise RecordedFutureIntelligence.DemistoException("404 Not Found")


def _build_stub_lookup_client(
    *,
    lookup_response: dict[str, Any],
    whoami_error: Exception | None = None,
) -> StubLookupClient:
    return StubLookupClient(
        lookup_response=lookup_response,
        whoami_error=whoami_error,
    )


def _get_indicator_score(*, indicator: Any) -> Any:
    dbot_score = getattr(indicator, "dbot_score", None)
    return getattr(dbot_score, "score", None)


def test_lookup_command_builds_backend_payload_with_cleaned_calling_context() -> (
    None
):
    demisto_params = {
        **DEFAULT_INTEGRATION_PARAMS,
        "collective_insights": "off",
        "server_url": "https://api.recordedfuture.com/gw/xsoar/",
        "token": "secret-token",
        "token_credential": {"password": "secret-credential"},
        "proxy": True,
        "insecure": False,
    }
    stub_lookup_client = _build_stub_lookup_client(
        lookup_response={
            "result_actions": [
                {
                    "CommandResults": {
                        "outputs": {},
                        "raw_response": {},
                        "readable_output": "No records found",
                    }
                }
            ]
        }
    )

    command_results = RecordedFutureIntelligence.lookup_command(
        client=cast(RecordedFutureIntelligence.Client, stub_lookup_client),
        demisto_params=demisto_params,
        command="ip",
        command_args={"ip": "8.8.8.8", "collective_insights": "on"},
        calling_context={
            "args": {"ip": "8.8.8.8"},
            "context": {
                "Incidents": [
                    {"id": "1", "name": "incident", "type": "type", "x": 1}
                ],
                "ExecutionContext": {"internal": "remove"},
            },
        },
    )

    assert len(command_results) == 1
    assert stub_lookup_client.captured_lookup_payloads == [
        {
            "demisto_command": "ip",
            "demisto_args": {"ip": "8.8.8.8", "collective_insights": "on"},
            "demisto_params": {
                "collective_insights": "off",
                "server_url": "https://api.recordedfuture.com/gw/xsoar/",
                "token": "secret-token",
                "token_credential": {"password": "secret-credential"},
                "proxy": True,
                "insecure": False,
                "ip_suspicious_threshold": 25,
                "ip_bad_threshold": 65,
                "domain_suspicious_threshold": 25,
                "domain_bad_threshold": 65,
                "url_suspicious_threshold": 25,
                "url_bad_threshold": 65,
                "file_suspicious_threshold": 25,
                "file_bad_threshold": 65,
                "cve_suspicious_threshold": 25,
                "cve_bad_threshold": 65,
                "integrationReliability": "B - Usually reliable",
            },
            "callingContext": {
                "args": {"ip": "8.8.8.8"},
                "context": {
                    "Incidents": [
                        {"id": "1", "name": "incident", "type": "type"}
                    ]
                },
            },
        }
    ]


def test_lookup_command_returns_no_results_entry_for_backend_404() -> None:
    command_results = RecordedFutureIntelligence.lookup_command(
        client=NotFoundLookupClient(),
        demisto_params=DEFAULT_INTEGRATION_PARAMS,
        command="ip",
        command_args={"ip": "8.8.8.8"},
        calling_context=None,
    )

    assert len(command_results) == 1
    assert command_results[0].readable_output == "No results found."


def test_process_lookup_response_creates_ip_indicator_from_backend_payload() -> (
    None
):
    command_results = RecordedFutureIntelligence._process_lookup_response(
        lookup_response={
            "result_actions": [
                {
                    "create_indicator": {
                        "common_class": "IP",
                        "constructor_kwargs": {
                            "ip": "8.8.8.8",
                            "description": "Test description",
                        },
                        "dbot_score": {
                            "indicator": "8.8.8.8",
                            "indicator_type": "ip",
                            "integration_name": "Recorded Future Intelligence",
                            "score": RecordedFutureIntelligence.Common.DBotScore.SUSPICIOUS,
                            "reliability": "B - Usually reliable",
                        },
                    },
                    "CommandResults": {
                        "outputs_prefix": "RecordedFuture.IP",
                        "outputs": {"name": "8.8.8.8"},
                        "raw_response": {},
                    },
                }
            ]
        }
    )

    created_indicator = cast(Any, command_results[0].indicator)
    assert created_indicator.ip == "8.8.8.8"
    assert created_indicator.description == "Test description"
    assert (
        _get_indicator_score(indicator=created_indicator)
        == RecordedFutureIntelligence.Common.DBotScore.SUSPICIOUS
    )


def test_process_lookup_response_creates_cve_indicator_from_backend_payload() -> (
    None
):
    command_results = RecordedFutureIntelligence._process_lookup_response(
        lookup_response={
            "result_actions": [
                {
                    "create_indicator": {
                        "common_class": "CVE",
                        "constructor_kwargs": {
                            "id": "CVE-2025-0001",
                            "cvss": 9.8,
                            "published": "2025-01-01T00:00:00Z",
                            "modified": "2025-01-02T00:00:00Z",
                            "description": "Remote code execution",
                            "cvss_version": "3.1",
                            "cvss_score": 9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        "dbot_score": {
                            "indicator": "CVE-2025-0001",
                            "indicator_type": "cve",
                            "integration_name": "Recorded Future Intelligence",
                            "score": RecordedFutureIntelligence.Common.DBotScore.BAD,
                            "malicious_description": "Score above 65",
                            "reliability": "B - Usually reliable",
                        },
                    },
                    "CommandResults": {
                        "outputs_prefix": "RecordedFuture.CVE",
                        "outputs": {
                            "name": "CVE-2025-0001",
                            "portalUrl": "https://app.recordedfuture.com/portal/intelligence-card/vulnerability:CVE-2025-0001/overview?utm_source=xsoar",
                        },
                        "raw_response": {},
                        "readable_output": "ok",
                        "outputs_key_field": "name",
                    },
                }
            ]
        }
    )

    created_indicator = cast(Any, command_results[0].indicator)
    assert created_indicator.id == "CVE-2025-0001"
    assert created_indicator.cvss == 9.8
    assert created_indicator.cvss_score == 9.8
    assert created_indicator.cvss_version == "3.1"
    assert (
        created_indicator.cvss_vector
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert created_indicator.published == "2025-01-01T00:00:00Z"
    assert created_indicator.modified == "2025-01-02T00:00:00Z"
    assert (
        _get_indicator_score(indicator=created_indicator)
        == RecordedFutureIntelligence.Common.DBotScore.BAD
    )
    assert (
        command_results[0].outputs["portalUrl"]
        == "https://app.recordedfuture.com/portal/intelligence-card/vulnerability:CVE-2025-0001/overview?utm_source=xsoar"
    )


def test_process_lookup_response_preserves_zero_cve_cvss_values() -> None:
    command_results = RecordedFutureIntelligence._process_lookup_response(
        lookup_response={
            "result_actions": [
                {
                    "create_indicator": {
                        "common_class": "CVE",
                        "constructor_kwargs": {
                            "id": "CVE-2025-9999",
                            "cvss": 0.0,
                            "published": "",
                            "modified": "",
                            "description": "No impact",
                            "cvss_score": 0.0,
                        },
                        "dbot_score": {
                            "indicator": "CVE-2025-9999",
                            "indicator_type": "cve",
                            "integration_name": "Recorded Future Intelligence",
                            "score": RecordedFutureIntelligence.Common.DBotScore.NONE,
                        },
                    },
                    "CommandResults": {
                        "outputs": {"name": "CVE-2025-9999"},
                        "raw_response": {},
                    },
                }
            ]
        }
    )

    created_indicator = cast(Any, command_results[0].indicator)
    assert created_indicator.cvss == 0.0
    assert created_indicator.cvss_score == 0.0
    assert (
        _get_indicator_score(indicator=created_indicator)
        == RecordedFutureIntelligence.Common.DBotScore.NONE
    )


def test_process_lookup_response_supports_command_results_only_action() -> (
    None
):
    command_results = RecordedFutureIntelligence._process_lookup_response(
        lookup_response={
            "result_actions": [
                {
                    "CommandResults": {
                        "outputs": {},
                        "raw_response": {},
                        "readable_output": "No records found",
                    }
                }
            ]
        }
    )

    assert len(command_results) == 1
    assert command_results[0].readable_output == "No records found"
    assert command_results[0].indicator is None


def test_process_lookup_response_ignores_unknown_backend_fields() -> None:
    command_results = RecordedFutureIntelligence._process_lookup_response(
        lookup_response={
            "result_actions": [
                {
                    "create_indicator": {
                        "common_class": "Domain",
                        "constructor_kwargs": {
                            "domain": "example.com",
                            "description": "Test description",
                            "relationships": [
                                {
                                    "name": "related-to",
                                    "entityA": "example.com",
                                    "entityAType": "Domain",
                                    "entityB": "1.1.1.1",
                                    "entityBType": "IP",
                                }
                            ],
                            "extra_constructor_field": "ignored",
                        },
                        "dbot_score": {
                            "indicator": "example.com",
                            "indicator_type": "domain",
                            "integration_name": "Recorded Future Intelligence",
                            "score": RecordedFutureIntelligence.Common.DBotScore.BAD,
                            "extra_score_field": "ignored",
                        },
                        "extra_create_indicator_field": True,
                    },
                    "CommandResults": {
                        "outputs": {"name": "example.com"},
                        "raw_response": {},
                        "relationships": [
                            {
                                "name": "related-to",
                                "entityA": "example.com",
                                "entityAType": "Domain",
                                "entityB": "1.1.1.1",
                                "entityBType": "IP",
                            }
                        ],
                        "extra_command_results_field": "ignored",
                    },
                    "extra_action_field": {"ignored": True},
                }
            ],
            "extra_response_field": {"ignored": True},
        }
    )

    created_indicator = cast(Any, command_results[0].indicator)
    assert created_indicator.domain == "example.com"
    assert created_indicator.description == "Test description"
    assert created_indicator.relationships is None
    assert (
        _get_indicator_score(indicator=created_indicator)
        == RecordedFutureIntelligence.Common.DBotScore.BAD
    )
    assert command_results[0].outputs == {"name": "example.com"}
    assert command_results[0].relationships is None


def test_process_lookup_response_raises_for_unsupported_indicator_class() -> (
    None
):
    with pytest.raises(RecordedFutureIntelligence.DemistoException):
        RecordedFutureIntelligence._process_lookup_response(
            lookup_response={
                "result_actions": [
                    {
                        "create_indicator": {
                            "common_class": "Vulnerability",
                            "constructor_kwargs": {},
                            "dbot_score": {
                                "indicator": "CVE-2025-0001",
                                "indicator_type": "cve",
                                "integration_name": "Recorded Future Intelligence",
                                "score": RecordedFutureIntelligence.Common.DBotScore.BAD,
                            },
                        },
                        "CommandResults": {
                            "outputs": {},
                            "raw_response": {},
                        },
                    }
                ]
            }
        )


def test_process_lookup_response_raises_when_result_actions_is_not_a_list() -> (
    None
):
    with pytest.raises(RecordedFutureIntelligence.DemistoException):
        RecordedFutureIntelligence._process_lookup_response(
            lookup_response={"result_actions": {"unexpected": True}}
        )


def test_test_module_command_returns_backend_error_message() -> None:
    stub_lookup_client = _build_stub_lookup_client(
        lookup_response={},
        whoami_error=Exception("HTTP 401 Unauthorized"),
    )

    with pytest.raises(RecordedFutureIntelligence.DemistoException) as error:
        RecordedFutureIntelligence.test_module_command(
            client=cast(RecordedFutureIntelligence.Client, stub_lookup_client)
        )

    assert str(error.value) == "Failed due to - HTTP 401 Unauthorized"
