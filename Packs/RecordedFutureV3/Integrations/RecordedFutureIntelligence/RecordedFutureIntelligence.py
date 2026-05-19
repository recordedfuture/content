import platform
from enum import Enum
from typing import NotRequired, Required, TypedDict

import requests  # noqa: F401

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

# flake8: noqa: F405

STATUS_TO_RETRY = [500, 501, 502, 503, 504]
LOOKUP_REPUTATION_PATH = "/v3/lookup/reputation"

__version__ = "1.0.0"
INVALID_LOOKUP_RESPONSE_MESSAGE = "Invalid lookup response."


class XsoarIndicatorClass(str, Enum):
    IP = "IP"
    DOMAIN = "Domain"
    URL = "URL"
    FILE = "File"
    CVE = "CVE"


class BaseIndicatorConstructorKwargsPayload(TypedDict, total=False):
    description: str | None


class IPIndicatorConstructorKwargsPayload(
    BaseIndicatorConstructorKwargsPayload, total=False
):
    ip: str | None


class DomainIndicatorConstructorKwargsPayload(
    BaseIndicatorConstructorKwargsPayload, total=False
):
    domain: str | None


class URLIndicatorConstructorKwargsPayload(
    BaseIndicatorConstructorKwargsPayload, total=False
):
    url: str | None


class FileIndicatorConstructorKwargsPayload(
    BaseIndicatorConstructorKwargsPayload, total=False
):
    md5: str | None
    sha1: str | None
    sha256: str | None
    sha512: str | None


class CVEIndicatorConstructorKwargsPayload(
    BaseIndicatorConstructorKwargsPayload, total=False
):
    id: str | None
    cvss: float | int | str | None
    published: str | None
    modified: str | None
    cvss_version: str | None
    cvss_score: float | int | str | None
    cvss_vector: str | None


CommonIndicatorConstructorKwargsPayload = (
    IPIndicatorConstructorKwargsPayload
    | DomainIndicatorConstructorKwargsPayload
    | URLIndicatorConstructorKwargsPayload
    | FileIndicatorConstructorKwargsPayload
    | CVEIndicatorConstructorKwargsPayload
)


class DBotScorePayload(TypedDict):
    indicator: Required[str]
    indicator_type: Required[str]
    integration_name: Required[str]
    score: Required[int]
    malicious_description: NotRequired[str | None]
    reliability: NotRequired[str | None]
    message: NotRequired[str | None]


class CommandResultsPayload(TypedDict, total=False):
    outputs_prefix: str
    raw_response: dict[str, Any]
    readable_output: str
    outputs_key_field: str
    ignore_auto_extract: bool


class CreateIndicatorActionPayload(TypedDict):
    common_class: Required[str]
    constructor_kwargs: Required[CommonIndicatorConstructorKwargsPayload]
    dbot_score: Required[DBotScorePayload]


class LookupResultActionPayload(TypedDict):
    CommandResults: Required[CommandResultsPayload]
    create_indicator: NotRequired[CreateIndicatorActionPayload | None]


class LookupResponsePayload(TypedDict):
    result_actions: Required[list[LookupResultActionPayload]]


class LookupReputationNoResultsError(DemistoException):
    pass


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _extract_api_token(
    *,
    demisto_params: dict[str, Any],
) -> str | None:
    token_credential = demisto_params.get("token_credential")
    token = (
        token_credential.get("password")
        if isinstance(token_credential, dict)
        else demisto_params.get("token")
    )
    if not isinstance(token, str):
        return None

    stripped_token = token.strip()
    return stripped_token or None


def _build_user_agent_header() -> str:
    demisto_version = demisto.demistoVersion()
    xsoar_version = "unknown"
    if isinstance(demisto_version, dict):
        version = demisto_version.get("version")
        if isinstance(version, str) and version.strip():
            xsoar_version = version.strip()

    return (
        f"RecordedFutureIntelligence/{__version__} "
        f"(Cortex_XSOAR_{xsoar_version}; {platform.platform()})"
    )


def _is_collective_insight_enabled(
    *,
    demisto_params: dict[str, Any],
    command_args: dict[str, Any],
) -> bool:
    command_setting = command_args.get("collective_insights")
    if isinstance(command_setting, str):
        normalized_command_setting = command_setting.strip().lower()
        if normalized_command_setting == "on":
            return True
        if normalized_command_setting == "off":
            return False

    integration_setting = demisto_params.get("collective_insights", "On")
    return str(integration_setting).strip().lower() == "on"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class Client(BaseClient):
    def whoami(self) -> dict:
        return self._http_request(
            method="get",
            url_suffix="info/whoami",
            timeout=60,
        )

    def lookup_reputation(
        self,
        *,
        lookup_payload: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            backend_response = self._http_request(
                method="post",
                url_suffix=LOOKUP_REPUTATION_PATH,
                json_data=lookup_payload,
                timeout=120,
                retries=3,
                status_list_to_retry=STATUS_TO_RETRY,
            )
        except DemistoException as err:
            if _is_lookup_not_found_error(error=err):
                raise LookupReputationNoResultsError(
                    "No results found."
                ) from err
            raise

        if not isinstance(backend_response, dict):
            raise DemistoException(INVALID_LOOKUP_RESPONSE_MESSAGE)
        if backend_response.get("return_error"):
            return_error(**backend_response["return_error"])
        return backend_response


def _is_lookup_not_found_error(*, error: DemistoException) -> bool:
    return "404" in str(error)


# ---------------------------------------------------------------------------
# Lookup payload
# ---------------------------------------------------------------------------


def _clean_calling_context(
    *,
    calling_context: dict[str, Any],
) -> dict[str, Any]:
    cleaned_calling_context = {
        key: calling_context[key]
        for key in ("args", "command", "params", "context")
        if key in calling_context
    }

    context = cleaned_calling_context.get("context")
    if not isinstance(context, dict):
        cleaned_calling_context.pop("context", None)
        return cleaned_calling_context

    cleaned_context = {
        key: context[key]
        for key in ("Incidents", "IntegrationInstance", "ParentEntry")
        if key in context
    }

    incidents = cleaned_context.get("Incidents")
    if isinstance(incidents, list):
        cleaned_context["Incidents"] = [
            {
                key: incident[key]
                for key in ("id", "name", "type")
                if key in incident
            }
            for incident in incidents
            if isinstance(incident, dict)
        ]

    parent_entry = cleaned_context.get("ParentEntry")
    if isinstance(parent_entry, dict):
        cleaned_context["ParentEntry"] = {
            key: parent_entry[key]
            for key in ("entryTask", "scheduled", "recurrent")
            if key in parent_entry
        }

    cleaned_calling_context["context"] = cleaned_context
    return cleaned_calling_context


def _add_calling_context_to_lookup_payload(
    *,
    demisto_params: dict[str, Any],
    lookup_payload: dict[str, Any],
    command_args: dict[str, Any],
    calling_context: dict[str, Any] | None,
) -> None:
    if not isinstance(calling_context, dict):
        return
    if not _is_collective_insight_enabled(
        demisto_params=demisto_params,
        command_args=command_args,
    ):
        return

    cleaned_calling_context = _clean_calling_context(
        calling_context=calling_context
    )
    if cleaned_calling_context:
        lookup_payload["callingContext"] = cleaned_calling_context


def _build_lookup_payload(
    *,
    demisto_params: dict[str, Any],
    command: str,
    command_args: dict[str, Any],
    calling_context: dict[str, Any] | None,
) -> dict[str, Any]:
    lookup_payload: dict[str, Any] = {
        "demisto_command": command,
        "demisto_args": command_args,
        "demisto_params": dict(demisto_params),
    }
    _add_calling_context_to_lookup_payload(
        demisto_params=demisto_params,
        lookup_payload=lookup_payload,
        command_args=command_args,
        calling_context=calling_context,
    )
    return lookup_payload


# ---------------------------------------------------------------------------
# Response parsing & Result builders
# ---------------------------------------------------------------------------


def _get_lookup_result_actions(
    *,
    raw_response: Any,
) -> list[LookupResultActionPayload]:
    lookup_response = cast(LookupResponsePayload, raw_response)
    raw_result_actions = lookup_response.get("result_actions", [])
    if not isinstance(raw_result_actions, list):
        raise DemistoException(INVALID_LOOKUP_RESPONSE_MESSAGE)

    return cast(list[LookupResultActionPayload], raw_result_actions)


def _drop_none_values(
    *,
    raw_kwargs: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value for key, value in raw_kwargs.items() if value is not None
    }


def _build_dbot_score_kwargs(
    *,
    raw_dbot_score: DBotScorePayload,
) -> dict[str, Any]:
    return _drop_none_values(
        raw_kwargs={
            "indicator": raw_dbot_score["indicator"],
            "indicator_type": raw_dbot_score["indicator_type"],
            "integration_name": raw_dbot_score["integration_name"],
            "score": raw_dbot_score["score"],
            "malicious_description": raw_dbot_score.get(
                "malicious_description"
            ),
            "reliability": raw_dbot_score.get("reliability"),
            "message": raw_dbot_score.get("message"),
        }
    )


def _parse_indicator_class(
    *,
    indicator_action_payload: CreateIndicatorActionPayload,
) -> XsoarIndicatorClass:
    common_class_value = indicator_action_payload.get("common_class")
    try:
        return XsoarIndicatorClass(common_class_value)
    except ValueError as error:
        raise DemistoException(INVALID_LOOKUP_RESPONSE_MESSAGE) from error


def _build_ip_indicator_kwargs(
    *,
    raw_constructor_kwargs: IPIndicatorConstructorKwargsPayload,
) -> dict[str, Any]:
    return _drop_none_values(
        raw_kwargs={
            "ip": raw_constructor_kwargs.get("ip"),
            "description": raw_constructor_kwargs.get("description"),
        }
    )


def _build_domain_indicator_kwargs(
    *,
    raw_constructor_kwargs: DomainIndicatorConstructorKwargsPayload,
) -> dict[str, Any]:
    return _drop_none_values(
        raw_kwargs={
            "domain": raw_constructor_kwargs.get("domain"),
            "description": raw_constructor_kwargs.get("description"),
        }
    )


def _build_url_indicator_kwargs(
    *,
    raw_constructor_kwargs: URLIndicatorConstructorKwargsPayload,
) -> dict[str, Any]:
    return _drop_none_values(
        raw_kwargs={
            "url": raw_constructor_kwargs.get("url"),
            "description": raw_constructor_kwargs.get("description"),
        }
    )


def _build_file_indicator_kwargs(
    *,
    raw_constructor_kwargs: FileIndicatorConstructorKwargsPayload,
) -> dict[str, Any]:
    return _drop_none_values(
        raw_kwargs={
            "md5": raw_constructor_kwargs.get("md5"),
            "sha1": raw_constructor_kwargs.get("sha1"),
            "sha256": raw_constructor_kwargs.get("sha256"),
            "sha512": raw_constructor_kwargs.get("sha512"),
            "description": raw_constructor_kwargs.get("description"),
        }
    )


def _build_cve_indicator_kwargs(
    *,
    raw_constructor_kwargs: CVEIndicatorConstructorKwargsPayload,
) -> dict[str, Any]:
    return _drop_none_values(
        raw_kwargs={
            "id": raw_constructor_kwargs.get("id"),
            "cvss": raw_constructor_kwargs.get("cvss"),
            "published": raw_constructor_kwargs.get("published"),
            "modified": raw_constructor_kwargs.get("modified"),
            "description": raw_constructor_kwargs.get("description"),
            "cvss_version": raw_constructor_kwargs.get("cvss_version"),
            "cvss_score": raw_constructor_kwargs.get("cvss_score"),
            "cvss_vector": raw_constructor_kwargs.get("cvss_vector"),
        }
    )


def _build_command_results_kwargs(
    *,
    raw_command_results: CommandResultsPayload,
) -> dict[str, Any]:
    raw_response = raw_command_results.get("raw_response", {})
    return _drop_none_values(
        raw_kwargs={
            "outputs_prefix": raw_command_results.get("outputs_prefix"),
            "outputs": raw_response.get("outputs"),
            "raw_response": raw_response,
            "readable_output": raw_command_results.get("readable_output"),
            "outputs_key_field": raw_command_results.get("outputs_key_field"),
            "ignore_auto_extract": raw_command_results.get(
                "ignore_auto_extract"
            ),
        }
    )


def _create_indicator(
    *,
    indicator_action_payload: CreateIndicatorActionPayload,
) -> Common.Indicator:
    dbot_score = Common.DBotScore(
        **_build_dbot_score_kwargs(
            raw_dbot_score=indicator_action_payload["dbot_score"]
        )
    )

    indicator_class = _parse_indicator_class(
        indicator_action_payload=indicator_action_payload
    )
    raw_constructor_kwargs = indicator_action_payload["constructor_kwargs"]

    if indicator_class == XsoarIndicatorClass.IP:
        constructor_kwargs = _build_ip_indicator_kwargs(
            raw_constructor_kwargs=cast(
                IPIndicatorConstructorKwargsPayload,
                raw_constructor_kwargs,
            )
        )
        return Common.IP(dbot_score=dbot_score, **constructor_kwargs)

    if indicator_class == XsoarIndicatorClass.DOMAIN:
        constructor_kwargs = _build_domain_indicator_kwargs(
            raw_constructor_kwargs=cast(
                DomainIndicatorConstructorKwargsPayload,
                raw_constructor_kwargs,
            )
        )
        return Common.Domain(dbot_score=dbot_score, **constructor_kwargs)

    if indicator_class == XsoarIndicatorClass.URL:
        constructor_kwargs = _build_url_indicator_kwargs(
            raw_constructor_kwargs=cast(
                URLIndicatorConstructorKwargsPayload,
                raw_constructor_kwargs,
            )
        )
        return Common.URL(dbot_score=dbot_score, **constructor_kwargs)

    if indicator_class == XsoarIndicatorClass.FILE:
        constructor_kwargs = _build_file_indicator_kwargs(
            raw_constructor_kwargs=cast(
                FileIndicatorConstructorKwargsPayload,
                raw_constructor_kwargs,
            )
        )
        return Common.File(dbot_score=dbot_score, **constructor_kwargs)

    if indicator_class == XsoarIndicatorClass.CVE:
        constructor_kwargs = _build_cve_indicator_kwargs(
            raw_constructor_kwargs=cast(
                CVEIndicatorConstructorKwargsPayload,
                raw_constructor_kwargs,
            )
        )
        return Common.CVE(dbot_score=dbot_score, **constructor_kwargs)

    raise DemistoException(
        f"Unsupported indicator class: {indicator_class.value}"
    )


def _build_command_results(
    *,
    command_results_payload: CommandResultsPayload,
    indicator: Common.Indicator | None,
) -> CommandResults:
    command_results_kwargs = _build_command_results_kwargs(
        raw_command_results=command_results_payload
    )
    if indicator is not None:
        command_results_kwargs["indicator"] = indicator

    return CommandResults(**command_results_kwargs)


def _build_no_results_command_result() -> CommandResults:
    return CommandResults(
        outputs_prefix="",
        outputs={},
        raw_response={},
        readable_output="No results found.",
        outputs_key_field="",
    )


def _process_lookup_response(
    *,
    lookup_response: dict[str, Any],
) -> list[CommandResults]:
    command_results_list: list[CommandResults] = []

    for result_action_payload in _get_lookup_result_actions(
        raw_response=lookup_response
    ):
        created_indicator = None
        create_indicator_payload = result_action_payload.get(
            "create_indicator"
        )
        if create_indicator_payload is not None:
            created_indicator = _create_indicator(
                indicator_action_payload=create_indicator_payload
            )

        command_results_list.append(
            _build_command_results(
                command_results_payload=result_action_payload[
                    "CommandResults"
                ],
                indicator=created_indicator,
            )
        )

    return command_results_list


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def lookup_command(
    *,
    client: Client,
    demisto_params: dict[str, Any],
    command: str,
    command_args: dict[str, Any],
    calling_context: dict[str, Any] | None,
) -> list[CommandResults]:
    try:
        backend_response = client.lookup_reputation(
            lookup_payload=_build_lookup_payload(
                demisto_params=demisto_params,
                command=command,
                command_args=command_args,
                calling_context=calling_context,
            )
        )
    except LookupReputationNoResultsError:
        return [_build_no_results_command_result()]

    return _process_lookup_response(lookup_response=backend_response)


def test_module_command(
    *,
    client: Client,
) -> str:
    try:
        client.whoami()
        return "ok"
    except Exception as err:
        message = str(err).strip() or "Unknown error"
        raise DemistoException(f"Failed due to - {message}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def get_client(
    *,
    demisto_params: dict[str, Any],
) -> Client:
    base_url_value = demisto_params.get("server_url", "")
    base_url = (
        base_url_value.strip().rstrip("/")
        if isinstance(base_url_value, str)
        else ""
    )
    if not base_url:
        return_error("Please provide a valid API URL")

    api_token = _extract_api_token(demisto_params=demisto_params)
    if not api_token:
        return_error("Please provide a valid API token")

    return Client(
        base_url=base_url,
        verify=not demisto_params.get("insecure", False),
        headers={
            "X-RFToken": api_token,
            "X-RF-User-Agent": _build_user_agent_header(),
        },
        proxy=demisto_params.get("proxy", False),
    )


def main() -> None:
    try:
        demisto_params = demisto.params()
        if not isinstance(demisto_params, dict):
            demisto_params = {}

        client = get_client(demisto_params=demisto_params)
        command = demisto.command()

        if command == "test-module":
            return_results(test_module_command(client=client))
        elif command in ["ip", "domain", "url", "file", "cve"]:
            return_results(
                lookup_command(
                    client=client,
                    demisto_params=demisto_params,
                    command=command,
                    command_args=demisto.args(),
                    calling_context=demisto.callingContext,
                )
            )
        else:
            raise NotImplementedError(
                f"Command '{command}' is not implemented."
            )
    except Exception as err:
        return_error(
            f"Failed to execute {demisto.command()} command. Error: {err}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
