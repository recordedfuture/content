import inspect
import platform
from typing import Any

import requests  # noqa: F401

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

# flake8: noqa: F405

STATUS_TO_RETRY = [500, 501, 502, 503, 504]
LOOKUP_REPUTATION_PATH = "/v3/lookup/reputation"

__version__ = "1.0.0"
INVALID_LOOKUP_RESPONSE_MESSAGE = "Invalid lookup response."


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


def _drop_none_values(
    *,
    raw_kwargs: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value for key, value in raw_kwargs.items() if value is not None
    }


_INDICATOR_TYPE_TO_COMMON_CLASS: dict[str, type] = {
    "ip": Common.IP,
    "domain": Common.Domain,
    "url": Common.URL,
    "file": Common.File,
    "cve": Common.CVE,
}


# CommandResults arguments that take XSOAR objects rather than plain JSON;
# each needs its own builder (see _create_indicator) before it can be passed on.
_OBJECT_COMMAND_RESULTS_ARGS = frozenset(
    {
        "indicator",
        "indicators",
        "indicators_timeline",
        "relationships",
        "scheduled_command",
        "execution_metrics",
    }
)


def _accepted_kwargs(
    *,
    target_class: type,
    payload: dict[str, Any],
    exclude: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Keep only the payload fields the constructor accepts.

    The backend owns the response format; ignoring fields this pack version
    (or the server's CommonServerPython) doesn't know keeps older packs
    working when the backend adds fields.
    """
    accepted = inspect.signature(target_class.__init__).parameters
    return _drop_none_values(
        raw_kwargs={
            key: value
            for key, value in payload.items()
            if key in accepted and key != "self" and key not in exclude
        }
    )


def _create_indicator(
    *,
    raw_indicator: dict[str, Any],
) -> Common.Indicator | None:
    indicator_type = raw_indicator.get("type")
    common_class = _INDICATOR_TYPE_TO_COMMON_CLASS.get(str(indicator_type))
    if common_class is None:
        demisto.debug(f"Ignoring unsupported indicator type: {indicator_type!r}")
        return None

    try:
        dbot_score = Common.DBotScore(
            **_accepted_kwargs(
                target_class=Common.DBotScore,
                payload=raw_indicator["dbot_score"],
            )
        )
        return common_class(
            dbot_score=dbot_score,
            **_accepted_kwargs(
                target_class=common_class,
                payload=raw_indicator,
                exclude=frozenset({"dbot_score"}),
            ),
        )
    except (KeyError, TypeError, ValueError) as err:
        raise DemistoException(
            f"{INVALID_LOOKUP_RESPONSE_MESSAGE} Invalid {indicator_type} indicator: "
            f"{err}"
        ) from err


def _build_command_results(
    *,
    result_action: dict[str, Any],
    indicator: Common.Indicator | None,
) -> CommandResults:
    raw_response = result_action.get("raw_response") or {}
    kwargs = _accepted_kwargs(
        target_class=CommandResults,
        payload=result_action,
        exclude=_OBJECT_COMMAND_RESULTS_ARGS,
    )
    # Outputs are sent once, inside raw_response, to avoid duplicating them
    # (same convention as the Recorded Future Alerts integration).
    if isinstance(raw_response, dict) and "outputs" in raw_response:
        kwargs.setdefault("outputs", raw_response["outputs"])
    if indicator is not None:
        kwargs["indicator"] = indicator
    return CommandResults(**kwargs)


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
    for result_action in lookup_response.get("result_actions") or []:
        raw_indicator = result_action.get("indicator")
        command_results_list.append(
            _build_command_results(
                result_action=result_action,
                indicator=(
                    _create_indicator(raw_indicator=raw_indicator)
                    if raw_indicator
                    else None
                ),
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
