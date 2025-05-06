"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

MAX_IMAGES_TO_FETCH = 25

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def _get(self, url_suffix, timeout=90, retries=3):
        params = demisto.args()
        return self._call(
            method="GET",
            url_suffix=url_suffix,
            params=params,
            timeout=timeout,
            retries=retries,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def _post(self, url_suffix, json_data, timeout=90, retries=3):
        return self._call(
            method="POST",
            url_suffix=url_suffix,
            json_data=json_data,
            timeout=timeout,
            retries=retries,
            status_list_to_retry=STATUS_TO_RETRY,
        )

    def _call(self, **kwargs):
        try:
            response = self._http_request(**kwargs)
            if isinstance(response, dict) and response.get("return_error"):
                # This will raise the Exception or call "demisto.results()" for the error and sys.exit(0).
                return_error(**response["return_error"])

        except DemistoException as err:
            if "404" in str(err):
                return CommandResults(
                    outputs_prefix="",
                    outputs={},
                    raw_response={},
                    readable_output="No results found.",
                    outputs_key_field="",
                )
            else:
                raise err

        return response

    def whoami(self) -> dict[str, Any]:
        return self._get(
            url_suffix="/info/whoami",
            timeout=60,
        )

    def get_alerts(self) -> dict[str, Any]:
        """Get alerts."""
        return self._get(url_suffix="/v3/alert/search")

    def get_alert_rules(self) -> dict[str, Any]:
        """Get alert rules."""
        return self._get(url_suffix="/v3/alert/rules")

    def get_alert_image(self, alert_type: str, alert_id: str, image_id: str) -> bytes:
        """
        Get an image from the v3 alert image endpoint.
        Returns the raw binary content of the image.
        """
        response_content: Any = self._http_request(
            method="get",
            url_suffix="/v3/alert/image",
            params={
                "alert_type": alert_type,
                "alert_id": alert_id,
                "image_id": image_id,
            },
            timeout=90,
            resp_type="content",
        )
        return response_content

    def fetch_incidents(self) -> dict[str, Any]:
        """Fetch incidents."""
        return self._post(
            url_suffix="/v3/alert/fetch",
            json_data={
                "integration_config": demisto.params(),
                "query_params": demisto.getLastRun(),
            },
            timeout=120,
        )


# === === === === === === === === === === === === === === ===
# === === === === === === ACTIONS === === === === === === ===
# === === === === === === === === === === === === === === ===


class Actions:
    def __init__(self, rf_client: Client):
        self.client = rf_client

    def fetch_incidents(self) -> None:
        response = self.client.fetch_incidents()
        alerts = response.get("alerts", [])
        next_query = response.get("next_query", {})

        incidents = [
            {
                "name": alert.get("title"),
                "occurred": alert.get("created"),
                "dbotMirrorId": alert.get("id"),
                "rawJSON": json.dumps(alert),
            }
            for alert in alerts
        ]

        demisto.incidents(incidents)
        demisto.setLastRun(next_query)

        # update_alert_status = response.pop("alerts_update_data", None)
        # if update_alert_status:
        #    self.client.alert_set_status(update_alert_status)

    def get_alerts_command(self) -> dict[str, Any]:
        """Get Alerts Command."""
        return self.client.get_alerts()

    def get_alert_rules_command(self) -> dict[str, Any]:
        """Get Alert Rules Command."""
        return self.client.get_alert_rules()

    @staticmethod
    def _get_file_name_from_image_id(image_id: str) -> str:
        return f"{image_id.replace('img:', '')}.png"

    def _get_image_and_create_attachment(self, alert_type: str, alert_id: str, image_id: str) -> dict | None:
        try:
            return_results(f"Trying to fetch {image_id=}")
            image_content = self.client.get_alert_image(alert_type, alert_id, image_id)
            file_name = self._get_file_name_from_image_id(image_id)
            file_result_obj = fileResult(file_name, image_content)
            demisto.results(file_result_obj)  # Important
            attachment = {
                "description": "Alert image",
                "name": file_result_obj.get("File"),
                "path": file_result_obj.get("FileID"),
                "showMediaFile": True,
            }
            return attachment
        except Exception as e:
            demisto.error(f"Failed to fetch image {image_id}: {str(e)}")
            return None

    def get_alert_images_command(self) -> list:
        incident = demisto.incident()
        return_results(f"{incident=}")
        labels = incident.get("labels", [])
        return_results(f"{labels=}")

        # alert_type = incident.get("type")  # "_Recorded Future Classic Alert"
        alert_type = None  # "classic-alert"
        for label in labels:
            if label.get("type") == "type":
                alert_type = label.get("value")
                break
        else:
            return_error("Failed to get alert_type from incident labels.")

        alert_id = incident.get("alertid")
        if not alert_id:
            return_error("Failed to get alert id from incident.")

        image_ids = []
        for label in labels:
            if label.get("type") == "images":
                image_ids_json_str = label.get("value")
                try:
                    image_ids = json.loads(image_ids_json_str)
                except Exception:
                    return_error(f"Failed to parse {image_ids_json_str}")

        return_results(f"{image_ids=}")

        if not image_ids:
            return [CommandResults(readable_output="No screenshots found in alert details.")]

        context = demisto.context()
        return_results(f"{context=}")

        files = demisto.get(context, "File")
        if not files:
            files = []
        if not isinstance(files, list):
            files = [files]

        return_results(f"{files=}")

        existing_file_names = {f.get("Name") for f in files}
        return_results(f"{existing_file_names=}")

        # Determine missing image IDs.
        missing_image_ids = {}
        for img_id in image_ids:
            # Limit to only 25 images.
            if len(missing_image_ids) >= MAX_IMAGES_TO_FETCH:
                break

            file_name = self._get_file_name_from_image_id(img_id)
            if file_name not in existing_file_names:
                missing_image_ids.add(img_id)

        return_results(f"{missing_image_ids=}")

        if not missing_image_ids:
            return [CommandResults(readable_output="No new images to fetch.")]

        # Fetch missing images concurrently using thread pool.
        new_attachments = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}

            for img_id in missing_image_ids:
                future = executor.submit(
                    self._get_image_and_create_attachment,
                    alert_type,
                    alert_id,
                    img_id,
                )
                futures[future] = img_id

            for future in concurrent.futures.as_completed(futures):
                attachment = future.result()
                if attachment:
                    new_attachments.append(attachment)

        if not new_attachments:
            return [
                CommandResults(
                    readable_output="No new images were fetched.",
                )
            ]

        message = f"Fetched {len(new_attachments)} new image(s)."
        return [
            CommandResults(
                readable_output=message,
            )
        ]


def get_client():
    demisto_params = demisto.params()

    base_url = demisto_params.get("url", "").rstrip("/")
    verify_ssl = not demisto_params.get("insecure", False)
    proxy = demisto_params.get("proxy", False)

    api_token = demisto_params.get("api_token", {}).get("password") or demisto_params.get("token")
    if not api_token:
        return_error("Please provide a valid API token")

    headers = {
        "X-RFToken": api_token,
        "X-RF-User-Agent": (
            f"RecordedFuture.py/{__version__} ({platform.platform()}) "
            f"XSOAR/{__version__} "
            f"RFClient/{__version__} (Cortex_XSOAR_{demisto.demistoVersion()['version']})"
        ),
    }
    return Client(base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy)


def main():
    try:
        client = get_client()

        command = demisto.command()
        actions = Actions(client)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            # Returning 'ok' indicates that the integration works like it suppose to and
            # connection to the service is successful.
            # Returning 'ok' will make the test result be green.
            # Any other response will make the test result be red.

            try:
                client.whoami()
                return_results("ok")
            except Exception as err:
                message = str(err)
                try:
                    error = json.loads(str(err).split("\n")[1])
                    if "fail" in error.get("result", {}).get("status", ""):
                        message = error.get("result", {})["message"]
                except Exception:
                    message = (
                        f"Unknown error. Please verify that the API URL and Token are correctly configured. RAW Error: {err}"
                    )
                raise DemistoException(f"Failed due to - {message}")

        elif command == "fetch-incidents":
            actions.fetch_incidents()

        elif command == "recordedfuture-alert-rules":
            return_results(actions.get_alert_rules_command())

        elif command == "recordedfuture-alert-search":
            return_results(actions.get_alerts_command())

        elif command == "recordedfuture-alert-images":
            return_results(actions.get_alert_images_command())

    except Exception as e:
        return_error(
            message=f"Failed to execute {demisto.command()} command: {str(e)}",
            error=e,
        )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
