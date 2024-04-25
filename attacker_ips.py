#!/var/ossec/framework/python/bin/python3
import json
import sys
import argparse
import os


def get_attackers(output_path, rules, sep):
    wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
    alert_log = open(wazuh_path + "/logs/alerts/alerts.json")
    banned_ips = []
    for alert in alert_log:
        alert_data = json.loads(alert)
        alert_log_file = alert_data.get("location")
        active_responses_log = alert_log_file.endswith("active-responses.log")
        if rules:
            for rule in rules:
                if active_responses_log and alert_data.get("rule").get("id") == rule:
                    banned_ips.append(
                        json.loads(alert)
                        .get("data")
                        .get("parameters")
                        .get("alert")
                        .get("data")
                        .get("srcip")
                    )
        else:
            if active_responses_log:
                banned_ips.append(
                    json.loads(alert)
                    .get("data")
                    .get("parameters")
                    .get("alert")
                    .get("data")
                    .get("srcip")
                )
        with open(output_path + "/all_attacker_ips.csv", "w") as attackers:
            attackers.write(f"{sep}".join(set(banned_ips)))
    return set(banned_ips)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blacklist generator")
    parser.add_argument(
        "-o",
        "--output-path",
        required=False,
        help="Specify the path for storing the exported IPs",
        default="/var/tmp",
    )
    parser.add_argument(
        "-i",
        "--rule-id",
        required=False,
        help="If Wazuh rule ID or IDs for filtering are not present, export all IPs from the logs.",
        default="",
    )
    parser.add_argument(
        "-s",
        "--separator",
        required=False,
        help="Delimiter used to separate IPs in the export file.",
        default=",",
    )
    args = vars(parser.parse_args())
    output_dir = args["output_path"]
    rule_id = args["rule_id"].split()
    separator = args["separator"]
    input_params = len(sys.argv)
    get_attackers(output_dir, rule_id, separator)
