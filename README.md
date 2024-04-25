# Generating IP blacklist from Wazuh logs.

Example of how to obtain an IP blacklist using Wazuh active response banning.

## Installation
Check out the repository to the Wazuh wodles folder.
```shell
git clone https://github.com/pyToshka/wazuh-active-response-attacker.git /var/ossec/wodles/black_list
chmod +x var/ossec/wodles/black_list/attacker_ips.py
```
Incorporate a new command wodle into your Wazuh configuration

Create blacklist without rule filters

```xml
<wodle name="command">
  <disabled>yes</disabled>
  <tag>ips_black_list</tag>
  <command>/var/ossec/wodles/black_list/attacker_ips.py</command>
  <interval>10m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>

```
Filtered by rule ids

```xml
<wodle name="command">
  <disabled>yes</disabled>
  <tag>ips_black_list</tag>
  <command>/var/ossec/wodles/black_list/attacker_ips.py -i "652 651"</command>
  <interval>10m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>

```

However, you can run manually or via cron:

```shell
/var/ossec/wodles/black_list/attacker_ips.py
```

The script will generate CSV file: `all_attacker_ips.csv`.

`all_attacker_ips.csv` - Contains unique blocked IPs from `/var/ossec/logs/alerts/alerts.json`.

### Arguments

| key              | Description                                                                          | Default value |
|------------------|--------------------------------------------------------------------------------------|---------------|
| -o/--output-path | Specify the path for storing the exported IPs                                        | `/var/tmp/`   |
| -i/--rule-id     | If Wazuh rule ID or IDs for filtering are not present, export all IPs from the logs. | `None`        |
| -s/--separator   | Delimiter used to separate IPs in the export file.                                   | `,`           |


Enjoy
