# Vulnder for Microsoft Sentinel and Defender

An hourly Logic App in your own subscription. It ranks the CVEs affecting your tenant with Vulnder and writes one row per CVE to a Log Analytics table, `Vulnder_CL`. Optional Sentinel analytics rules open an incident when a CVE becomes Act now. The template is in [integrations/azure/](../integrations/azure/).

It works the same whatever your licences. Only where the list of what you run comes from changes:

| Mode | You have | Where the CVEs come from | What Vulnder receives |
|---|---|---|---|
| `defender` | Defender Vulnerability Management: Defender for Endpoint Plan 2, the standalone licence, or Defender for Servers | Defender's open CVEs (`DeviceTvmSoftwareVulnerabilities`), ranked by Vulnder whatever their age | CVE IDs |
| `intune` | Intune (Microsoft 365 E3, Business Premium and similar) without Vulnerability Management | Intune's discovered apps, matched to CVE records by Vulnder | App names, versions, publishers and device counts |
| `stack` | Neither, or products Defender can't see (firewalls, VPNs, appliances) | A stack you write once ([STACK_FORMAT.md](STACK_FORMAT.md)) | The stack |

Every mode writes the same rows, so the same rules and queries work for every tenant.

## What it creates

- **`Vulnder_CL`**, a custom table in your workspace, with one row per CVE per run: priority, score, reasons, KEV and CISA exploitation evidence, EPSS, CVSS, matched items, fixed versions and mitigation. Columns are listed in [main.bicep](../integrations/azure/main.bicep).
- **A data collection rule** of kind `Direct`, which takes the rows through the Logs Ingestion API. It needs no data collection endpoint.
- **A Logic App** (Consumption) with a system-assigned managed identity and the Monitoring Metrics Publisher role on that rule. Nothing is stored as a secret.
- **With `sentinelRules=true`**, the analytics rule "Vulnder: new Act now CVE". It opens one incident per CVE the first hour it is Act now ([new-act.kql](../integrations/azure/kql/new-act.kql)).

## Deploy

```sh
az deployment group create -g <workspace-resource-group> \
  -f integrations/azure/main.bicep \
  -p workspaceName=<workspace> mode=intune sentinelRules=true
```

For `stack`, also pass `stack=...`. You can use the `stack` value `/api/v1/stack` returns, or a plain one such as `p:fortinet/fortios@7.4.3,p:paloaltonetworks/pan-os@11.1`.

Then grant the Logic App's identity (the `principalId` output) the Microsoft Graph permission its mode needs. This takes an admin who can grant application permissions, such as a Privileged Role Administrator:

| Mode | Graph application permission |
|---|---|
| `defender` | `ThreatHunting.Read.All` |
| `intune` | `DeviceManagementManagedDevices.Read.All` |
| `stack` | none |

```sh
MI=<principalId output>
GRAPH=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)
ROLE=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles[?value=='ThreatHunting.Read.All'].id" -o tsv)
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" \
  --body "{\"principalId\":\"$MI\",\"resourceId\":\"$GRAPH\",\"appRoleId\":\"$ROLE\"}"
```

Runs before the grant fail at the Graph call and write nothing. Rows can take a few minutes to appear in a new table.

## Alerting the SOC and the patching teams

- **SOC: new Act now CVEs**, from the analytics rule, hourly. A CVE alerts once, the first hour it is Act now: on CISA KEV, reported actively exploited by CISA, or likely to be exploited soon. The alert carries Vulnder's reasons, the CISA due date where there is one, and the fixed versions. The first run alerts on every CVE already at Act now.
- **Patching: a daily list**, from [daily-patch-list.kql](../integrations/azure/kql/daily-patch-list.kql). It lists CVEs now at Act now or Attend that are new or rose in priority since the week before, with what to upgrade to. Run it as a scheduled query or a workbook, or have a Logic App post it to Teams.
- **Which devices**, in mode `defender`, from [defender-devices.kql](../integrations/azure/kql/defender-devices.kql) in the Defender portal's Advanced hunting, with Sentinel connected. It joins Vulnder's priorities to `DeviceTvmSoftwareVulnerabilities` and shows each CVE's devices and the update to install.
- **The current picture**, from [latest.kql](../integrations/azure/kql/latest.kql): every CVE in the latest run, most urgent first.

These rules look for CVEs that are new to the table, or whose priority rose. They don't use Vulnder's change dates, because a CVE can reach Vulnder after the date its change carries (see [API.md](API.md#post-apiv1rank)).

Vulnder's priorities are guidance for ordering work. Only CISA KEV means exploited (`Exploited`). `SsvcExploitation` is CISA's own assessment. EPSS is a predicted probability, and `Score` orders CVEs within a priority; it isn't a probability.

## Notes per mode

- **`defender`** sends Defender's distinct CVE IDs, up to 2,000 per call, in as many calls as needed. Vulnder ranks each listed CVE whatever its age, so nothing Defender found is left out.
- **`intune`** reads every page of `detectedApps` (up to 8,000 entries a run) and sends four fields per app. Vulnder cleans the names and collapses versions. The 200 places in a stack go to the products on most devices, and `/api/v1/stack` names the rest in `notChecked` (see [API.md](API.md#post-apiv1stack)). A product the fleet runs at several versions is checked unversioned, so it shows every version's CVEs. Apps Vulnder can't match are listed in `unrecognised`, and stay unchecked. Discovered apps don't usually include the Windows release itself. To cover it, add the Windows releases you run in mode `stack` with a second deployment (another `name`), for example `p:microsoft/windows_11_24h2`.
- **`stack`** suits edge devices and appliances, which Defender and Intune can't see. Mark internet-facing ones `;edge` so they get the edge-device deadlines.

## Privacy and cost

- Vulnder gets only what the table above lists. Device names, users and IPs stay in the tenant. Vulnder doesn't log or store request bodies, and nothing from your tenant reaches a model (see [API.md](API.md#privacy)). In mode `intune`, device counts are sent only to choose which products fill the 200 places.
- The Logic App calls `vulnder.com` and Microsoft endpoints over HTTPS 443, outbound only. If you filter outbound traffic, allow `vulnder.com`.
- Ingestion is a few hundred rows an hour. Logic App cost is a few dozen actions a run, more in mode `intune` (two per page of apps).
- Consumption Logic Apps share their region's outbound IPs, and Vulnder's limits are per IP. Hourly runs are well inside them. If you're refused anyway, `/api/v1/` returns 429 and the Logic App retries.

## Not tested here

The template follows the current Microsoft documentation for each resource, but it hasn't been deployed from this repository's CI. Before relying on it, deploy it to a test resource group and check that a run succeeds and rows arrive. Report problems as issues.
