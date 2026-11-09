// What Vulnder creates on the Log Analytics workspace itself: the Vulnder_CL
// table and, optionally, the Sentinel analytics rule. main.bicep deploys this
// into the workspace's resource group, which can differ from its own.

param workspaceName string
param tableName string
param sentinelRules bool

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

// One row per CVE per run. Reasons, Matched and FixedVersions are string arrays.
resource table 'Microsoft.OperationalInsights/workspaces/tables@2025-02-01' = {
  parent: workspace
  name: tableName
  properties: {
    plan: 'Analytics'
    schema: {
      name: tableName
      description: 'CVEs ranked by Vulnder, one row per CVE per run.'
      columns: [
        { name: 'TimeGenerated', type: 'dateTime' }
        { name: 'RunId', type: 'string' }
        { name: 'Mode', type: 'string' }
        { name: 'Source', type: 'string' }
        { name: 'Cve', type: 'string' }
        { name: 'CveTitle', type: 'string' }
        { name: 'Priority', type: 'string' }
        { name: 'Score', type: 'real' }
        { name: 'RespondWithinHours', type: 'int' }
        { name: 'Reasons', type: 'dynamic' }
        { name: 'Exploited', type: 'boolean' }
        { name: 'KevAddedAt', type: 'dateTime' }
        { name: 'KevDueDate', type: 'dateTime' }
        { name: 'KnownRansomware', type: 'boolean' }
        { name: 'SsvcExploitation', type: 'string' }
        { name: 'Epss', type: 'real' }
        { name: 'EpssPercentile', type: 'real' }
        { name: 'Cvss', type: 'real' }
        { name: 'PublishedAt', type: 'dateTime' }
        { name: 'BeforeWindow', type: 'boolean' }
        { name: 'Matched', type: 'dynamic' }
        { name: 'MatchType', type: 'string' }
        { name: 'Confidence', type: 'string' }
        { name: 'FixedVersions', type: 'dynamic' }
        { name: 'Mitigation', type: 'string' }
        { name: 'Advisory', type: 'string' }
        { name: 'Patch', type: 'string' }
        { name: 'ExploitRef', type: 'string' }
      ]
    }
  }
}

// Incidents for the SOC: a CVE that is Act now in the latest run and wasn't in the run before.
resource newActRule 'Microsoft.SecurityInsights/alertRules@2025-09-01' = if (sentinelRules) {
  scope: workspace
  name: guid(workspace.id, 'vulnder-new-act')
  kind: 'Scheduled'
  properties: {
    displayName: 'Vulnder: new Act now CVE'
    description: 'A CVE affecting this tenant became Act now in Vulnder: on CISA KEV, reported actively exploited by CISA, or likely to be exploited soon. The alert lists Vulnder\'s reasons and the fixed versions.'
    enabled: true
    severity: 'High'
    query: loadTextContent('kql/new-act.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P2D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Vulnder: {{Cve}} is Act now'
      alertDescriptionFormat: '{{CveTitle}}'
    }
    customDetails: {
      Cve: 'Cve'
      Reasons: 'Reasons'
      RespondWithinHours: 'RespondWithinHours'
      KevDueDate: 'KevDueDate'
      FixedVersions: 'FixedVersions'
      Matched: 'Matched'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: false
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  }
  // Sentinel runs the query when the rule is created and refuses it if
  // Vulnder_CL doesn't exist yet.
  dependsOn: [table]
}

output workspaceId string = workspace.id
output location string = workspace.location
