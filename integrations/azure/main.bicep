// Vulnder for Microsoft Sentinel and Defender: an hourly Logic App that ranks
// a tenant's CVEs with Vulnder and writes one row per CVE to Vulnder_CL.
// Everything runs in your subscription under a managed identity; Vulnder
// gets CVE IDs, or product names and versions, and never a credential.
// Deploy into the resource group of an existing Log Analytics workspace.
// Setup and the Graph permissions to grant afterwards: docs/AZURE.md.

@description('An existing Log Analytics workspace in this resource group (the Sentinel workspace, if you use Sentinel).')
param workspaceName string

@description('defender: rank the CVEs Defender Vulnerability Management finds. intune: build the stack from Intune discovered apps. stack: rank a fixed stack.')
@allowed(['defender', 'intune', 'stack'])
param mode string

@description('The stack, as /api/v1/stack returns it or in the stack URL format. Needed for mode "stack". In modes "defender" and "intune" it is optional and ranked alongside, for what they can\'t see, such as firewalls and VPNs.')
param stack string = ''

@description('Your Vulnder deployment.')
param vulnderUrl string = 'https://vulnder.com'

@description('Window in days for new CVEs (1-90). Listed CVEs (mode "defender") are ranked whatever their age.')
@minValue(1)
@maxValue(90)
param days int = 30

@description('Also create Sentinel analytics rules that open incidents for new Act now CVEs. Needs Sentinel on the workspace.')
param sentinelRules bool = false

param location string = resourceGroup().location

@description('Names the Logic App and its data collection rule, and fills the Source column. Deploy again with another name to add a second mode to the same workspace.')
param name string = 'vulnder'

var streamName = 'Custom-VulnderRows'
var tableName = 'Vulnder_CL'
// Monitoring Metrics Publisher, which the Logs Ingestion API requires on the DCR.
var metricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

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

// The rows as /api/v1/rank returns them, plus four fields the Logic App adds.
// Fields Vulnder adds later aren't declared, so they're dropped, not refused.
resource dcr 'Microsoft.Insights/dataCollectionRules@2024-03-11' = {
  name: '${name}-dcr'
  location: location
  kind: 'Direct'
  properties: {
    streamDeclarations: {
      '${streamName}': {
        columns: [
          { name: 'timeGenerated', type: 'string' }
          { name: 'runId', type: 'string' }
          { name: 'mode', type: 'string' }
          { name: 'source', type: 'string' }
          { name: 'cve', type: 'string' }
          { name: 'title', type: 'string' }
          { name: 'priority', type: 'string' }
          { name: 'score', type: 'real' }
          { name: 'respondWithinHours', type: 'int' }
          { name: 'reasons', type: 'dynamic' }
          { name: 'exploited', type: 'boolean' }
          { name: 'kevAddedAt', type: 'string' }
          { name: 'kevDueDate', type: 'string' }
          { name: 'knownRansomware', type: 'boolean' }
          { name: 'ssvcExploitation', type: 'string' }
          { name: 'epss', type: 'real' }
          { name: 'epssPercentile', type: 'real' }
          { name: 'cvss', type: 'real' }
          { name: 'publishedAt', type: 'string' }
          { name: 'beforeWindow', type: 'boolean' }
          { name: 'matched', type: 'dynamic' }
          { name: 'match', type: 'string' }
          { name: 'confidence', type: 'string' }
          { name: 'fixedVersions', type: 'dynamic' }
          { name: 'mitigation', type: 'string' }
          { name: 'advisory', type: 'string' }
          { name: 'patch', type: 'string' }
          { name: 'exploitRef', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [{ name: 'workspace', workspaceResourceId: workspace.id }]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['workspace']
        outputStream: 'Custom-${tableName}'
        // Title is a reserved column name, hence CveTitle. The field source is
        // bracketed because the input table is also called source.
        transformKql: 'source | project TimeGenerated = todatetime(timeGenerated), RunId = runId, Mode = mode, Source = [\'source\'], Cve = cve, CveTitle = title, Priority = priority, Score = score, RespondWithinHours = respondWithinHours, Reasons = reasons, Exploited = exploited, KevAddedAt = todatetime(kevAddedAt), KevDueDate = todatetime(kevDueDate), KnownRansomware = knownRansomware, SsvcExploitation = ssvcExploitation, Epss = epss, EpssPercentile = epssPercentile, Cvss = cvss, PublishedAt = todatetime(publishedAt), BeforeWindow = beforeWindow, Matched = matched, MatchType = [\'match\'], Confidence = confidence, FixedVersions = fixedVersions, Mitigation = mitigation, Advisory = advisory, Patch = patch, ExploitRef = exploitRef'
      }
    ]
  }
  dependsOn: [table]
}

// The DCR's own ingestion endpoint (kind Direct), so no DCE is needed.
var dcrProps = dcr.properties
var ingestUrl = '${dcrProps.endpoints.logsIngestion}/dataCollectionRules/${dcrProps.immutableId}/streams/${streamName}?api-version=2023-01-01'

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: name
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('workflow.json')
    parameters: {
      mode: { value: mode }
      stack: { value: stack }
      vulnderUrl: { value: vulnderUrl }
      days: { value: days }
      ingestUrl: { value: ingestUrl }
      source: { value: name }
    }
  }
}

resource canPublish 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, logicApp.id, metricsPublisher)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', metricsPublisher)
    principalId: logicApp.identity.principalId
    principalType: 'ServicePrincipal'
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
}

@description('The Logic App\'s managed identity. Grant it Graph permissions for mode "defender" or "intune" (docs/AZURE.md).')
output principalId string = logicApp.identity.principalId
output ingestUrl string = ingestUrl
