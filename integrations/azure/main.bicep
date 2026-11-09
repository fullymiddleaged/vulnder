// Vulnder for Microsoft Sentinel and Defender: an hourly Logic App that ranks
// a tenant's CVEs with Vulnder and writes one row per CVE to Vulnder_CL.
// Everything runs in your subscription under a managed identity; Vulnder
// gets CVE IDs, or product names and versions, and never a credential.
// The Logic App and its data collection rule go in the resource group you
// deploy to; the table and Sentinel rule go on an existing workspace, which
// can be in another group (workspace.bicep).
// Setup and the Graph permissions to grant afterwards: docs/AZURE.md.

@description('An existing Log Analytics workspace (the Sentinel workspace, if you use Sentinel).')
param workspaceName string

@description('The workspace\'s resource group, if it isn\'t the one you deploy to.')
param workspaceResourceGroup string = resourceGroup().name

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

// The table and the Sentinel rule go on the workspace, in its own resource group.
module onWorkspace 'workspace.bicep' = {
  name: '${name}-workspace'
  scope: resourceGroup(workspaceResourceGroup)
  params: {
    workspaceName: workspaceName
    tableName: tableName
    sentinelRules: sentinelRules
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
          { name: 'sourceName', type: 'string' }
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
      logAnalytics: [{ name: 'workspace', workspaceResourceId: onWorkspace.outputs.workspaceId }]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: ['workspace']
        outputStream: 'Custom-${tableName}'
        // Title is a reserved column name, hence CveTitle. The transform parser
        // rejects the field names title and match bare (title is a render
        // keyword), so they're bracketed. The workflow's field is sourceName,
        // not source, which is the name of the input table here.
        transformKql: 'source | project TimeGenerated = todatetime(timeGenerated), RunId = runId, Mode = mode, Source = sourceName, Cve = cve, CveTitle = [\'title\'], Priority = priority, Score = score, RespondWithinHours = respondWithinHours, Reasons = reasons, Exploited = exploited, KevAddedAt = todatetime(kevAddedAt), KevDueDate = todatetime(kevDueDate), KnownRansomware = knownRansomware, SsvcExploitation = ssvcExploitation, Epss = epss, EpssPercentile = epssPercentile, Cvss = cvss, PublishedAt = todatetime(publishedAt), BeforeWindow = beforeWindow, Matched = matched, MatchType = [\'match\'], Confidence = confidence, FixedVersions = fixedVersions, Mitigation = mitigation, Advisory = advisory, Patch = patch, ExploitRef = exploitRef'
      }
    ]
  }
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

@description('The Logic App\'s managed identity. Grant it Graph permissions for mode "defender" or "intune" (docs/AZURE.md).')
output principalId string = logicApp.identity.principalId
output ingestUrl string = ingestUrl
