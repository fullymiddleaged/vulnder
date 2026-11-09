// The Logic App, its data collection rule and the role that lets it write
// rows. main.bicep deploys this into your resource group, in the workspace's
// region: Bicep can only take a region worked out during deployment (from
// workspace.bicep) as a module parameter, not on a resource directly.

param name string
param location string
param workspaceId string
param tableName string
param mode string
param stack string
param vulnderUrl string
param days int

var streamName = 'Custom-VulnderRows'
// Monitoring Metrics Publisher, which the Logs Ingestion API requires on the DCR.
var metricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

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
      logAnalytics: [{ name: 'workspace', workspaceResourceId: workspaceId }]
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

output principalId string = logicApp.identity.principalId
output ingestUrl string = ingestUrl
