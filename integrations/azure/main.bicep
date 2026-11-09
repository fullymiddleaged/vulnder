// Vulnder for Microsoft Sentinel and Defender: an hourly Logic App that ranks
// a tenant's CVEs with Vulnder and writes one row per CVE to Vulnder_CL.
// Everything runs in your subscription under a managed identity; Vulnder
// gets CVE IDs, or product names and versions, and never a credential.
// The Logic App and its data collection rule go in the resource group you
// deploy to (logicapp.bicep); the table and Sentinel rule go on an existing
// workspace, which can be in another group (workspace.bicep).
// Setup and the Graph permissions to grant afterwards: docs/AZURE.md.

@description('An existing Log Analytics workspace (the Sentinel workspace, if you use Sentinel).')
@minLength(4)
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

@description('Region for the Logic App and its data collection rule. Leave empty for the workspace\'s region.')
param location string = ''

@description('Names the Logic App and its data collection rule, and fills the Source column. Deploy again with another name to add a second mode to the same workspace.')
param name string = 'vulnder'

var tableName = 'Vulnder_CL'

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

// The Logic App, its data collection rule and its role, in the workspace's
// region unless you name one. The portal's workspace picker doesn't reliably
// pass the region, so it's looked up here, not taken from the form.
module onResourceGroup 'logicapp.bicep' = {
  name: '${name}-logicapp'
  params: {
    name: name
    location: empty(location) ? onWorkspace.outputs.location : location
    workspaceId: onWorkspace.outputs.workspaceId
    tableName: tableName
    mode: mode
    stack: stack
    vulnderUrl: vulnderUrl
    days: days
  }
}

@description('The Logic App\'s managed identity. Grant it Graph permissions for mode "defender" or "intune" (docs/AZURE.md).')
output principalId string = onResourceGroup.outputs.principalId
output ingestUrl string = onResourceGroup.outputs.ingestUrl
