// A new Log Analytics workspace, for anyone without one, with Sentinel turned
// on when the Sentinel rule is wanted. main.bicep deploys this only with
// createWorkspace=true, before workspace.bicep adds the table and rule; a
// workspace you already have is never changed by it.

param workspaceName string
param location string
param sentinel bool

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource onboarding 'Microsoft.SecurityInsights/onboardingStates@2025-09-01' = if (sentinel) {
  scope: workspace
  name: 'default'
  properties: {}
}
