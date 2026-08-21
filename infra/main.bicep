// ============================================================
// CyberDash — Root Infrastructure Orchestrator (main.bicep)
// ============================================================
// Deploys the complete CyberDash hosting environment into the
// target Resource Group based on environment parameters.
//
// GLOBALLY UNIQUE NAMING:
// In Azure, Web Apps require globally unique names across the entire
// azurewebsites.net domain. If no explicit webAppName is passed,
// a deterministic unique suffix is appended using uniqueString(resourceGroup().id).
// ============================================================

targetScope = 'resourceGroup'

@description('Deployment environment name: staging or prod.')
@allowed([
  'staging'
  'prod'
])
param environmentType string = 'staging'

@description('Azure region for all resources. Defaults to the Resource Group location.')
param location string = resourceGroup().location

@description('Optional explicit Web App name. If empty, a globally unique name is automatically generated.')
param webAppName string = ''

@description('Base name prefix used when generating a unique Web App name.')
param baseName string = 'cyberdash'

@description('App Service Plan pricing tier SKU.')
@allowed([
  'B1'
  'B2'
  'B3'
  'S1'
  'P1v3'
  'P2v3'
])
param skuName string = 'B1'

@description('Enable persistent SQLite storage mounted at /home.')
param enablePersistentStorage bool = (environmentType == 'prod')

@description('Full container image reference (e.g. cyberdashregistry.azurecr.io/cyberdash:latest).')
param containerImage string

@description('ACR login server URL.')
param acrLoginServer string = 'cyberdashregistry.azurecr.io'

@description('ACR username for container registry authentication.')
param acrUsername string = ''

@description('ACR password for container registry authentication.')
@secure()
param acrPassword string = ''

// Compute globally unique, collision-resistant Web App name
var effectiveWebAppName = !empty(webAppName) ? webAppName : '${baseName}-${environmentType}-${uniqueString(resourceGroup().id)}'

// Derive App Service Plan name from environment and web app name
var appServicePlanName = 'asp-${effectiveWebAppName}'

// Standard enterprise tags
var standardTags = {
  Project: 'CyberDash'
  Environment: environmentType
  ManagedBy: 'Bicep'
}

// ------------------------------------------------------------
// Deploy App Service Module
// ------------------------------------------------------------
module appServiceModule './modules/appservice.bicep' = {
  name: 'appServiceDeployment-${environmentType}'
  params: {
    location: location
    appServicePlanName: appServicePlanName
    webAppName: effectiveWebAppName
    skuName: skuName
    environmentType: environmentType
    enablePersistentStorage: enablePersistentStorage
    containerImage: containerImage
    acrLoginServer: acrLoginServer
    acrUsername: acrUsername
    acrPassword: acrPassword
    tags: standardTags
  }
}

// ------------------------------------------------------------
// Root Outputs (Dynamically consumed by Azure Pipelines)
// ------------------------------------------------------------
output webAppName string = appServiceModule.outputs.webAppName
output webAppDefaultHostName string = appServiceModule.outputs.webAppDefaultHostName
output webAppUrl string = appServiceModule.outputs.webAppUrl
output principalId string = appServiceModule.outputs.principalId
