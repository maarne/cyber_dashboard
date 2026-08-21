// ============================================================
// CyberDash — Reusable App Service & Container Web App Module
// ============================================================
// Deploys a Linux App Service Plan and Web App for Containers
// with managed identity, port bindings, and configurable persistent storage.
// ============================================================

@description('The Azure location where resources should be deployed.')
param location string = resourceGroup().location

@description('The name of the App Service Plan.')
param appServicePlanName string

@description('The name of the Web App.')
param webAppName string

@description('App Service Plan pricing tier SKU (e.g. B1, P1v3).')
@allowed([
  'B1'
  'B2'
  'B3'
  'S1'
  'P1v3'
  'P2v3'
])
param skuName string = 'B1'

@description('The environment name (e.g. staging, prod).')
param environmentType string = 'staging'

@description('Enable persistent storage mounted at /home (/home/data/cyber_dashboard.db).')
param enablePersistentStorage bool = false

@description('The full container image reference (e.g. cyberdashregistry.azurecr.io/cyberdash:latest).')
param containerImage string

@description('The ACR login server URL (e.g. cyberdashregistry.azurecr.io).')
param acrLoginServer string = 'cyberdashregistry.azurecr.io'

@description('The ACR username (optional if using Managed Identity).')
param acrUsername string = ''

@description('The ACR password (optional if using Managed Identity).')
@secure()
param acrPassword string = ''

@description('Standard resource tags.')
param tags object = {
  Project: 'CyberDash'
  ManagedBy: 'Bicep-Pipeline'
  Environment: environmentType
}

// ------------------------------------------------------------
// 1. Linux App Service Plan
// ------------------------------------------------------------
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  kind: 'linux'
  properties: {
    reserved: true // Required for Linux container hosting
  }
  sku: {
    name: skuName
    tier: skuName == 'B1' || skuName == 'B2' || skuName == 'B3' ? 'Basic' : 'PremiumV3'
  }
}

// ------------------------------------------------------------
// 2. Web App for Containers
// ------------------------------------------------------------
resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: webAppName
  location: location
  tags: tags
  kind: 'app,linux,container'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'DOCKER|${containerImage}'
      alwaysOn: skuName != 'F1' && skuName != 'D1'
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE'
          value: string(enablePersistentStorage)
        }
        {
          name: 'DATABASE_PATH'
          value: enablePersistentStorage ? '/home/data/cyber_dashboard.db' : '/app/data/cyber_dashboard.db'
        }
        {
          name: 'WEBSITES_CONTAINER_START_TIME_LIMIT'
          value: '1800'
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_URL'
          value: 'https://${acrLoginServer}'
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_USERNAME'
          value: acrUsername
        }
        {
          name: 'DOCKER_REGISTRY_SERVER_PASSWORD'
          value: acrPassword
        }
      ]
    }
  }
}

// ------------------------------------------------------------
// Outputs
// ------------------------------------------------------------
output appServicePlanId string = appServicePlan.id
output webAppId string = webApp.id
output webAppName string = webApp.name
output webAppDefaultHostName string = webApp.properties.defaultHostName
output webAppUrl string = 'https://${webApp.properties.defaultHostName}'
output principalId string = webApp.identity.principalId
