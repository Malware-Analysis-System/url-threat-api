# GCP SDK Usage Manual: Orchestrator Backend

This manual provides a detailed guide on how to use the Google Cloud Platform (GCP) SDKs within the `orchestrator-backend`. It covers the core services, authentication patterns, and remote execution mechanisms.

## 1. SDK Overview

The project uses the following high-level GCP SDK packages:

| Service | Package | Primary Clients |
| :--- | :--- | :--- |
| **Compute** | `@google-cloud/compute` | `InstancesClient`, `ImagesClient`, `NetworksClient` |
| **IAM** | `@google-cloud/iam` | `IAMClient` |
| **Resource Manager**| `@google-cloud/resource-manager` | `ProjectsClient` (for Policy management) |
| **OS Config** | `@google-cloud/os-config` | `OsConfigServiceClient` (Remote Execution) |
| **Auth** | `google-auth-library` | Used for custom credential parsing |

---

## 2. Authentication Pattern

All GCP services inherit from [GcpBaseService](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-base.service.js#3-30). Authentication is handled by passing a **Service Account JSON Object** (or string) to the base service.

### Key Class: [GcpBaseService](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-base.service.js#3-30)
- **Location**: [src/services/gcp-services/gcp-base.service.js](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-base.service.js)
- **Function**: [getAuth(credentials)](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-base.service.js#4-21)
- **Usage**: Automatically extracts the `projectId` and `credentials` object from the provided JSON.

```javascript
// Example in a derived service
const auth = this.getAuth(credentials);
const client = new InstancesClient({ credentials: auth.credentials });
```

---

## 3. Compute Engine (GCE)

Managed via [GcpComputeService](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-compute.service.js#5-252). It handles instance lifecycle and discovery.

### Common Operations

#### Listing Images & Networks
Used to populate UI dropdowns for VM creation.
```javascript
const client = new ImagesClient({ credentials });
const [images] = await client.list({ project: projectId });
```

#### Lifecycle Operations (Start, Stop, Reset, Delete)
Commands for managing power state and deletion are simple but require polling the operation result.

```javascript
// Examples from GcpComputeService
const client = new InstancesClient({ credentials });

// Start Instance
const [startRes] = await client.start({ project, zone, instance: name });
await this._waitForOperation(credentials, project, zone, startRes.latestResponse);

// Stop Instance
const [stopRes] = await client.stop({ project, zone, instance: name });
await this._waitForOperation(credentials, project, zone, stopRes.latestResponse);

// Delete Instance
const [delRes] = await client.delete({ project, zone, instance: name });
await this._waitForOperation(credentials, project, zone, delRes.latestResponse);
```

#### Creating an Instance
Instance creation is **asynchronous**. You must wait for the `ZoneOperation` to reach `DONE` status.

> [!IMPORTANT]
> Always use `ZoneOperationsClient` to track the status of long-running operations like `insert`, `start`, or `stop`.

```javascript
const [response] = await client.insert({
    project: projectId,
    zone: zone,
    instanceResource: config
});
// Operation Polling
await this._waitForOperation(credentials, projectId, zone, response.latestResponse);
```

---

## 4. Remote Execution (SSM Parity)

GCP uses **OS Config** to provide functionality similar to AWS SSM SendCommand.

### Key Class: [GcpOsConfigService](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-os-config.service.js#4-80)
- **Mechanism**: `executePatchJob` with a `linuxExecStepConfig`.
- **Requirement**: The `google-osconfig-agent` must be installed and running on the target VM.

#### Executing a Command
```javascript
const [response] = await client.executePatchJob({
    parent: `projects/${projectId}`,
    patchConfig: {
        postStep: {
            linuxExecStepConfig: {
                executable: '/bin/bash',
                args: ['-c', 'cat /etc/os-release']
            }
        }
    },
    instanceFilter: {
        instanceNamePrefixes: [`projects/${projectId}/zones/${zone}/instances/${instanceId}`]
    }
});
```

---

## 5. IAM & Permissions

Managed via [GcpIamService](file:///c:/Users/Zain/Downloads/vtap_GUI-main%20%281%29/vtap_GUI-main/orchestrator-backend/src/services/gcp-services/gcp-iam.service.js#6-103). This service handles the creation of Service Accounts and the assignment of project-level IAM policies.

### RBAC Workflow: Demo Code
Here is how to create a Service Account and grant it roles (e.g., for OS Config) at the project level.

```javascript
const { IAMClient } = require('@google-cloud/iam');
const { ProjectsClient } = require('@google-cloud/resource-manager');

// 1. Create a Service Account
const iamClient = new IAMClient({ credentials });
const [sa] = await iamClient.createServiceAccount({
    name: `projects/${projectId}`,
    accountId: 'my-service-account-id',
    serviceAccount: { displayName: 'My Demo SA' }
});

// 2. Grant Roles (Project IAM Policy)
const rmClient = new ProjectsClient({ credentials });
const [policy] = await rmClient.getIamPolicy({ resource: `projects/${projectId}` });

policy.bindings.push({
    role: 'roles/osconfig.admin',
    members: [`serviceAccount:${sa.email}`]
});

await rmClient.setIamPolicy({
    resource: `projects/${projectId}`,
    policy: policy
});
```

---


