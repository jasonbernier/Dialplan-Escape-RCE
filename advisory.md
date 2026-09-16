# Dialplan Escape: FusionPBX Dialplan Validation Bypass with Conditional OS Command Execution

## Advisory status

This advisory documents a confirmed server-side validation defect and its configuration-dependent command-execution impact. It does **not** claim unauthenticated RCE or RCE against a stock secure installation.

The vendor was notified and does not consider the reported behavior a vulnerability. Its position is that FusionPBX has shipped the applicable FreeSWITCH system-command interfaces disabled by default for several years. That position and the exploit prerequisites are included prominently below.

## Summary

FusionPBX's structured dialplan editor attempts to exclude dangerous FreeSWITCH applications such as `system`, `bgsystem`, `spawn`, `bg_spawn`, and `spawn_stream`. Its server-side validation uses two independent negative assignments, however. A submitted `system` value fails the `system` condition and then passes the `spawn` condition; a submitted `spawn` value does the reverse. The prohibited value can therefore be stored and emitted into executable FreeSWITCH dialplan XML.

FusionPBX's shipped FreeSWITCH configuration independently disables system dialplan applications and system API commands. The validation bypass alone therefore does not produce operating-system execution on the reviewed stock configuration.

For the direct dialplan `system` action to execute, the following FusionPBX variable must have this effective state:

```text
Name:    disable_system_app_commands
Value:   false
Enabled: true
```

The name is a double negative. Setting the value to `false` disables the protection and permits the applicable system-command application to register. FusionPBX ships this value as `true`.

After the value changes, FreeSWITCH must reload its XML configuration and `mod_dptools` must be loaded after the new value is effective. A safe module reload may be sufficient; a FreeSWITCH restart is the more reliable activation method. In the laboratory used for this research, a FreeSWITCH restart was used during portions of validation.

## Metadata

| Field | Value |
|---|---|
| Product | FusionPBX |
| Version verified | `5.6.4-dev` master-branch snapshot |
| Component | Structured dialplan editor and dialplan XML generator |
| Vulnerability class | Stored OS command injection through server-side validation bypass |
| Primary CWE | CWE-184: Incomplete List of Disallowed Inputs |
| Additional CWE | CWE-20: Improper Input Validation; CWE-78: OS Command Injection |
| Authentication | Required |
| Stock privilege | `superadmin` |
| Stock exposure | Command execution blocked by secure defaults |
| Execution identity | FreeSWITCH service account; `www-data` in the tested lab |
| Vendor disposition | Not considered a vulnerability |

No universal CVSS score is assigned. A score that omits the disabled-by-default interface and superadmin prerequisites would overstate the default risk.

## Tested source

- Archive: `fusionpbx-master.zip`
- Reported application version: `5.6.4-dev`
- Archive SHA-256: `0624F2AD94EF8A890326E8599ED0330A085EBA4B67E23317A5527EC8C782E13A`
- Primary handler: `app/dialplans/dialplan_edit.php`
- XML generator: `app/dialplans/resources/classes/dialplan.php`

Only this snapshot was verified. Affected-version ranges should not be inferred without checking tagged releases for the same logic and surrounding controls.

## Technical analysis

### Intended restriction

The editor queries supported FreeSWITCH applications but deliberately omits command-execution applications from the displayed list:

```php
if (
	$application != "name"
	&& $application != "system"
	&& $application != "spawn"
	&& $application != "bg_spawn"
	&& $application != "spawn_stream"
	&& stristr($application, "[") != true
) {
	// Add application to the editor list.
}
```

Removing an option from the interface does not prevent a client from submitting it directly, so the server-side validation is the relevant security boundary.

### Broken server-side validation

The POST handler processes attacker-controlled detail values using separate negative conditions:

```php
if (!preg_match("/system/i", $row["dialplan_detail_type"])) {
	$dialplan_detail_type = $row["dialplan_detail_type"];
}
if (!preg_match("/spawn/i", $row["dialplan_detail_type"])) {
	$dialplan_detail_type = $row["dialplan_detail_type"];
}
```

Equivalent logic is applied to `dialplan_detail_data`.

The conditions do not combine to reject either family. Instead, each condition can assign the value independently:

| Submitted value | `system` condition | `spawn` condition | Stored result |
|---|---|---|---|
| `system` | Assignment skipped | Assignment performed | Accepted |
| `bgsystem` | Assignment skipped | Assignment performed | Accepted |
| `spawn` | Assignment performed | Assignment skipped | Accepted |
| `bg_spawn` | Assignment performed | Assignment skipped | Accepted |
| `spawn_stream` | Assignment performed | Assignment skipped | Accepted |

The variables are also not initialized defensively for each submitted detail, creating a possibility of stale values carrying between iterations.

### Executable XML generation

The accepted type and data are saved. The dialplan generator later writes them into FreeSWITCH XML without applying the intended restriction again:

```php
if ($dialplan_detail_tag == "action") {
	$xml .= "\t\t<action application=\"" . $dialplan_detail_type .
		"\" data=\"" . $dialplan_detail_data . "\"" . $detail_inline . "/>\n";
}
```

When the direct system application is available, the resulting XML can be equivalent to:

```xml
<action application="system" data="/usr/bin/touch /dev/shm/fusionpbx-rce-poc-UNIQUE"/>
```

Once a call matches that dialplan condition, FreeSWITCH invokes the action under its service identity.

## The exact security option

### Direct `system` dialplan action

The direct application path covered by this advisory requires:

```text
disable_system_app_commands=false
```

In **Advanced → Variables → Security**, the variable record remains enabled:

```text
Name:    disable_system_app_commands
Value:   false
Enabled: true
```

The secure shipped state is:

```text
Name:    disable_system_app_commands
Value:   true
Enabled: true
```

The generated XML appears as an enabled preprocessor variable:

```xml
<X-PRE-PROCESS cmd="set"
 data="disable_system_app_commands=true"
 category="Security"
 enabled="true"/>
```

Changing only the database or generated XML is not necessarily sufficient for immediate execution. FreeSWITCH must consume the new XML, and `mod_dptools` must load while the effective value permits system applications.

### API-expansion variant

A separate PoC technique can place `${system(...)}` inside data for an otherwise ordinary action such as `set`. That is not the same execution path. It requires:

```text
disable_system_api_commands=false
```

It also requires the API command to be registered after the configuration change and FreeSWITCH API expansion to be enabled at runtime. Enabling only `disable_system_app_commands=false` does not satisfy the API-expansion prerequisites.

Public descriptions and reproduction instructions should identify which variant they use.

## Permissions and authentication

The affected dialplan page accepts sessions holding at least one relevant dialplan, inbound-route, or outbound-route editing permission. In the reviewed stock application configuration, those permissions are assigned to `superadmin`.

The configuration and module-management permissions needed to change and activate the global FreeSWITCH system-command controls are also assigned to `superadmin` by default. An attacker does not necessarily require the literal username and password: a stolen authenticated session, compromised SSO session, or other superadmin-equivalent authentication state can satisfy the authentication prerequisite.

Ordinary `admin` and `user` roles do not receive the complete chain under the reviewed stock permission assignments. Custom deployments may delegate permissions differently.

## Exploitation prerequisites

For the direct `system` application path, all of the following must be true:

1. The actor has an authenticated session with a qualifying dialplan or route-editing permission.
2. FusionPBX accepts and stores the prohibited action through the validation defect.
3. `disable_system_app_commands` has the effective value `false`.
4. FreeSWITCH has reloaded XML and `mod_dptools` was loaded after the unsafe value became effective.
5. The actor can cause a call or synthetic call to reach the stored dialplan condition.
6. The requested command is permitted by the FreeSWITCH service account's operating-system privileges and confinement.

The system-command interface could already be enabled because of local configuration drift. Otherwise, changing and activating it requires superadmin-equivalent application privileges and, depending on the deployment and selected activation method, host-level service management.

## Attack scenario

In the strongest stock-role scenario, a threat actor first compromises a FusionPBX `superadmin` authentication state. The actor uses administrative access to place the applicable security variable into its unsafe state, activates that state in FreeSWITCH, submits a prohibited dialplan action through the flawed handler, and triggers the matching route. The command then executes as the FreeSWITCH service account rather than as the remote browser user.

This is a post-superadmin-compromise scenario. Whether transition from FusionPBX `superadmin` to operating-system execution as the FreeSWITCH service account constitutes a security boundary is part of the product threat model. The vendor's response indicates that it does not consider this chain a vulnerability.

A custom deployment presents a different risk if it delegates dialplan editing to a role that is not intended to execute host commands while independently leaving system applications enabled.

## Proof of concept

A proof of concept has been created to execute a reverse shell as the current user.

## Laboratory results

Testing produced these materially different outcomes:

- FusionPBX accepted and retained prohibited dialplan content, confirming the validation bypass.
- The exact route could be triggered without a physical phone by originating a synthetic call in the test context.
- No marker was created while the required FreeSWITCH command capability was unavailable.
- A harmless marker was created after the applicable command capability was available and the stored route was triggered.
- The FreeSWITCH process in the laboratory ran as `www-data`, so the marker and resulting command inherited that account's privileges.

These results demonstrate conditional command execution, not default-installation exploitation.

## Impact

When all prerequisites are satisfied, an attacker can execute an operating-system command as the FreeSWITCH service account. Depending on local permissions and confinement, this may expose:

- Call recordings and voicemail accessible to the service account.
- FreeSWITCH configuration and runtime information.
- Telephony credentials or secrets readable by that account.
- Call-routing integrity and telephony availability.
- A starting point for host-specific local privilege escalation.

No claim is made that execution automatically provides root privileges. The tested execution identity was `www-data`.

## Severity assessment

The confirmed defect is an incomplete server-side restriction. Its runtime impact is strongly configuration- and privilege-dependent.

Suggested description:

> Defense-in-depth dialplan validation bypass with conditional authenticated OS command execution after a superadmin-equivalent actor enables a secure-by-default FreeSWITCH system-command interface.

Reasonable severity interpretations include:

- **Informational or Low** for the reviewed stock permission and configuration model, where system applications are disabled and the complete chain requires a fully trusted `superadmin`.
- **Medium** in a documented custom deployment where route editing is delegated across an intended application-to-host boundary and system applications are independently enabled.
- **Potentially higher only with additional evidence**, such as a lower-privileged method to change the variables or activate the runtime component, or a bypass that works while the shipped protections remain enabled.

This advisory intentionally does not reuse the earlier proposed High CVSS rating because it did not adequately represent the secure defaults and activation prerequisites later confirmed during testing and vendor correspondence.

## Vendor position

The vendor pointed to these settings in the FusionPBX FreeSWITCH variable template:

```text
disable_system_api_commands=true
disable_system_app_commands=true
```

It noted that both are enabled and secure by default and that repository history shows they were introduced several years before this report. On that basis, the vendor does not consider the conditional chain a vulnerability.

This publication preserves that position and does not describe stock installations as directly vulnerable to RCE.

## Remediation and hardening

FreeSWITCH's independent controls reduce impact, but the web handler should still enforce the restriction it expresses.

Recommended changes:

1. Replace the independent negative conditions with an exact allowlist of applications permitted through the structured editor.
2. Initialize all detail variables on every loop iteration and reject the complete request when validation fails.
3. Apply the same validator to structured editing, raw XML paths, imports, copies, and API/database write paths.
4. Create a distinct, clearly named permission if host-command applications are intentionally supported through the web interface.
5. Keep both `disable_system_app_commands` and `disable_system_api_commands` enabled with values of `true`.
6. Restrict module management and global variable editing to trusted host-impacting administrators.
7. Run FreeSWITCH under a dedicated, minimally privileged account with AppArmor, SELinux, or equivalent confinement where practical.
8. Monitor dialplan details and generated XML for unexpected command-execution applications.

An allowlist is preferable to another substring denylist because FreeSWITCH applications and expansion behavior can evolve.

## Detection guidance

A read-only PostgreSQL query can identify stored direct command applications:

```sql
SELECT
    d.domain_name,
    p.dialplan_uuid,
    p.dialplan_name,
    dd.dialplan_detail_uuid,
    dd.dialplan_detail_type,
    dd.dialplan_detail_data,
    dd.update_date
FROM v_dialplan_details AS dd
JOIN v_dialplans AS p ON p.dialplan_uuid = dd.dialplan_uuid
LEFT JOIN v_domains AS d ON d.domain_uuid = p.domain_uuid
WHERE lower(trim(dd.dialplan_detail_type)) IN
      ('system', 'bgsystem', 'spawn', 'bg_spawn', 'spawn_stream')
ORDER BY dd.update_date DESC NULLS LAST;
```

Results should be reviewed rather than automatically deleted because an administrator may have created intentional historical entries. Correlate results with FusionPBX audit logs, web requests to the dialplan editor, FreeSWITCH logs, and host process telemetry.

## Safe verification and cleanup

Use an isolated domain, a non-routable trigger, and a fixed marker command. Do not route the test through a billable gateway. Record both security-variable values before testing.

After testing:

1. Restore both system-command variables to their original values; on a secure installation both should be enabled and `true`.
2. Reload or restart FreeSWITCH so the secure state is effective at runtime.
3. Delete the exact PoC dialplan through Dialplan Manager.
4. Remove only the exact marker created for the test.
5. Verify that no `system`, `bgsystem`, `spawn`, `bg_spawn`, or `spawn_stream` API/application interfaces remain unexpectedly available.

## Disclosure conclusion

Two facts coexist:

1. FusionPBX's structured dialplan handler accepts applications that its own code explicitly attempts to prohibit.
2. FusionPBX's shipped FreeSWITCH configuration independently blocks those command interfaces unless a trusted administrator changes the configuration and activates the relevant runtime component.

The first is a genuine validation defect. The second materially limits exploitability and explains the vendor's disposition. Any public description should include both.
