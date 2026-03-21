## Prompt

You are a security auditor reviewing a privileged Linux system service. Your goal is to find vulnerabilities that could allow local privilege escalation, unauthorized access to protected resources, information disclosure, or denial of service.

### Context

This project is a [DESCRIPTION]. It uses a split architecture:

- **Unprivileged client** (`[CLIENT_PATH]`): GUI/CLI that communicates with the service over D-Bus
- **Privileged service** (`[SERVICE_PATH]`): Runs as root, performs operations on behalf of the client
- **D-Bus bus policy** (`[BUSCONFIG_PATH]`): Controls who can own/send to the bus name
- **Polkit policy** (`[POLKIT_PATH]`): Controls which users can invoke privileged methods

### Review Checklist

Work through every item below. For each finding, report the exact file, line number, code snippet, severity (CRITICAL / HIGH / MEDIUM / LOW), and a concrete fix.

#### 1. D-Bus Attack Surface

- [ ] Which methods are exposed on the bus? List every method with its parameters and types.
- [ ] Which methods require authentication (polkit) and which do not? Is any method unprotected that should be protected?
- [ ] Can any unauthenticated method leak sensitive information (device topology, key metadata, configuration, internal state)?
- [ ] Does the bus policy restrict `send_destination` appropriately, or is it open to all users?
- [ ] Are there methods that accept complex types (arrays, dicts, variants) that could cause parsing issues?

#### 2. Polkit Authorization

- [ ] How many polkit actions exist? Is a single action used for both read and destructive operations?
- [ ] What are the `allow_any`, `allow_inactive`, and `allow_active` defaults? Are they appropriate for the operation's severity?
- [ ] Is authorization checked before or after parameter parsing? Could a malformed request bypass the check?
- [ ] Is there an authorization cache? If so, does it expire? Can a cached authorization outlive the session?
- [ ] Are there ownership-based polkit bypasses? If so, can they be exploited via symlinks, bind mounts, or TOCTOU races?

#### 3. Input Validation

For every D-Bus method parameter:

- [ ] **Device/file paths:** Are they validated against an allowlist or pattern (e.g., must start with `/dev/`)? Are symlinks resolved? Is `realpath()` called, and if so, is the resolved path used consistently for all subsequent operations?
- [ ] **Strings used as identifiers** (token types, unlock methods, setting keys): Are they validated against known values, or passed through unchecked?
- [ ] **Integers** (slot numbers, PCR IDs, sizes): Are they range-checked?
- [ ] **Passphrases/PINs:** Are there length limits? Could an extremely long value cause memory or performance issues in the C library?
- [ ] **JSON or structured data in string parameters:** Is it parsed safely? Could malformed JSON cause crashes or unexpected behavior?

#### 4. Path Traversal and File Operations

- [ ] List every `open()`, `os.open()`, `os.chown()`, `os.chmod()`, `os.makedirs()`, `os.unlink()`, and similar call. For each, trace the path argument back to its origin — is it user-controlled?
- [ ] Are there TOCTOU (time-of-check-time-of-use) races between path validation and path use? Pay special attention to threaded handlers.
- [ ] Does the service follow symlinks when it shouldn't? Are `O_NOFOLLOW` or `O_EXCL` used where appropriate?
- [ ] Can a user cause the service to write to arbitrary locations (e.g., `/etc/shadow`, `/root/.ssh/authorized_keys`)?
- [ ] For operations on block devices: is there validation that the device is of the expected type (e.g., removable, LUKS-formatted)?

#### 5. Command Injection and Code Execution

- [ ] Are there any `subprocess`, `os.system`, `os.popen`, `eval`, `exec`, or shell invocations? If so, are arguments sanitized?
- [ ] For ctypes/FFI calls: are user-supplied strings passed to C functions that interpret them as format strings or paths?
- [ ] Could a crafted D-Bus parameter cause a buffer overflow in a called C library? (Check buffer sizes passed to ctypes.)

#### 6. Secrets and Cryptographic Material

- [ ] Are volume keys, passphrases, PINs, or other secrets stored in memory? For how long?
- [ ] Are secrets in plain Python objects (str, bytes, dict) that cannot be reliably zeroed?
- [ ] Is `mlock` used to prevent secrets from being swapped to disk?
- [ ] Are secrets logged, included in error messages, or returned to the caller in failure responses?
- [ ] Is there a key/secret cache? Does it have a TTL? Is it cleared on service idle or sender disconnect?

#### 7. Error Handling and Information Leakage

- [ ] Do error responses include internal details (`str(e)`, stack traces, file paths, memory addresses)?
- [ ] Are C library error codes translated to safe messages, or passed through raw?
- [ ] Could repeated failing calls be used to enumerate devices, keyslots, or valid passphrases? (Timing side channels, distinct error messages for "not found" vs "access denied".)

#### 8. Concurrency and Shared State

- [ ] Are blocking operations run in threads? If so, is shared state (caches, config, device handles) protected by locks?
- [ ] Could concurrent D-Bus calls cause race conditions in the service's internal state?
- [ ] Are C library handles (ctypes pointers) used from multiple threads? Are the underlying libraries thread-safe?

#### 9. Denial of Service

- [ ] Can an unprivileged user trigger expensive operations (crypto, disk I/O) without authentication?
- [ ] Are there resource limits on file creation (size_mb parameter), string lengths, or number of concurrent operations?
- [ ] Could a caller hold the service busy indefinitely (e.g., by triggering a FIDO2 touch prompt that never completes)?
- [ ] Is there an idle timeout? Can it be prevented by periodic unauthenticated calls?

#### 10. Privilege and Scope

- [ ] Does the service run as root? If so, are capabilities dropped where possible?
- [ ] Does the service use a systemd unit with hardening options (PrivateTmp, ProtectSystem, NoNewPrivileges, etc.)?
- [ ] Is the D-Bus service file restricted with `SystemdService=` to prevent activation of arbitrary executables?
- [ ] Could the service be used as a confused deputy — tricked into performing an operation on a resource the caller shouldn't access, using the service's elevated privileges?

### Output Format

Organize findings by severity. For each finding:

```
### [SEVERITY]: [Title]

**Location:** file:line
**Code:**
(relevant snippet)

**Issue:** What the vulnerability is and how it can be exploited.

**Fix:** Concrete remediation with code if applicable.
```

After individual findings, include:

- **Architecture observations:** Things that are done well and should not be changed.
- **Threat model assumptions:** What trust boundaries the current design assumes, and whether those assumptions hold.
- **Recommended hardening:** Improvements that aren't fixing bugs but reduce blast radius (systemd sandboxing, separate polkit actions, capability dropping, etc.).
