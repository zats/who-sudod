# Who Sudo

Who Sudo adds a passive process panel behind and beside the macOS administrator authentication dialog. Its background extends 20 points around the dialog, continues behind it, and leaves 20 points between the dialog and process content. Its content appears on the right when space permits and moves to the left near the right screen edge. It follows the dialog, hides when the dialog is not focused, and shows the likely live `/usr/bin/sudo` request with its parent tree.

The requested command does not normally start until authentication succeeds. Who Sudo therefore shows it as a pending row with no numeric PID. This row comes from the live sudo command line; it is not presented as a live child process. Any actual descendants use numeric PIDs. Process names use the containing app bundle's display name when the executable is the app's main executable.

The 46-point envelope corner radius is the measured 26-point SecurityAgent dialog radius plus the 20-point inset. This keeps the inner and outer corner curves concentric.

The app does not modify SecurityAgent, `sudo`, PAM, or system files. SIP can stay enabled. All process inspection stays on the Mac.

## Run

1. Open `WhoSudo.xcodeproj` and run the `WhoSudo` scheme, or build it from Terminal:

   ```sh
   xcodegen generate
   xcodebuild -project WhoSudo.xcodeproj -scheme WhoSudo -configuration Debug -derivedDataPath .build build
   open .build/Build/Products/Debug/WhoSudo.app
   ```

2. The bundled Permiso assistant opens **System Settings > Privacy & Security > Device Control and Data Access** and shows how to add Who Sudo. This category is named **Accessibility** on older macOS versions. Until access is allowed, Who Sudo does not inspect processes or show the companion window. This access lets the app verify the focused SecurityAgent window. It does not let Who Sudo enter or read a password.
3. Run a command that needs fresh authentication, for example `sudo -k && sudo -v`.

Who Sudo runs as a menu bar app. Its key icon shows the current monitor state.

## Attribution limit

This build uses the public kernel process table and `libproc`. It finds live `/usr/bin/sudo` processes for the signed-in user and walks each POSIX parent PID. When a dialog appears, the panel selects a likely request and keeps that `(PID, start time)` identity pinned while it remains live. It ignores later overlapping sudo processes and drops the pinned request when it exits.

The app reads the pending invocation through Apple's `/bin/ps` because macOS blocks an unprivileged process from reading the effective-root sudo argument data directly. The `ps` result is display text and can lose exact argument boundaries. The row is therefore a readable requested command, not a guaranteed structured argument vector.

macOS does not provide a public transaction identifier that connects a SecurityAgent window to its requester. Exact attribution for every Authorization Services request needs an Endpoint Security client with Apple's restricted `com.apple.developer.endpoint-security.client` entitlement, root operation, and Full Disk Access. The local signing assets do not contain that entitlement. The parent tree is accurate for the selected live process, but its connection to one dialog remains heuristic when requests overlap.

## Test

```sh
xcodebuild -project WhoSudo.xcodeproj -scheme WhoSudo -destination 'platform=macOS' -derivedDataPath .build test
```
