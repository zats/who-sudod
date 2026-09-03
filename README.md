# Who Sudo'd

Who Sudo'd adds a passive process panel beside macOS authentication requests. It detects dialogs from SecurityAgent and the LocalAuthentication UI agent. It also detects an interactive `/usr/bin/sudo` process that waits for a hidden password in a terminal, even though macOS does not show a system dialog. For a system dialog, the panel background extends 20 points around the dialog and continues behind it. For a terminal password request, the standalone panel stays tied to the focused window of the nearest active ancestor app. The panel shows the observed or likely live requester with its parent and descendant processes.

The requested command does not normally start until authentication succeeds. Who Sudo'd therefore shows it as a pending row with no numeric PID. This row comes from the live sudo command line; it is not presented as a live child process. Any actual descendants use numeric PIDs. Process names use the containing app bundle's display name when the executable is the app's main executable.

The 46-point envelope corner radius is the measured 26-point SecurityAgent dialog radius plus the 20-point inset. This keeps the inner and outer corner curves concentric.

The app does not modify SecurityAgent or the `sudo` executable. Its optional PAM Password Input feature installs a signed PAM module, a signed terminal reader, and two owned lines around the standard password entry in `/etc/pam.d/sudo`. Install, repair, and uninstall are explicit actions in **Settings > General**. A signed helper requests macOS administrator authorization for each change. It keeps all other PAM entries and their order. It refuses a PAM configuration that it cannot update without changing password behavior. SIP can stay enabled. All process inspection and password transfer stay on the Mac.

## Run

1. Generate the ignored Xcode project from `project.yml`:

   ```sh
   Tools/generate-project.zsh
   ```

2. Open `WhoSudod.xcodeproj` and run the `WhoSudod` scheme, or build and open the app from Terminal:

   ```sh
   xcodebuild -project WhoSudod.xcodeproj -scheme WhoSudod -configuration Debug -derivedDataPath .build build
   open ".build/Build/Products/Debug/Who Sudo'd.app"
   ```

3. The bundled Permiso assistant opens **System Settings > Privacy & Security > Device Control and Data Access** and shows how to add Who Sudo'd. This category is named **Accessibility** on older macOS versions. Until access is allowed, Who Sudo'd does not inspect processes or show the companion window. Accessibility access lets the app verify and follow the system authentication window. It does not let the app read a password.
4. To use the app as an optional password input for terminal `sudo`, open **Settings > General** and select **Install…**. macOS asks for administrator approval, and the app's signed helper makes the change. A restart is not required.
5. Start an operation that needs authentication. Examples include `sudo -k /bin/echo who-sudod-check`, an Authorization Services request, or an app that uses LocalAuthentication.

Who Sudo'd runs as a menu bar app. Its key icon shows the current monitor state.

## Attribution

Who Sudo'd monitors narrow unified-log records from LocalAuthentication and Authorization Services. A LocalAuthentication evaluation record supplies the client PID and executable path. An Authorization Services shell record supplies the caller PID. The app then checks that PID, executable path, start time, and real user against the live kernel process table before it displays the process tree. It keeps the observed `(PID, start time)` identity pinned while the request remains active. If an observed requester exits first, the panel retains its last known tree.

SecurityAgent windows are verified by their exact Apple executable path and Core Graphics window metadata. LocalAuthentication secure windows are not present in the Core Graphics window list on current macOS. For those windows, the app verifies the exact `coreautha` or LocalAuthentication remote-service executable and reads its focused Accessibility window frame.

Some `sudo` prompts do not provide a usable direct caller record. For these prompts, the app uses a heuristic fallback. For a terminal password request, it requires an exact `/usr/bin/sudo` process for the signed-in user, effective root access, a controlling terminal, ownership of the terminal foreground process group, disabled terminal echo, canonical terminal input, and no started child command. Canonical input separates a sudo password read from shells such as fish, which can disable echo while they edit in noncanonical mode. The app confirms the change into this password-input mode when it sees that change. If the first scan of a new terminal occurs during a new prompt for an external command, it can instead confirm the complete password-input state across three scans. That no-baseline fallback applies only to a `sudo` process that is at most five seconds old. The app reads terminal settings only. It does not read terminal bytes. It does not use this fallback for a LocalAuthentication-only window.

The app reads the pending invocation through Apple's `/bin/ps` because macOS blocks an unprivileged process from reading the effective-root sudo argument data directly. The `ps` result is display text and can lose exact argument boundaries. The row is therefore a readable requested command, not a guaranteed structured argument vector.

macOS does not provide a general mapping from a terminal device to an app window or tab. The panel therefore does not claim exact tab attribution. If the user changes to another existing window in the same app, the panel hides instead of moving to that window.

Without the optional PAM feature, the app does not read authentication payloads, passwords, or text-field values. When the feature is installed, a signed PAM module offers app input only after the PAM stack reaches the standard account-password prompt. A successful Touch ID, smart-card, YubiKey, or other earlier `sufficient` PAM method bypasses this path. The signed terminal reader supplies the normal hidden password input at the same time as the app. The first complete password wins, and **Use Terminal** removes only the app option. Who Sudo'd sends an app-entered password directly to the waiting PAM conversation and does not log or store it. Other prompt text and multi-prompt conversations use the original PAM conversation only.

The optional input path does not run for `sudo -n`, `sudo -S`, or `sudo -A`. After the app accepts a request, the terminal reader uses a plain `Password:` prompt and a five-minute input limit. It cannot preserve a custom `sudo -p` prompt, `SUDO_PROMPT`, `pwfeedback`, a configured password timeout, or prompt bells. If the helper cannot start after the app route is ready, authentication stops with a conversation error instead of showing a second password prompt.

The unified-log record format is an observed macOS interface, not a documented stable API, so a future macOS release can require parser updates. macOS also does not supply a public transaction identifier that joins every visible dialog to one requester. The app uses the dialog type and a narrow time window for that join. A process can imitate a LocalAuthentication client log record, so the app describes log attribution as observed, not verified. Overlapping requests can remain ambiguous, and the `sudo` fallback is only a live-process heuristic.

## Test

```sh
Tools/generate-project.zsh
xcodebuild -project WhoSudod.xcodeproj -scheme WhoSudod -destination 'platform=macOS' -derivedDataPath .build test
Tools/test-pam.zsh
```

Run the deterministic password-only sudo check after Accessibility access is enabled:

```sh
Tools/check-auth-live-tree.zsh terminal-password
```

The check creates a private terminal, starts a real password-waiting `sudo`, compares every displayed row with the expected live process tree, cancels the request, and confirms that the panel hides. It does not enter or read a password.
