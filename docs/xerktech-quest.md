# Quest client for the xerktech fork

This fork changes the wire protocol (AES-GCM stream integrity, pinned server identity key),
and the protocol hash covers it. The Horizon store WiVRn client is refused at handshake by a
server built from this fork ("Incompatible server version"). The Quest needs the fork's own
APK, built from the same commit as the server.

## Server and APK move together

- The APK and `wivrn-server` must be built from the **same commit**.
- Whenever the server pin is bumped (fenrir's vr image), install the APK released for that
  commit in the same change. A mismatch fails at handshake.
- Releases are tagged `apk-<full commit sha>` on
  <https://github.com/xerktech/WiVRn/releases>.

## Publishing an APK

- Every push to `master` runs `.github/workflows/APK-Release.yml` and publishes
  `apk-<sha>` for that commit.
- For any other commit: Actions → "Release APK Only" → Run workflow, `ref` = the full
  40-character commit sha (a short sha is looked up as a branch name and fails).
  Or `gh workflow run APK-Release.yml -R xerktech/WiVRn -f ref=<sha>`.
- The workflow refuses to run without the `APK_SIGNINGKEYPASSWORD` and `APK_KEYSTORE_BASE64`
  repository secrets: an unsigned APK cannot be installed.
- Keep the signing key forever. A release signed with a different key cannot update an
  installed one: you must uninstall, which deletes the pinned server key, so you re-pair.

### Creating the signing key (once)

```bash
umask 077
P=$(openssl rand -hex 24)
keytool -genkeypair -keystore ks.keystore -storetype PKCS12 -alias default_key \
  -keyalg RSA -keysize 4096 -validity 36500 -storepass "$P" -keypass "$P" \
  -dname "CN=WiVRn XerkTech, O=XerkTech"
printf %s "$P" | gh secret set APK_SIGNINGKEYPASSWORD -R xerktech/WiVRn
base64 -w0 ks.keystore | gh secret set APK_KEYSTORE_BASE64 -R xerktech/WiVRn
```

Back up `ks.keystore` and the password somewhere durable, then delete the local copy.
The alias must be `default_key` (see `signingConfigs` in `build.gradle`).

## Sideloading onto a Quest 3

1. Enable developer mode: in the Meta Horizon phone app, Devices → the headset →
   Headset settings → Developer mode → on. (The Meta account needs a developer
   organisation, created once at <https://developer.oculus.com/manage/organizations/create/>.)
2. Reboot the headset, connect it over USB-C, and accept "Allow USB debugging" in the headset.
3. Check it is visible: `adb devices` lists it as `device` (not `unauthorized`).
4. Download the APK for the server's commit and install it:

   ```bash
   SHA=<commit the server is built from>
   gh release download "apk-$SHA" -R xerktech/WiVRn -p '*.apk'
   adb install -r "wivrn-xerktech-$SHA.apk"
   ```

5. Launch it from Library → Applications → Unknown Sources → "WiVRn XerkTech".
6. First connection: enter the PIN the server shows. The headset then pins that server's key
   and refuses any other server.

Notes:

- The package is `org.meumeu.wivrn.xerktech`, so it installs beside the store client
  (`org.meumeu.wivrn`) rather than replacing it. Uninstall the store client to avoid
  launching the wrong one.
- `adb install -r` keeps app data, so the pinned server key survives an upgrade.
- The version code is the commit count, so `adb install -r` refuses an older commit's APK
  (`INSTALL_FAILED_VERSION_DOWNGRADE`). Rolling the server pin back means
  `adb uninstall org.meumeu.wivrn.xerktech`, installing the older APK, and re-pairing.
- Wireless adb (after the first USB connection): `adb tcpip 5555`, then
  `adb connect <headset-ip>:5555`.
