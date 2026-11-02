# Checks the macOS signing secrets of desktop-macos.yml before Tauri signs with them, and writes the files that
# scripts/bundle.mjs and Tauri take (docs/DEVELOPMENT.md, "Signing the macOS app"). Sourced by the workflow's signing
# step, in bash:
#
#   source apps/desktop/scripts/prepare-signing.sh <private directory> <bundle identifier>
#
# It reads APPLE_CERTIFICATE (a base64 .p12) with APPLE_CERTIFICATE_PASSWORD, APPLE_TEAM_ID,
# APPLE_PROVISIONING_PROFILE_BASE64, APPLE_API_KEY and APPLE_API_PRIVATE_KEY, and fails with an error that names the
# secret at fault: Tauri's own import of the certificate says only "The user name or passphrase you entered is not
# correct", for a wrong password and for a wrong file alike, and a wrong profile is signed into the app without
# complaint. It exports APPLE_SIGNING_IDENTITY, the name of the certificate, which Tauri requires to be exactly that
# (an APPLE_SIGNING_IDENTITY secret is needed only when OpenSSL cannot read the certificate), and
# APPLE_PROVISIONING_PROFILE and APPLE_API_KEY_PATH, files in the directory, which the caller deletes. Tauri imports
# APPLE_CERTIFICATE itself, as it is.

# The step runs with -e, which would end it at a failing command substitution before its message: every check that
# may fail is part of an || list.
prepare_signing() {
  local dir="$1" identifier="$2" openssl o
  fail() {
    echo "::error::$*"
    return 1
  }

  # OpenSSL 3 or later with its legacy provider (`-legacy`), not the system's LibreSSL: Keychain Access exports a
  # .p12 under RC2-40 and 3DES, OpenSSL 3 under AES, and only the legacy provider reads RC2.
  for o in /opt/homebrew/opt/openssl@3/bin/openssl openssl /opt/homebrew/opt/openssl@4/bin/openssl; do
    if [[ "$("${o}" version 2>/dev/null)" =~ ^OpenSSL\ [3-9] ]]; then
      openssl="${o}"
      break
    fi
  done
  [[ -n "${openssl}" ]] || fail "OpenSSL 3 or later is missing on the runner." || return 1

  # The certificate. A password that does not open it fails; a .p12 that this OpenSSL cannot read for another reason
  # skips the checks of the certificate, and `security import` judges it.
  local certificate=
  (umask 077 && base64 --decode <<<"${APPLE_CERTIFICATE}" >"${dir}/given.p12") ||
    fail "APPLE_CERTIFICATE is not base64: set it from \`base64 -i <file>.p12\`." || return 1
  echo "APPLE_CERTIFICATE: $(wc -c <"${dir}/given.p12" | tr -d ' ') bytes, SHA-256" \
    "$(shasum -a 256 "${dir}/given.p12" | cut -d ' ' -f 1)"
  if (umask 077 && "${openssl}" pkcs12 -legacy -in "${dir}/given.p12" -passin env:APPLE_CERTIFICATE_PASSWORD \
    -nodes -out "${dir}/identity.pem" 2>"${dir}/openssl.log"); then
    certificate="${dir}/certificate.pem"
  elif grep -q 'Mac verify error' "${dir}/openssl.log"; then
    fail "APPLE_CERTIFICATE_PASSWORD does not open APPLE_CERTIFICATE. If the SHA-256 above is not the one that" \
      "\`shasum -a 256 <file>.p12\` prints for the exported certificate, set APPLE_CERTIFICATE again from that file;" \
      "if it is, set APPLE_CERTIFICATE_PASSWORD again." || return 1
  else
    echo "::warning::OpenSSL could not read APPLE_CERTIFICATE, so it is not checked: $(head -n 3 "${dir}/openssl.log")"
  fi
  if [[ -n "${certificate}" ]]; then
    "${openssl}" pkey -in "${dir}/identity.pem" -noout 2>/dev/null ||
      fail "APPLE_CERTIFICATE has no private key: export the identity (the certificate with its key) from" \
        "Keychain Access, not the certificate alone." || return 1
    "${openssl}" pkcs12 -legacy -in "${dir}/given.p12" -passin env:APPLE_CERTIFICATE_PASSWORD -clcerts -nokeys \
      2>/dev/null | "${openssl}" x509 -out "${certificate}" 2>/dev/null ||
      fail "APPLE_CERTIFICATE has no certificate for its key." || return 1
    local name
    name="$("${openssl}" x509 -in "${certificate}" -noout -subject -nameopt multiline |
      sed -n 's/^ *commonName *= *//p')"
    echo "APPLE_CERTIFICATE: ${name}, until $("${openssl}" x509 -in "${certificate}" -noout -enddate |
      cut -d = -f 2)"
    [[ "${name}" == "Developer ID Application: "*"(${APPLE_TEAM_ID})" ]] ||
      fail "APPLE_CERTIFICATE is \"${name}\", not a Developer ID Application certificate of team ${APPLE_TEAM_ID}." ||
      return 1
    if [[ -n "${APPLE_SIGNING_IDENTITY}" && "${APPLE_SIGNING_IDENTITY}" != "${name}" ]]; then
      echo "::warning::APPLE_SIGNING_IDENTITY is not the certificate's name, which is used instead: \"${name}\"."
    fi
    export APPLE_SIGNING_IDENTITY="${name}"
  else
    [[ -n "${APPLE_SIGNING_IDENTITY}" ]] ||
      fail "Set APPLE_SIGNING_IDENTITY to the name of APPLE_CERTIFICATE's certificate, which OpenSSL could not read." ||
      return 1
  fi
  rm -f "${dir}/given.p12" "${dir}/identity.pem" "${dir}/openssl.log"

  # The provisioning profile: a Developer ID profile of this app, with the associated domains, made for this
  # certificate. Any other one is signed into the app without complaint, and the app then fails to launch.
  (umask 077 && base64 --decode <<<"${APPLE_PROVISIONING_PROFILE_BASE64}" >"${dir}/segv.provisionprofile") ||
    fail "APPLE_PROVISIONING_PROFILE_BASE64 is not base64: set it from \`base64 -i <file>.provisionprofile\`." ||
    return 1
  security cms -D -i "${dir}/segv.provisionprofile" -o "${dir}/profile.plist" 2>/dev/null ||
    fail "APPLE_PROVISIONING_PROFILE_BASE64 is not a provisioning profile." || return 1
  local plist=(/usr/libexec/PlistBuddy -c) app_id all i der found=
  app_id="$("${plist[@]}" "Print :Entitlements:com.apple.application-identifier" "${dir}/profile.plist" 2>/dev/null)" ||
    true
  echo "APPLE_PROVISIONING_PROFILE_BASE64: \"$("${plist[@]}" "Print :Name" "${dir}/profile.plist" 2>/dev/null)\"" \
    "for ${app_id}, until $("${plist[@]}" "Print :ExpirationDate" "${dir}/profile.plist" 2>/dev/null)"
  [[ "${app_id}" == "${APPLE_TEAM_ID}.${identifier}" ]] ||
    fail "APPLE_PROVISIONING_PROFILE_BASE64 is a profile of ${app_id:-no app}, not of ${APPLE_TEAM_ID}.${identifier}." ||
    return 1
  all="$("${plist[@]}" "Print :ProvisionsAllDevices" "${dir}/profile.plist" 2>/dev/null)" || true
  [[ "${all}" == true ]] ||
    fail "APPLE_PROVISIONING_PROFILE_BASE64 is a development profile, which lists the Macs it runs on: make a" \
      "Developer ID profile." || return 1
  "${plist[@]}" "Print :Entitlements:com.apple.developer.associated-domains" "${dir}/profile.plist" >/dev/null 2>&1 ||
    fail "APPLE_PROVISIONING_PROFILE_BASE64 lacks Associated Domains: enable it for ${identifier} and make the" \
      "profile again." || return 1
  if [[ -n "${certificate}" ]]; then
    local cert
    cert="$("${openssl}" x509 -in "${certificate}" -outform der | shasum -a 256 | cut -d ' ' -f 1)"
    for ((i = 0; ; i++)); do
      der="$(plutil -extract "DeveloperCertificates.${i}" raw -o - "${dir}/profile.plist" 2>/dev/null)" || break
      [[ "$(base64 --decode <<<"${der}" | shasum -a 256 | cut -d ' ' -f 1)" == "${cert}" ]] && found=1
    done
    [[ -n "${found}" ]] ||
      fail "APPLE_PROVISIONING_PROFILE_BASE64 was not made for APPLE_CERTIFICATE's certificate: make the profile" \
        "again with it." || return 1
  fi
  rm -f "${dir}/profile.plist" "${dir}/certificate.pem"
  export APPLE_PROVISIONING_PROFILE="${dir}/segv.provisionprofile"

  # The App Store Connect API key, for notarization: a team key, whose issuer ID is a UUID (an individual key has none,
  # and Tauri notarizes only with an issuer), its 10-character key ID and its .p8 file.
  local uuid='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' id='^[A-Z0-9]{10}$'
  if [[ "${APPLE_API_ISSUER}" =~ ${id} && "${APPLE_API_KEY}" =~ ${uuid} ]]; then
    fail "APPLE_API_KEY and APPLE_API_ISSUER are swapped: the key ID is 10 characters, the issuer ID a UUID." ||
      return 1
  fi
  [[ "${APPLE_API_ISSUER}" =~ ${uuid} ]] ||
    fail "APPLE_API_ISSUER is not an issuer ID (a UUID): App Store Connect shows it above the team keys under Users" \
      "and Access › Integrations › App Store Connect API. An individual key has none: make a team key." || return 1
  [[ "${APPLE_API_KEY}" =~ ${id} ]] ||
    fail "APPLE_API_KEY is not a key ID (10 letters and digits, as in AuthKey_<key ID>.p8)." || return 1
  (umask 077 && printf '%s\n' "${APPLE_API_PRIVATE_KEY}" >"${dir}/AuthKey_${APPLE_API_KEY}.p8")
  "${openssl}" pkey -in "${dir}/AuthKey_${APPLE_API_KEY}.p8" -noout 2>/dev/null ||
    fail "APPLE_API_PRIVATE_KEY is not the content of an AuthKey_<key ID>.p8 file." || return 1
  export APPLE_API_KEY_PATH="${dir}/AuthKey_${APPLE_API_KEY}.p8"
}

prepare_signing "$@"
