# Checks the macOS signing secrets of desktop-macos.yml and prepares them for scripts/bundle.mjs and Tauri
# (docs/DEVELOPMENT.md, "Signing the macOS app"). Sourced by the workflow's signing step, in bash:
#
#   source apps/desktop/scripts/prepare-signing.sh <private directory> <bundle identifier>
#
# It reads APPLE_CERTIFICATE (a base64 .p12) with APPLE_CERTIFICATE_PASSWORD, APPLE_SIGNING_IDENTITY,
# APPLE_TEAM_ID, APPLE_PROVISIONING_PROFILE_BASE64, APPLE_API_KEY and APPLE_API_PRIVATE_KEY, and fails with an error
# that names the secret at fault. Then it exports:
#
# - APPLE_CERTIFICATE and APPLE_CERTIFICATE_PASSWORD again: the same identity, opened with OpenSSL and written anew
#   with a random password in the oldest form of PKCS#12 (3DES, an SHA-1 MAC), which `security import` reads on
#   every macOS. A .p12 exported by a newer macOS or OpenSSL than the runner's may use a form that the runner's
#   `security` rejects with "The user name or passphrase you entered is not correct", as a wrong password does.
# - APPLE_PROVISIONING_PROFILE and APPLE_API_KEY_PATH: files in the directory, which the caller deletes.

# The step runs with -e, which would end it at a failing command substitution before its message: every check that
# may fail is part of an || list.
prepare_signing() {
  local dir="$1" identifier="$2" openssl o
  fail() {
    echo "::error::$*"
    return 1
  }

  # OpenSSL 3 or later, not the system's LibreSSL: it reads every form of PKCS#12 that macOS and OpenSSL write.
  for o in openssl /opt/homebrew/opt/openssl@3/bin/openssl /opt/homebrew/opt/openssl@4/bin/openssl; do
    if [[ "$("${o}" version 2>/dev/null)" =~ ^OpenSSL\ [3-9] ]]; then
      openssl="${o}"
      break
    fi
  done
  [[ -n "${openssl}" ]] || fail "OpenSSL 3 or later is missing on the runner." || return 1

  # The certificate.
  (umask 077 && base64 --decode <<<"${APPLE_CERTIFICATE}" >"${dir}/given.p12") ||
    fail "APPLE_CERTIFICATE is not base64: set it from \`base64 -i <file>.p12\`." || return 1
  echo "APPLE_CERTIFICATE: $(wc -c <"${dir}/given.p12" | tr -d ' ') bytes, SHA-256" \
    "$(shasum -a 256 "${dir}/given.p12" | cut -d ' ' -f 1)"
  if ! (umask 077 && "${openssl}" pkcs12 -in "${dir}/given.p12" -passin env:APPLE_CERTIFICATE_PASSWORD -nodes \
    -out "${dir}/identity.pem" 2>"${dir}/openssl.log"); then
    sed 's/^/  /' "${dir}/openssl.log"
    fail "APPLE_CERTIFICATE_PASSWORD does not open APPLE_CERTIFICATE. If the SHA-256 above is not the one that" \
      "\`shasum -a 256 <file>.p12\` prints for the exported certificate, set APPLE_CERTIFICATE again; if it is," \
      "set APPLE_CERTIFICATE_PASSWORD again." || return 1
  fi
  "${openssl}" pkey -in "${dir}/identity.pem" -noout 2>/dev/null ||
    fail "APPLE_CERTIFICATE has no private key: export the identity (the certificate with its key) from" \
      "Keychain Access, not the certificate alone." || return 1
  "${openssl}" pkcs12 -in "${dir}/given.p12" -passin env:APPLE_CERTIFICATE_PASSWORD -clcerts -nokeys 2>/dev/null |
    "${openssl}" x509 -out "${dir}/certificate.pem" 2>/dev/null ||
    fail "APPLE_CERTIFICATE has no certificate for its key." || return 1
  local name
  name="$("${openssl}" x509 -in "${dir}/certificate.pem" -noout -subject -nameopt multiline |
    sed -n 's/^ *commonName *= *//p')"
  echo "APPLE_CERTIFICATE: ${name}, until $("${openssl}" x509 -in "${dir}/certificate.pem" -noout -enddate |
    cut -d = -f 2)"
  [[ "${name}" == "Developer ID Application: "*"(${APPLE_TEAM_ID})" ]] ||
    fail "APPLE_CERTIFICATE is \"${name}\", not a Developer ID Application certificate of team ${APPLE_TEAM_ID}." ||
    return 1
  if [[ ! "${APPLE_SIGNING_IDENTITY}" =~ ^[0-9A-Fa-f]{40}$ && "${APPLE_SIGNING_IDENTITY}" != "${name}" ]]; then
    fail "APPLE_SIGNING_IDENTITY is not the name of APPLE_CERTIFICATE's certificate, \"${name}\"." || return 1
  fi

  # The same identity, in the form that every `security import` reads, under a password of its own.
  local password
  password="$("${openssl}" rand -hex 24)"
  echo "::add-mask::${password}"
  (umask 077 && PASSWORD="${password}" "${openssl}" pkcs12 -export -in "${dir}/identity.pem" \
    -out "${dir}/signing.p12" -passout env:PASSWORD -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1) ||
    fail "OpenSSL could not write the certificate again." || return 1
  rm -f "${dir}/given.p12" "${dir}/identity.pem"
  APPLE_CERTIFICATE="$(base64 -i "${dir}/signing.p12")"
  APPLE_CERTIFICATE_PASSWORD="${password}"
  export APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD

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
  local cert
  cert="$("${openssl}" x509 -in "${dir}/certificate.pem" -outform der | shasum -a 256 | cut -d ' ' -f 1)"
  for ((i = 0; ; i++)); do
    der="$(plutil -extract "DeveloperCertificates.${i}" raw -o - "${dir}/profile.plist" 2>/dev/null)" || break
    [[ "$(base64 --decode <<<"${der}" | shasum -a 256 | cut -d ' ' -f 1)" == "${cert}" ]] && found=1
  done
  [[ -n "${found}" ]] ||
    fail "APPLE_PROVISIONING_PROFILE_BASE64 was not made for APPLE_CERTIFICATE's certificate: make the profile" \
      "again with it." || return 1
  rm -f "${dir}/profile.plist" "${dir}/certificate.pem"
  export APPLE_PROVISIONING_PROFILE="${dir}/segv.provisionprofile"

  # The App Store Connect API key, for notarization.
  (umask 077 && printf '%s\n' "${APPLE_API_PRIVATE_KEY}" >"${dir}/AuthKey_${APPLE_API_KEY}.p8")
  "${openssl}" pkey -in "${dir}/AuthKey_${APPLE_API_KEY}.p8" -noout 2>/dev/null ||
    fail "APPLE_API_PRIVATE_KEY is not the content of an AuthKey_<key ID>.p8 file." || return 1
  export APPLE_API_KEY_PATH="${dir}/AuthKey_${APPLE_API_KEY}.p8"
}

prepare_signing "$@"
