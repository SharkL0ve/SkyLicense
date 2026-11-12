#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
base_dir=$PWD
case "${1:-}" in
  setup)
    java -cp SkyLicense-basic.jar SetupLocal.java server runtime
    java -cp SkyLicense-basic.jar SetupLocal.java client customer
    ;;
  server)
    cd runtime
    export SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE="$PWD/secrets/operation-log-hmac.txt"
    export SKYLICENSE_MFA_ENCRYPTION_KEY_FILE="$PWD/secrets/mfa-encryption-key.txt"
    unset SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE
    if [ ! -f web_magiclicense.db ]; then
      export SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE="$PWD/secrets/bootstrap-admin.txt"
    fi
    java -jar ../SkyLicense-Server.jar --validate-config
    exec java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -jar ../SkyLicense-Server.jar
    ;;
  license)
    cd customer
    export SKYLICENSE_LICENSE_FILE_SECRET_FILE="$PWD/secrets/license-file-secret.txt"
    exec java -cp ../SkyLicense-basic.jar cn.sky.license.LicenseFileTool ./license.dat
    ;;
  client)
    cd customer
    export SKYLICENSE_LICENSE_FILE_SECRET_FILE="$PWD/secrets/license-file-secret.txt"
    export SKYLICENSE_BASIC_CA_CERT_FILE="$PWD/ca-cert.pem"
    exec java -cp '.:../SkyLicense-basic.jar' cn.sky.license.BasicLauncher "${2:-localhost:13331}" "${3:-DemoApp}" "${4:-1.0.0}"
    ;;
  *) echo 'usage: sh run.sh setup|server|license|client [host:port program version]' >&2; exit 1 ;;
esac
