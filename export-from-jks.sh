#!/bin/bash
#
#

# Set environment variables
set -u
export JKS_CN="MC-OAuthServer"
export JKS_OU="Authorization Server"
export JKS_O="Multicode"
export JKS_L="GO"
export JKS_ST="Goiania"
export JKS_C="BR"

export KEYSTORE_ALIAS=""
export KEYSTORE_FILE_PATH="./${KEYSTORE_ALIAS}.jks"
export KEYSTORE_PASSWORD=""

# Export pub cert from jks
keytool -export -alias $KEYSTORE_ALIAS -keystore $KEYSTORE_FILE_PATH -rfc -file test.pem -storepass $KEYSTORE_PASSWORD



# Unset environment variables
set +u
unset KEYSTORE_ALIAS
unset KEYSTORE_PASSWORD
unset KEYSTORE_FILE_PATH