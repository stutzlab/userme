#!/bin/sh

echo "Starting Userme..."
set -x
userme \
     --loglevel=$LOG_LEVEL \
     \
     --db-dialect=$DB_DIALECT \
     --db-host=$DB_HOST \
     --db-port=$DB_PORT \
     --db-username=$DB_USERNAME \
     --db-password=$DB_PASSWORD \
     --db-name=$DB_NAME \
     \
     --cors-allowed-origins=$CORS_ALLOWED_ORIGINS \
     --accesstoken-expiration-minutes=$ACCESS_TOKEN_EXPIRATION_MINUTES \
     --accesstoken-default-scope=$ACCESS_TOKEN_DEFAULT_SCOPE \
     --refreshtoken-expiration-minutes=$REFRESH_TOKEN_EXPIRATION_MINUTES \
     --validationtoken-expiration-minutes=$VALIDATION_TOKEN_EXPIRATION_MINUTES \
     --passwordresettoken-expiration-minutes=$PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES \
     --password-retries-max=$INCORRECT_PASSWORD_MAX_RETRIES \
     --password-retries-time=$INCORRENT_PASSWORD_TIME_SECONDS \
     --password-expiration-days=$PASSWORD_EXPIRATION_DAYS \
     --account-activation-method=$ACCOUNT_ACTIVATION_METHOD \
     --password-validation-regex=$PASSWORD_VALIDATION_REGEX \
     --jwt-signing-key-file=$JWT_SIGNING_KEY_FILE \
     --jwt-signing-method=$JWT_SIGNING_METHOD \
     --master-public-key-file=$MASTER_PUBLIC_KEY_FILE \
     \
     --mail-smtp-host=$MAIL_SMTP_HOST \
     --mail-smtp-port=$MAIL_SMTP_PORT \
     --mail-smtp-username=$MAIL_SMTP_USER \
     --mail-smtp-password=$MAIL_SMTP_PASS \
     --mail-from-address=$MAIL_FROM_ADDRESS \
     --mail-from-name=$MAIL_FROM_NAME \
     --mail-activation-subject="$MAIL_ACTIVATION_SUBJECT" \
     --mail-activation-html="$MAIL_ACTIVATION_HTML" \
     --mail-password-reset-subject="$MAIL_PASSWORD_RESET_SUBJECT" \
     --mail-password-reset-html="$MAIL_PASSWORD_RESET_HTML" \
     --mail-tokens-tests=$MAIL_TOKENS_FOR_TESTS \
     \
     --google-client-id=$GOOGLE_CLIENT_ID \
     --google-client-secret=$GOOGLE_CLIENT_SECRET \
     --facebook-client-id=$FACEBOOK_CLIENT_ID \
     --facebook-client-secret=$FACEBOOK_CLIENT_SECRET

