#!/bin/sh

echo "Starting Userme..."
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
     --token-expiration-minutes=$TOKEN_EXPIRATION_MINUTES \
     --token-default-scope=$TOKEN_DEFAULT_SCOPE \
     --max-incorrect-retries=$MAX_INCORRECT_PASSWORD_RETRIES \
     --account-activation-method=$ACCOUNT_ACTIVATION_METHOD \
     --password-validation-regex=$PASSWORD_VALIDATION_REGEX \
     --jwt-pk-file=$JWT_PK_FILE \
     \
     --mail-smtp-host=$MAIL_SMTP_HOST \
     --mail-smtp-port=$MAIL_SMTP_PORT \
     --mail-smtp-user=$MAIL_SMTP_USER \
     --mail-smtp-pass=$MAIL_SMTP_PASS \
     --mail-from-address=$MAIL_FROM_ADDRESS \
     --mail-activation-subject=$MAIL_ACTIVATION_SUBJECT \
     --mail-activation-html=$MAIL_ACTIVATION_HTML \
     --mail-password-reset-subject=$MAIL_PASSWORD_RESET_SUBJECT \
     --mail-password-reset-html=$MAIL_PASSWORD_RESET_HTML

