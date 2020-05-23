# userme
Userme gives you a bunch of API services for basic account creation, token validation, user authentication, password reset, mail validation etc

## *s

* LOG_LEVEL - Application log details level. defaults to 'info'
* CORS_ALLOWED_ORIGINS - Browser origin domains allowed to invoke this service. defaults to '*'
* ACCESS_TOKEN_EXPIRATION_MINUTES - Access Token expiration time after creation. This is the token used in requests to the server. If you want to extend this time, use a Refresh Token to get a new Access Token at endpoint /token/refresh. defaults to '480'
* REFRESH_TOKEN_EXPIRATION_MINUTES - Refresh token expiration time. This token can be used to get new Access Tokens, but we will verify if this account is enabled/unlock before doing so. Probably much higher than access tokens expiration because this token can be used to extend long time authentications, for example, for supporting mobile applications to keep authenticated after being closed etc. defaults to '40320'
* ACCESS_TOKEN_DEFAULT_SCOPE - Scope (claim) included in all tokens indicating a good authentication. defaults to 'basic'
* MAX_INCORRECT_PASSWORD_RETRIES - Max number of wrong password retries during user authentication before the account get locked (then it will need a "password reset"). defaults to '5'
* ACCOUNT_ACTIVATION_METHOD - Whetever activate account immediatelly after user creation ('direct') or send an "activation link" to the user e-mail. defaults to 'direct'
* PASSWORD_VALIDATION_REGEX - Regex used against new user passwords. defaults to '^.{6,30}$'
* JWT_PK_FILE - File path containing the PrivateKey used on JWT token signatures. In Docker, user "secrets" to store this kind of information. defaults to '/secrets/jwtpk'

* DB_DIALECT - One of 'mysql', 'postgres', 'sqlite' or 'mssql'. defaults to 'mysql'
* DB_HOST - database hostname. required
* DB_PORT - database port. required
* DB_USERNAME - database connection username. defaults to 'userme'
* DB_PASSWORD - database connection password. required
* DB_NAME - database name. defaults to 'userme'

* MAIL_SMTP_HOST - smtp mail sender host. defaults to 'smtp.mailgun.com'
* MAIL_SMTP_PORT - secure (tls) smtp port. defaults to '465'
* MAIL_SMTP_USER - smtp authentication username. required
* MAIL_SMTP_PASS - smtp authentication password. required
* MAIL_FROM_ADDRESS - Send emails using this "mail from" info. required
* MAIL_ACTIVATION_SUBJECT - Mail Subject used on account activation messages. required. Example: ```Activate your account at Berimbau.com!```
* MAIL_ACTIVATION_HTML - Mail HTML Body used on account activation messages. Use DISPLAY_NAME and ACTIVATION_TOKEN for string templating. required. Example: ```<b>Hi DISPLAY_NAME</b>, <p> <a href=https://test.com/activate?t=ACTIVATION_TOKEN>Click here to complete your registration</a><br>Be welcome!</p> <p>-Test Team.</p>```
* MAIL_PASSWORD_RESET_SUBJECT - Mail Subject used on password reset messages. required. Example: ```Password reset requested at Test.com```
* MAIL_PASSWORD_RESET_HTML - Mail HTML Body used on password reset messages. Use DISPLAY_NAME and ACTIVATION_TOKEN for string templating. required. Example: ```<b>Hi DISPLAY_NAME</b>, <p> <a href=https://test.com/reset-password?t=ACTIVATION_TOKEN>Click here to reset your password</a></p><p>-Test Team.</p>```
