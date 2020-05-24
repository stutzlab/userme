# userme
Userme gives you a bunch of API services for basic account creation, token validation, user authentication, password reset, mail validation etc

<img src="signup.png" width="700" />
<img src="signin.png" width="700" />

## Basics

* A user is created with a email/password
* And JWT access token is returned against a email/password validation so that your application can check that he/she was authenticated
* You have two tokens:
  * Access token - the token used for your http requests to check if the user is OK. Will be invalidated in a matter of minutes or hours
  * Refresh token - a token that can be used by the client application to recreate an Access Token even after it has expired. Useful to avoid the user to have to retype his/hers password, for example, in a mobile application so that the user won't have to login each time the application is opened.
* There are APIs for password reseting (by sending email) and password change
* In future we may add TOTP capabilities too. Please contribute on that!

## Rest API

* PUT /user/:email
  * request body json: name, password
  * response status
    * 201 - user created and activated
    * 250 - user created and activation link sent to email
    * 450 - invalid name
    * 455 - invalid email (used for bad email names and already registered emails too)
    * 460 - invalid password
    * 500 - server error

* POST /user/:email/activate
  * request header: Bearer <activation token>
  * response status
    * 202 - account activated successfuly
    * 450 - invalid activation token
    * 455 - account already activated
    * 460 - account locked
    * 500 - server error
  * response body json: name, jwtAccessToken, jwtRefreshToken, accessTokenExpirationDate, refreshTokenExpirationDate

* POST /user/:email/reset-password
  * response status
    * 202 - password reset request accepted (maybe email doesn't exist and email won't be sent, but we don't want to give this clue to abusers ;), so this kind of details can be accessed only on server logs)
    * 500 - server error

* POST /user/:mail/change-password
  * resquest header: Bearer <access token>
  * request body json: currentPassword, newPassword
  * response status:
    * 200 - password changed successfuly
    * 450 - wrong current password (this will be used to indicate that the email doesn't exist too)
    * 460 - invalid new password
    * 500 - server error

* POST /token
  * request json body: email, password
  * response status
    * 200 - token created
    * 450 - invalid/inexistent email/password combination
    * 500 - server error
  * response body json: name, jwtAccessToken, jwtRefreshToken, accessTokenExpirationDate, refreshTokenExpirationDate

* GET /token
  * request header: Bearer <access token>
  * response status
    * 200 - token valid
    * 450 - token invalid
    * 500 - server error
  * response body json: name, email, expirationDate, claims[]


## ENVs

* LOG_LEVEL - Application log details level. defaults to 'info'
* CORS_ALLOWED_ORIGINS - Browser origin domains allowed to invoke this service. defaults to '*'
* ACCESS_TOKEN_EXPIRATION_MINUTES - Access Token expiration time after creation. This is the token used in requests to the server. If you want to extend this time, use a Refresh Token to get a new Access Token at endpoint /token/refresh. defaults to '480'
* REFRESH_TOKEN_EXPIRATION_MINUTES - Refresh token expiration time. This token can be used to get new Access Tokens, but we will verify if this account is enabled/unlock before doing so. Probably much higher than access tokens expiration because this token can be used to extend long time authentications, for example, for supporting mobile applications to keep authenticated after being closed etc. defaults to '40320'
* ACCESS_TOKEN_DEFAULT_SCOPE - Scope (claim) included in all tokens indicating a good authentication. defaults to 'basic'
* INCORRECT_PASSWORD_MAX_RETRIES - Max number of wrong password retries during user authentication before the account get locked (then it will need a "password reset"). defaults to '5'
* INCORRENT_PASSWORD_TIME_SECONDS - Time to permit a new password retry base. This base is doubled each time the user misses the password. For example: With value of '1', the user can do the first retry after 1 second, the second retry after 2 seconds, third retry after 4 seconds, forth retry after 8 seconds until reaching MAX_RETRIES. defaults to '1'
* ACCOUNT_ACTIVATION_METHOD - Whetever activate account immediately after user creation ('direct') or send an "activation link" to the user e-mail ('email'). defaults to 'direct'
* PASSWORD_VALIDATION_REGEX - Regex used against new user passwords. defaults to '^.{6,30}$'

* JWT_SIGNING_METHOD - JWT algorithm used to sign tokens. defaults to 'ES256'
* JWT_SIGNING_KEY_FILE - PEM file path containing the key used on JWT token signatures. In Docker, user "secrets" to store this kind of information. defaults to '/run/secrets/jwt-signing-key'
* MATER_PUBLIC_KEY_FILE - File path containing the Public Key used to sign special "master" tokens that can be used to perform some administrative operations on Userme. In Docker, user "secrets" to store this kind of information. defaults to '/run/secrets/jwt-private-key'

* DB_DIALECT - One of 'mysql', 'postgres', 'sqlite3' or 'mssql'. defaults to 'mysql'
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

## Volume

* /data - if using SQLite database, the database file will be stored at /data/userme.db by default

## Development Tips

### JWT Keys

* Test keys are not stored in repository
* Generate your own PEM keys using https://jwt.io/ (see PEM keys at right boxes in blue) and place in file "test-jwt-private-key.pem"

### TBD

* Convert Post invocations to Swagger yaml using https://www.apimatic.io/, then convert Swagger yaml to Markdown using 
```markdown-swagger swagger.yaml README.md``` 
* Install this using "npm install markdown-swagger -g"
* After updating the API you can re-run this over this README because it will replace only contents inside its tags.

