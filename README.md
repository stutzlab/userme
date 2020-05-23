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

* PUT /user/email
  * request body json: name, password
  * response status
    * 201 - user created and activated
    * 250 - user created and activation link sent to email
    * 450 - invalid name
    * 455 - invalid email
    * 460 - invalid password
    * 465 - user email already registered
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
    * 202 - password reset request accepted (maybe mail doesn't exist and email won't be sent, but we don't want to give this clue to abusers ;), so this kind of details can be accessed only on server logs)
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

* POST /user/:mail/change-password
  * resquest header: Bearer <access token>
  * request body json: currentPassword, newPassword
  * response status:
    * 200 - password changed successfuly
    * 450 - wrong current password (this will be used to indicate that the email doesn't exist too)
    * 460 - invalid new password
    * 500 - server error


## ENVs

* LOG_LEVEL - Application log details level. defaults to 'info'
* CORS_ALLOWED_ORIGINS - Browser origin domains allowed to invoke this service. defaults to '*'
* ACCESS_TOKEN_EXPIRATION_MINUTES - Access Token expiration time after creation. This is the token used in requests to the server. If you want to extend this time, use a Refresh Token to get a new Access Token at endpoint /token/refresh. defaults to '480'
* REFRESH_TOKEN_EXPIRATION_MINUTES - Refresh token expiration time. This token can be used to get new Access Tokens, but we will verify if this account is enabled/unlock before doing so. Probably much higher than access tokens expiration because this token can be used to extend long time authentications, for example, for supporting mobile applications to keep authenticated after being closed etc. defaults to '40320'
* ACCESS_TOKEN_DEFAULT_SCOPE - Scope (claim) included in all tokens indicating a good authentication. defaults to 'basic'
* MAX_INCORRECT_PASSWORD_RETRIES - Max number of wrong password retries during user authentication before the account get locked (then it will need a "password reset"). defaults to '5'
* ACCOUNT_ACTIVATION_METHOD - Whetever activate account immediatelly after user creation ('direct') or send an "activation link" to the user e-mail. defaults to 'direct'
* PASSWORD_VALIDATION_REGEX - Regex used against new user passwords. defaults to '^.{6,30}$'
* JWT_PRIVATE_KEY_FILE - File path containing the PrivateKey used on JWT token signatures. In Docker, user "secrets" to store this kind of information. defaults to '/secrets/jwt-private-key'
* MATER_PUBLIC_KEY_FILE - File path containing the Public Key used to sign special "master" tokens that can be used to perform some administrative operations on Userme. In Docker, user "secrets" to store this kind of information. defaults to '/secrets/jwt-private-key'

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


## Development Tips

### TBD

* Convert Post invocations to Swagger yaml using https://www.apimatic.io/, then convert Swagger yaml to Markdown using 
```markdown-swagger swagger.yaml README.md``` 
* Install this using "npm install markdown-swagger -g"
* After updating the API you can re-run this over this README because it will replace only contents inside its tags.
