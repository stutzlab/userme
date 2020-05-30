# userme
Userme gives you a bunch of API services for basic account creation, token validation, user authentication, password reset, mail validation etc

<img src="signup.png" width="700" />
<img src="signin.png" width="700" />

## Basics

* A user is created with just a name, email and password
* A JWT access token is returned against a email/password validation so that your application can check that he/she was authenticated
* You have two tokens:
  * Access token - the token used for your http requests to check if the user is OK. Will be invalidated in a matter of minutes or hours
  * Refresh token - a token that can be used by the client application to recreate an Access Token even after it has expired. Useful to avoid the user to have to retype his/hers password, for example, in a mobile application so that the user won't have to login each time the application is opened.
* There are APIs for password reseting (by sending email) and password change
* For a successful token creation (authentication):
  * User account must be enabled
  * The provided email/password must match
  * The password must be still valid (not expired)
  * User account must not be locked (max wrong password retries reached)
    * For each wrong password trial, an internal counter will double the time to permit a new password retry only after some time, until max retries is reached. You can configure the "doubled" delay in INCORRENT_PASSWORD_TIME_SECONDS and max retries in INCORRECT_PASSWORD_MAX_RETRIES
* For a successful access token creation from refresh tokens
  * The account must be enabled
  * The password must be still valid (not expired)
* In future we may add TOTP capabilities too. Please contribute on that!

## Usage

* Create a docker-compose.yml

```
version: '3.6'

services:

  userme:
    image: stutzlab/userme
    ports:
      - "6000:6000"
    restart: always
    environment:
      - LOG_LEVEL=debug
      - DB_DIALECT=sqlite3
      - MAIL_SMTP_HOST=mailslurper
      - MAIL_SMTP_PORT=2500
      - MAIL_SMTP_USER=test
      - MAIL_SMTP_PASS=test
      - MAIL_FROM_NAME=Berimbal
      - MAIL_FROM_ADDRESS=test@test.com
      - MAIL_ACTIVATION_SUBJECT=Activate your account at Berimbau.com!
      - MAIL_ACTIVATION_HTML=<b>Hi DISPLAY_NAME</b>, <p> <a href=https://test.com/activate?t=ACTIVATION_TOKEN>Click here to complete your registration</a><br>Be welcome!</p> <p>-Test Team.</p>
      - MAIL_PASSWORD_RESET_SUBJECT=Password reset requested at Berimbau.com
      - MAIL_PASSWORD_RESET_HTML=<b>Hi DISPLAY_NAME</b>, <p> <a href=https://test.com/reset-password?t=PASSWORD_RESET_TOKEN>Click here to reset your password</a></p><p>-Test Team.</p>
      - MAIL_TOKENS_FOR_TESTS=true
      - ACCOUNT_ACTIVATION_METHOD=mail
      - JWT_SIGNING_METHOD=ES256
    secrets:
      - jwt-signing-key

  mailslurper:
    image: marcopas/docker-mailslurper
    ports:
      - "8080:8080"
      - "8085:8085"
      - "2500:2500"
    restart: always

secrets:
  jwt-signing-key:
    file: ./tests/test-key.pem
```

* Run ```docker-compose up```

* Create a new user
```
curl --location --request PUT 'http://localhost:6000/user/test1@test.com' \
--header 'Content-Type: application/json' \
--data-raw '{
	"password": "testtest",
	"name": "test1@test.com"
}'
```

* Validate user account using mail tester
  * Open mailslurper at http://
````
curl --location --request POST 'http://localhost:6000/user/test82089130@test.com/activate' \
--header 'Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTA0NjYwNjEsImlhdCI6MTU5MDQ2NDI2MSwiaXNzIjoiQmVyaW1iYWwiLCJqdGkiOiIxYTExN2ViYS01M2Y4LTRjYmQtOGUyNS1mNDQ5MDdlY2FkZGYiLCJuYmYiOjE1OTA0NjQyNjEsInN1YiI6InRlc3QzMTE2OTQ3MUB0ZXN0LmNvbSIsInR5cCI6ImFjdGl2YXRpb24ifQ.poBYDyg-3zIiULtwUthsbUzpYzsJr-I3jtXZwMrJr9QKhc9ZaNXkKw9KyqWeczYxAdGZYQ37QX10xHbA1JYr5Q'
```

* Create a token with email/passoword

* Check user token

* For more details, check a full working with Postman example at "/tests/collection.json"

## Rest API

* PUT /user/:email
  * request body json: name, password
  * response status
    * 201 - user created and activated
    * 250 - user created and activation link sent to email
    * 450 - invalid name
    * 455 - invalid email
    * 460 - invalid password
    * 465 - email already registered
    * 500 - server error

* POST /user/:email/activate
  * request header: Bearer <activation token>
  * response status
    * 202 - account activated successfuly
    * 450 - invalid activation token
    * 455 - account already activated
    * 460 - account disabled
    * 500 - server error
  * response body json: name, jwtAccessToken, jwtRefreshToken, accessTokenExpirationDate, refreshTokenExpirationDate

* POST /user/:email/password-reset-request
  * response status
    * 202 - password reset request accepted (maybe email doesn't exist and email won't be sent, but we don't want to give this clue to abusers ;), so this kind of details can be accessed only on server logs)
    * 500 - server error

* POST /user/:email/password-reset-change
  * resquest header: Bearer <password reset token>
  * request body json: newPassword
  * response status
    * 200 - password changed successfuly
    * 450 - invalid token
    * 455 - invalid account
    * 460 - invalid new password
    * 500 - server error

* POST /user/:email/password-change
  * resquest header: Bearer <access token>
  * request body json: currentPassword, password
  * response status:
    * 200 - password changed successfuly
    * 450 - invalid token
    * 455 - invalid account
    * 460 - invalid new password
    * 470 - invalid current password
    * 500 - server error

* POST /token
  * request json body: email, password
  * response status
    * 200 - token created
    * 450 - invalid/inexistent email/password combination
    * 455 - password expired
    * 460 - account disabled
    * 465 - account locked
    * 500 - server error
  * response body json: name, jwtAccessToken, jwtRefreshToken, accessTokenExpirationDate, refreshTokenExpirationDate

* POST /token/refresh
  * request header Authorization: Bearer <refresh token>
  * response status
    * 200 - token created
    * 450 - invalid refresh token
    * 455 - password expired
    * 460 - account disabled
    * 500 - server error
  * response body json: name, jwtAccessToken, jwtRefreshToken, accessTokenExpirationDate, refreshTokenExpirationDate

* GET /token
  * Validates access tokens and verify if the user is enabled in database
  * request header: Bearer <access token>
  * response status
    * 200 - token/user valid
    * 450 - token invalid
    * 455 - account disabled
    * 500 - server error
  * response body json: name, email, expirationDate, claims[]

## ENVs

* LOG_LEVEL - Application log details level. defaults to 'info'
* CORS_ALLOWED_ORIGINS - Browser origin domains allowed to invoke this service. defaults to '*'
* ACCESS_TOKEN_EXPIRATION_MINUTES - Access Token expiration time after creation. This is the token used in requests to the server. If you want to extend this time, use a Refresh Token to get a new Access Token at endpoint /token/refresh. defaults to '480'
* REFRESH_TOKEN_EXPIRATION_MINUTES - Refresh token expiration time. This token can be used to get new Access Tokens, but we will verify if this account is enabled/unlock before doing so. Probably much higher than access tokens expiration because this token can be used to extend long time authentications, for example, for supporting mobile applications to keep authenticated after being closed etc. defaults to '40320'
* VALIDATION_TOKEN_EXPIRATION_MINUTES - Validation token expiration in minutes. This is the time the link sent to email will remain valid. defaults to '20'
* PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES - Password reset token expiration in minutes. This is the time the link sent to email will remain valid. defaults to '5'
* ACCESS_TOKEN_DEFAULT_SCOPE - Scope (claim) included in all tokens indicating a good authentication. defaults to 'basic'
* INCORRECT_PASSWORD_MAX_RETRIES - Max number of wrong password retries during user authentication before the account gets locked (then it will need a "password reset"). defaults to '5'
* INCORRENT_PASSWORD_TIME_SECONDS - Time to permit a new password retry base. This base is doubled each time the user misses the password. For example: With value of '1', the user can do the first retry after 1 second, the second retry after 2 seconds, third retry after 4 seconds, forth retry after 8 seconds until reaching MAX_RETRIES. defaults to '1'
* ACCOUNT_ACTIVATION_METHOD - Whetever activate account immediately after user creation ('direct') or send an "activation link" to the user e-mail ('email'). defaults to 'direct'
* PASSWORD_VALIDATION_REGEX - Regex used against new user passwords. defaults to '^.{6,30}$'
* PASSWORD_EXPIRATION_DAYS - Password expiration days after changing it (will force the user to change the password upon login). -1 means no expiration. defaults to -1

* JWT_ISSUER - JWT 'iss' field contents. Used as the 'name' of mail from too.
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
* MAIL_ACTIVATION_HTML - Mail HTML Body used on account activation messages. Use $DISPLAY_NAME and $ACTIVATION_TOKEN for string templating. required. Example: ```<b>Hi $DISPLAY_NAME</b>, <p> <a href=https://test.com/activate?t=$ACTIVATION_TOKEN>Click here to complete your registration</a><br>Be welcome!</p> <p>-Test Team.</p>```
* MAIL_PASSWORD_RESET_SUBJECT - Mail Subject used on password reset messages. required. Example: ```Password reset requested at Test.com```
* MAIL_PASSWORD_RESET_HTML - Mail HTML Body used on password reset messages. Use $DISPLAY_NAME and $PASSWORD_RESET_TOKEN for string templating. required. Example: ```<b>Hi $DISPLAY_NAME</b>, <p> <a href=https://test.com/reset-password?t=$PASSWORD_RESET_TOKEN>Click here to reset your password</a></p><p>-Test Team.</p>```

* MAIL_TOKENS_FOR_TESTS - If true, adds password reset and account activation tokens in http response headers with name "TestToken" so that automated scripts can proceed with tests that needs those tokens. NEVER USE THIS IN PRODUCTION as it will make the e-mail (second factor) useless for security matters. defaults to false

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

### Postman files

* https://www.getpostman.com/collections/ec55eac4574064ce15e2

* Import tests/collection.json to Postman so that you can test and update the automated tests
