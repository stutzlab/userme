FROM golang:1.14.3-alpine3.11 AS BUILD

RUN apk add build-base

WORKDIR /userme
ADD /go.mod /userme
ADD /go.sum /userme
RUN go mod download

#now build source code
ADD / /userme
RUN go build -o /go/bin/userme


FROM golang:1.14.3-alpine3.11

ENV LOG_LEVEL                           'info'
ENV CORS_ALLOWED_ORIGINS                '*'
ENV ACCESS_TOKEN_EXPIRATION_MINUTES     '480'
ENV REFRESH_TOKEN_EXPIRATION_MINUTES    '40320'
ENV VALIDATION_TOKEN_EXPIRATION_MINUTES '30'
ENV ACCESS_TOKEN_DEFAULT_SCOPE          'basic'
ENV INCORRENT_PASSWORD_TIME_SECONDS     '1'
ENV INCORRECT_PASSWORD_MAX_RETRIES      '5'
ENV ACCOUNT_ACTIVATION_METHOD           'direct'
ENV PASSWORD_VALIDATION_REGEX            ^.{6,30}$
ENV PASSWORD_EXPIRATION_DAYS            '-1'
ENV JWT_SIGNING_METHOD                  'ES256'
ENV JWT_SIGNING_KEY_FILE                '/run/secrets/jwt-signing-key'
ENV MASTER_PUBLIC_KEY_FILE              '/run/secrests/master-public-key'

ENV DB_DIALECT  'mysql'
ENV DB_HOST     ''
ENV DB_PORT     '0'
ENV DB_USERNAME 'userme'
ENV DB_PASSWORD ''
ENV DB_NAME     'userme'

ENV MAIL_SMTP_HOST          'smtp.mailgun.com'
ENV MAIL_SMTP_PORT          '465'
ENV MAIL_SMTP_USER          ''
ENV MAIL_SMTP_PASS          ''
ENV MAIL_FROM_ADDRESS       ''
ENV MAIL_FROM_NAME          ''
ENV MAIL_ACTIVATION_SUBJECT ''
ENV MAIL_ACTIVATION_HTML    ''
ENV MAIL_PASSWORD_RESET_SUBJECT 'Password reset requested at Test.com'
ENV MAIL_PASSWORD_RESET_HTML ''

COPY --from=BUILD /go/bin/userme /bin/

ADD startup.sh /

EXPOSE 6000

VOLUME [ "/data" ]

CMD [ "/startup.sh" ]

