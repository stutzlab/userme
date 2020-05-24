package main

import (
	"crypto/rsa"
	"flag"
	"io/ioutil"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"github.com/sirupsen/logrus"
)

type options struct {
	logLevel     string
	dbDialect    string
	dbHost       string
	dbPort       int
	dbUsername   string
	dbPassword   string
	dbName       string
	dbSqliteFile string

	corsAllowedOrigins                   string
	accessTokenDefaultExpirationMinutes  int
	refreshTokenDefaultExpirationMinutes int
	accessTokenDefaultScope              string
	jwtSigningMethod                     string
	jwtSigningKeyFile                    string
	jwtSigningKey                        *rsa.PrivateKey
	masterPublicKeyFile                  string
	passwordRetriesMax                   int
	passwordRetriesTimeSeconds           int
	accountActivationMethod              string
	passwordValidationRegex              string

	mailSMTPHost              string
	mailSMTPPort              int
	mailSMTPUser              string
	mailSMTPPass              string
	mailFromAddress           string
	mailActivationSubject     string
	mailActivationHTMLBody    string
	mailResetPasswordSubject  string
	mailResetPasswordHTMLBody string
}

var (
	opt options
	db  *gorm.DB
)

func main() {
	logLevel := flag.String("loglevel", "debug", "debug, info, warning, error")

	dbDialect0 := flag.String("db-dialect", "mysql", "Database dialect to use. One of mysql, postgres, sqlite or mssql. Defaults to 'mysql'")
	dbHost0 := flag.String("db-host", "", "Database host address")
	dbPort0 := flag.Int("db-port", 0, "Database port")
	dbUsername0 := flag.String("db-username", "userme", "Database username. defaults to 'userme'")
	dbPassword0 := flag.String("db-password", "", "Database password")
	dbName0 := flag.String("db-name", "userme", "Database name. defaults to 'userme'")
	dbSqliteFile0 := flag.String("db-sqlite-file", "/data/userme.db", "SQLite file path location")

	corsAllowedOrigins0 := flag.String("cors-allowed-origins", "*", "Cors allowed origins for this server. defaults to '*' (not recommended for production)")
	accessTokenDefaultExpirationMinutes0 := flag.Int("acesstoken-expiration-minutes", 480, "Default access token expiration age")
	refreshTokenDefaultExpirationMinutes0 := flag.Int("refreshtoken-expiration-minutes", 40320, "Default refresh token expiration age")
	accessTokenDefaultScope0 := flag.String("accesstoken-default-scope", "basic", "Default claim (scope) added to all access tokens")
	passwordRetriesMax0 := flag.Int("password-retries-max", 5, "Max number of incorrect password retries")
	passwordRetriesTimeSeconds0 := flag.Int("password-retries-time", 5, "Max number of incorrect password retries")
	accountActivationMethod0 := flag.String("account-activation-method", "direct", "Activation method for new accounts. One of 'direct' (no additional steps needed) or 'mail' (send e-mail with activation link to user). Defaults to 'direct'")
	passwordValidationRegex0 := flag.String("password-validation-regex", "^.{6,30}$", "Password validation regex. Defaults to '^.{6,30}$'")
	jwtSigningMethod0 := flag.String("jwt-signing-method", "", "JWT signing method. defaults to 'EC256'")
	jwtSigningKeyFile0 := flag.String("jwt-signing-key-file", "", "Key file used to sign tokens. Tokens may be later validated by thirdy parties by checking the signature with related public key when usign assymetric keys")
	masterPublicKeyFile0 := flag.String("master-public-key-file", "", "Public key file used to sign special master tokens that can be used to perform special operations on userme.")

	mailSMTPHost0 := flag.String("mail-smtp-host", "", "Mail smtp host")
	mailSMTPPort0 := flag.Int("mail-smtp-port", 0, "Mail smtp port")
	mailSMTPUser0 := flag.String("mail-smtp-username", "", "Mail smtp username")
	mailSMTPPass0 := flag.String("mail-smtp-password", "", "Mail smtp password")
	mailFromAddress0 := flag.String("mail-from-address", "", "Mail from address")
	mailActivationSubject0 := flag.String("mail-activation-subject", "", "Mail activation subject")
	mailActivationHTML0 := flag.String("mail-activation-html", "", "Mail activation html body. Use placeholders DISPLAY_NAME and ACTIVATION_TOKEN as templating")
	mailResetPasswordSubject0 := flag.String("mail-password-reset-subject", "", "Mail password reset subject")
	mailResetPasswordHTML0 := flag.String("mail-password-reset-html", "", "Mail password reset html body. Use placeholders DISPLAY_NAME and ACTIVATION_TOKEN as templating")

	flag.Parse()

	switch *logLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
		break
	case "warning":
		logrus.SetLevel(logrus.WarnLevel)
		break
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
		break
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}

	opt = options{
		logLevel:     *logLevel,
		dbDialect:    *dbDialect0,
		dbHost:       *dbHost0,
		dbPort:       *dbPort0,
		dbUsername:   *dbUsername0,
		dbPassword:   *dbPassword0,
		dbName:       *dbName0,
		dbSqliteFile: *dbSqliteFile0,

		corsAllowedOrigins:                   *corsAllowedOrigins0,
		accessTokenDefaultExpirationMinutes:  *accessTokenDefaultExpirationMinutes0,
		refreshTokenDefaultExpirationMinutes: *refreshTokenDefaultExpirationMinutes0,
		accessTokenDefaultScope:              *accessTokenDefaultScope0,
		jwtSigningMethod:                     *jwtSigningMethod0,
		jwtSigningKeyFile:                    *jwtSigningKeyFile0,
		masterPublicKeyFile:                  *masterPublicKeyFile0,
		passwordRetriesMax:                   *passwordRetriesMax0,
		passwordRetriesTimeSeconds:           *passwordRetriesTimeSeconds0,
		accountActivationMethod:              *accountActivationMethod0,
		passwordValidationRegex:              *passwordValidationRegex0,

		mailSMTPHost:              *mailSMTPHost0,
		mailSMTPPort:              *mailSMTPPort0,
		mailSMTPUser:              *mailSMTPUser0,
		mailSMTPPass:              *mailSMTPPass0,
		mailFromAddress:           *mailFromAddress0,
		mailResetPasswordSubject:  *mailResetPasswordSubject0,
		mailResetPasswordHTMLBody: *mailResetPasswordHTML0,
		mailActivationSubject:     *mailActivationSubject0,
		mailActivationHTMLBody:    *mailActivationHTML0,
	}

	if opt.dbDialect != "sqlite" {
		if opt.dbHost == "" || opt.dbPort == 0 || opt.dbName == "" || opt.dbUsername == "" || opt.dbPassword == "" {
			logrus.Errorf("--db-host, --db-port, --db-name, --db-username and --db-password are all required non empty")
			os.Exit(1)
		}
	}

	if opt.mailSMTPHost == "" || opt.mailSMTPPort == 0 || opt.mailSMTPUser == "" || opt.mailSMTPPass == "" {
		logrus.Errorf("--mail-smtp-host, --mail-smtp-port, --mail-smtp-username and --mail-smtp-password are required")
		os.Exit(1)
	}

	if opt.mailFromAddress == "" || opt.mailResetPasswordSubject == "" || opt.mailResetPasswordHTMLBody == "" {
		logrus.Errorf("--mail-from-address, --mail-password-reset-subject and --mail-password-reset-html are required")
		os.Exit(1)
	}

	if opt.accountActivationMethod == "mail" {
		if opt.mailActivationSubject == "" || opt.mailActivationHTMLBody == "" {
			logrus.Errorf("--mail-activation-subject and --mail-activation-html must be non empty when activation method is 'mail'")
			os.Exit(1)
		}

	}

	sm := jwt.GetSigningMethod(opt.jwtSigningMethod)
	if sm == nil {
		logrus.Errorf("Unsupported JWT signing method %s", opt.jwtSigningMethod)
		os.Exit(1)
	}

	logrus.Infof("Loading JWT signing key")
	//load key contents
	jwtSigningPEM, err := ioutil.ReadFile(opt.jwtSigningKeyFile)
	if err != nil {
		logrus.Errorf("Couldn't read key file contents. err=%s", err)
		os.Exit(1)
	}
	logrus.Debugf("JWT key read from file '%s'", opt.jwtSigningKeyFile)

	pk, err := jwt.ParseRSAPrivateKeyFromPEM(jwtSigningPEM)
	if err != nil {
		logrus.Errorf("Failed to parse PEM private key. err=%s", err)
		os.Exit(1)
	}
	opt.jwtSigningKey = pk
	logrus.Debugf("JWT key loaded")

	db0, err0 := initDB()
	if err0 != nil {
		logrus.Warnf("Couldn't init database. err=%s", err0)
		os.Exit(1)
	}
	db = db0
	defer db.Close()

	err = NewHTTPServer().Start()
	if err != nil {
		logrus.Warnf("Error starting server. err=%s", err)
		os.Exit(1)
	}
}
