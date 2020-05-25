package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/smtp"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func sendMail(subject string, htmlBody string, mailTo string) error {
	logrus.Infof("Sending mail %s - %s", mailTo, subject)
	auth := smtp.PlainAuth("", opt.mailSMTPUser, opt.mailSMTPPass, opt.mailSMTPHost)

	from := fmt.Sprintf("From: %s\n", opt.mailFromAddress)
	to := fmt.Sprintf("To: %s\n", mailTo)
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n"
	msg := []byte(fmt.Sprintf("%s%s%s\n%s", from, to, mime, htmlBody))

	return smtp.SendMail(fmt.Sprintf("%s:%d", opt.mailSMTPHost, opt.mailSMTPPort), auth, opt.mailFromAddress, []string{mailTo}, msg)
}

func createJWTToken(email string, expirationMinutes int, typ string, scopes string) (string, error) {
	sm := jwt.GetSigningMethod(opt.jwtSigningMethod)
	jti := uuid.New()
	token := jwt.NewWithClaims(sm, jwt.MapClaims{
		"iss":   "userme",
		"sub":   email,
		"exp":   json.Number(strconv.FormatInt(time.Now().Unix()+int64(60*expirationMinutes), 10)),
		"iat":   json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
		"nbf":   json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
		"jti":   jti.String(),
		"scope": scopes,
		"typ":   typ,
	})
	return token.SignedString(opt.jwtSigningKey)
}

func parseKeyFromPEM(pemFile string, private bool) (interface{}, error) {
	pemFileContents, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read pem file contents. err=%s", err)
	}

	nextBytes := pemFileContents
	for len(nextBytes) > 0 {
		block, rbytes := pem.Decode(nextBytes)
		if block == nil {
			return nil, errors.New("Failed to parse PEM block")
		}

		var err error
		var key interface{}

		if private {
			if block.Type == "PRIVATE KEY" {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)

			} else if block.Type == "EC PRIVATE KEY" {
				key, err = x509.ParseECPrivateKey(block.Bytes)

			} else if block.Type == "RSA PRIVATE KEY" {
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}

		} else {
			if block.Type == "PUBLIC KEY" {
				key, err = x509.ParsePKIXPublicKey(block.Bytes)
			}
			if block.Type == "RSA PUBLIC KEY" {
				key, err = x509.ParsePKCS1PublicKey(block.Bytes)
			}
		}

		if err != nil {
			return nil, err
		}
		if key != nil {
			return key, nil
		}
		nextBytes = rbytes
	}
	if private {
		return nil, fmt.Errorf("Couldn't find key 'PRIVATE KEY' block in PEM file")
	}
	return nil, fmt.Errorf("Couldn't find key 'PUBLIC KEY' block in PEM file")
}
