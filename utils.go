package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/smtp"
	"time"

	"github.com/dgrijalva/jwt-go"
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
		"exp":   time.Now().Unix() + int64(60*expirationMinutes),
		"iat":   time.Now().Unix(),
		"nbf":   time.Now().Unix(),
		"jti":   jti,
		"scope": scopes,
		"typ":   typ,
	})
	return token.SignedString(opt.jwtSigningKey)
}

func parsePKIXPublicKeyFromPEM(pubPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
