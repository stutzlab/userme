package main

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func processFacebookLogin(m map[string]string, shortLivedFacebookToken string, c *gin.Context, pmethod string, ppath string) {
	logrus.Debugf("Authentication using Facebook login")

	if opt.facebookClientID == "" || opt.facebookClientSecret == "" {
		c.JSON(400, gin.H{"message": "Facebook login disabled"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	//https://developers.facebook.com/docs/facebook-login/access-tokens/refreshing/

	logrus.Debugf("Checking short lived user token validity at facebook")
	temail, tname, success := processFacebookToken(c, shortLivedFacebookToken, pmethod, ppath)
	if !success {
		return
	}

	logrus.Debugf("Exchanging user short lived FB token by a user long lived one")
	resp, err := requestURLWithJsonResponse("GET", fmt.Sprintf("https://graph.facebook.com/v7.0/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s", opt.facebookClientID, opt.facebookClientSecret, shortLivedFacebookToken), "", "", nil, 200)
	if err != nil {
		logrus.Warnf("Error calling Facebook to get a long lived token. err=%s", err)
		c.JSON(400, gin.H{"message": "Couldn't exchange Facebook tokens"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	longLivedUserFacebookToken0, exists := resp["access_token"]
	if !exists {
		logrus.Debugf("FB body contents for long lived token don't contain 'access_token'. body=%v", resp)
		c.JSON(500, gin.H{"message": "Couldn't parse FB body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}
	longLivedUserFacebookToken := longLivedUserFacebookToken0.(string)

	logrus.Debugf("Checking facebook token validity")
	temail, tname, success = processFacebookToken(c, longLivedUserFacebookToken, pmethod, ppath)
	if !success {
		return
	}
	logrus.Debugf("Facebook token valid for %s. Checking if account already exists")

	authType := "facebook"
	success = processCreateActivatedUserIfNeeded(c, temail, tname, pmethod, ppath, authType)
	if !success {
		return
	}

	u, success := processValidateUserActivated(temail, c, pmethod, ppath)
	if !success {
		return
	}

	validateUserAndOutputTokensToResponse(u, c, pmethod, ppath, authType, longLivedUserFacebookToken)
	logrus.Debugf("Facebook login for %s", u.Email)
}

func processFacebookRefreshToken(c *gin.Context, facebookToken string, pmethod string, ppath string) (newFacebookToken string, success bool) {
	logrus.Debugf("Renewing Facebook token for refresh")
	resp, err := requestURLWithJsonResponse("GET", fmt.Sprintf("https://graph.facebook.com/v7.0/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s", opt.facebookClientID, opt.facebookClientSecret, facebookToken), "", "", nil, 200)
	if err != nil {
		logrus.Warnf("Error calling Facebook to renew token during refresh. err=%s", err)
		c.JSON(400, gin.H{"message": "Couldn't exchange Facebook tokens"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return "", false
	}

	facebookToken0, exists := resp["access_token"]
	if !exists {
		logrus.Debugf("FB body contents for access_token don't contain 'access_token'. body=%v", resp)
		c.JSON(500, gin.H{"message": "Couldn't parse FB body contents"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return "", false
	}
	facebookToken2 := facebookToken0.(string)
	return facebookToken2, true
}

func processGoogleLogin(m map[string]string, googleAuthCode string, c *gin.Context, pmethod string, ppath string) {
	logrus.Debugf("Authentication using Google login")

	if opt.googleClientID == "" || opt.googleClientSecret == "" {
		c.JSON(400, gin.H{"message": "Google login disabled"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}

	logrus.Debugf("Exchanging Google authorization code by a refresh token")

	body := fmt.Sprintf(`client_id=%s&client_secret=%s&redirect_uri=http://localhost:3000&grant_type=authorization_code&code=%s`, opt.googleClientID, opt.googleClientSecret, googleAuthCode)
	resp, err := requestURLWithJsonResponse("POST", "https://oauth2.googleapis.com/token", body, "application/x-www-form-urlencoded", nil, 200)
	if err != nil {
		logrus.Warnf("Error calling Google to exchange code by refresh token. err=%s", err)
		c.JSON(400, gin.H{"message": "Couldn't validate Google auth code"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}
	logrus.Debugf("Google user info=%v", resp)

	googleRefreshToken0, exists := resp["refresh_token"]
	if !exists {
		logrus.Warnf("Google body contents for exchange token doesn't contain a 'refresh_token'. body=%v", resp)
		c.JSON(500, gin.H{"message": "Couldn't exchange auth code"})
		invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
		return
	}
	googleRefreshToken := googleRefreshToken0.(string)

	temail, tname, success := processGoogleRefreshToken(c, googleRefreshToken, pmethod, ppath)
	if !success {
		return
	}
	logrus.Debugf("Google refresh token valid for %s", temail)

	authType := "google"
	success = processCreateActivatedUserIfNeeded(c, temail, tname, pmethod, ppath, authType)
	if !success {
		return
	}

	u, success := processValidateUserActivated(temail, c, pmethod, ppath)
	if !success {
		return
	}

	validateUserAndOutputTokensToResponse(u, c, pmethod, ppath, "google", googleRefreshToken)
	logrus.Debugf("Google login for %s", u.Email)

	return
}

func processGoogleRefreshToken(c *gin.Context, googleRefreshToken string, pmethod string, ppath string) (email string, name string, success bool) {
	logrus.Debugf("Getting Google Access Token from Refresh token")

	headers := make(map[string]string)
	body := fmt.Sprintf(`client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s`, opt.googleClientID, opt.googleClientSecret, googleRefreshToken)
	resp, err := requestURLWithJsonResponse("POST", "https://accounts.google.com/o/oauth2/token", body, "application/x-www-form-urlencoded", headers, 200)
	if err != nil {
		logrus.Infof("Error calling Google to get access token from refresh token. err=%s", err)
		c.JSON(400, gin.H{"message": "Couldn't refresh token"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return email, name, false
	}

	accessToken0, exists := resp["access_token"]
	if !exists {
		return email, name, false
	}
	googleAccessToken := accessToken0.(string)
	logrus.Debugf("Got access token from Google")

	resp, err = requestURLWithJsonResponse("GET", fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", googleAccessToken), "", "", nil, 200)
	if err != nil {
		logrus.Infof("Error calling Google to get profile info from access token. err=%s", err)
		c.JSON(400, gin.H{"message": "Couldn't refresh token"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return email, name, false
	}
	logrus.Debugf("Google user info=%v", resp)

	email0, exists := resp["email"]
	if !exists {
		logrus.Infof("No 'email' in google profile response")
		return email, name, false
	}
	email = email0.(string)

	name0, exists := resp["name"]
	if !exists {
		logrus.Infof("No 'name' in google profile response")
		return email, name, false
	}
	name = name0.(string)

	return email, name, true
}

func processFacebookToken(c *gin.Context, facebookRefreshToken string, pmethod string, ppath string) (email string, name string, success bool) {
	// logrus.Debugf("FB token=%s", facebookToken)
	resp, err := requestURLWithJsonResponse("GET", fmt.Sprintf("https://graph.facebook.com/me?fields=email,name,id&access_token=%s", facebookRefreshToken), "", "", nil, 200)
	if err != nil {
		logrus.Warnf("Facebook didn't validate token. body=%v", resp)
		c.JSON(400, gin.H{"message": "Token could not be validated at Facebook"})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return "", "", false
	}

	temail1, exists := resp["email"]
	if !exists {
		c.JSON(400, gin.H{"message": fmt.Sprintf("Couldn't get email from Facebook token")})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return "", "", false
	}

	//FB bug: https://stackoverflow.com/questions/13510458/golang-convert-iso8859-1-to-utf8
	temail := toUtf8(temail1.(string))

	tname, exists := resp["name"]
	if !exists {
		c.JSON(400, gin.H{"message": fmt.Sprintf("Couldn't get 'name' from Facebook token for user %s", tname)})
		invocationCounter.WithLabelValues(pmethod, ppath, "400").Inc()
		return
	}
	return temail, tname.(string), true
}

func toUtf8(iso88591str string) string {
	iso88591buf := []byte(iso88591str)
	buf := make([]rune, len(iso88591buf))
	for i, b := range iso88591buf {
		buf[i] = rune(b)
	}
	return string(buf)
}

func processCreateActivatedUserIfNeeded(c *gin.Context, email string, name string, pmethod string, ppath string, authType string) bool {
	u := User{}
	if db.First(&u, "email = ?", email).RecordNotFound() {
		logrus.Debugf("User %s not found. Auto creating user for %s login", email, authType)
		t := time.Now()
		u.ActivationDate = &t
		u = User{
			Name:           name,
			Email:          email,
			Enabled:        1,
			CreationDate:   time.Now(),
			ActivationDate: &t,
		}
		err := db.Create(&u).Error
		if err != nil {
			logrus.Warnf("Error creating user email=%s for %s login. err=%s", email, authType, err)
			c.JSON(500, gin.H{"message": "Server error"})
			invocationCounter.WithLabelValues(pmethod, ppath, "500").Inc()
			return false
		}
		logrus.Debugf("New account created from %s login. email=%s", authType, email)
	}
	return true
}
