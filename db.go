package main

import (
	"fmt"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mssql"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/sirupsen/logrus"
)

//User as in database
type User struct {
	Name               string    `gorm:"size:60; not null"`
	Email              string    `gorm:"primary_key"`
	PasswordHash       string    `gorm:"size:100; not null"`
	PasswordDate       time.Time `gorm:"not null"`
	ActivationDate     *time.Time
	WrongPasswordCount uint8 `gorm:"not null; default:0"`
	WrongPasswordDate  *time.Time
	CreationDate       time.Time `gorm:"not null; default:CURRENT_TIMESTAMP"`
	Active             uint8     `gorm:"not null; default:1"`
}

func initDB() (*gorm.DB, error) {
	connectString := opt.dbSqliteFile

	switch opt.dbDialect {
	case "mysql":
		connectString = fmt.Sprintf("%s:%s@(%s)/%s?charset=utf8&parseTime=True&loc=Local",
			opt.dbUsername, opt.dbPassword, opt.dbHost, opt.dbName)
	case "postgres":
		connectString = fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s",
			opt.dbHost, opt.dbPort, opt.dbUsername, opt.dbName, opt.dbPassword)
	case "mssql":
		connectString = fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s",
			opt.dbUsername, opt.dbPassword, opt.dbHost, opt.dbPort, opt.dbName)
	}

	logrus.Infof("Initializing database. dialect=%s; dbname=%s; dbhost=%s; dbport=%d", opt.dbDialect, opt.dbName, opt.dbHost, opt.dbPort)
	db0, err := gorm.Open(opt.dbDialect, connectString)
	if err != nil {
		logrus.Errorf("Couldn't connect to database. err=%s", err)
		return db0, err
	}

	if opt.logLevel == "debug" {
		db0.LogMode(true)
	}

	db0.Set("gorm:table_options", "charset=utf8")

	logrus.Infof("Checking database schema")
	db0.AutoMigrate(&User{})

	return db0, nil
}
