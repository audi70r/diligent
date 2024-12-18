package db

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() error {
	var err error
	DB, err = gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	// Auto migrate your models here
	err = DB.AutoMigrate(&Log{})
	if err != nil {
		return err
	}

	return nil
}

type Log struct {
	gorm.Model
	ID      uint
	Date    string
	Content string
}

func CreateLog(date time.Time, content string) error {
	log := Log{
		Date:    date.Format("2006-01-02 15:04:05"),
		Content: content,
	}
	result := DB.Create(&log)
	return result.Error
}
