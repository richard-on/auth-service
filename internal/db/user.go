package db

import (
	"database/sql"
	"errors"
	"regexp"
	"time"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/richard-on/auth-service/config"
	"github.com/richard-on/auth-service/internal/model"
	"github.com/richard-on/auth-service/pkg/logger"
)

type DB struct {
	Db  *sql.DB
	Log logger.Logger
}

func NewDatabase(db *sql.DB) *DB {
	return &DB{
		Db: db,
		Log: logger.NewLogger(
			config.DefaultWriter,
			config.LogInfo.Level,
			"auth-db"),
	}
}

// AddUser adds new user to database.
// If user with such login already exists, UserAlreadyExistsError returned. Otherwise, hashed password is generated
// and user inserted into database. If no more errors occurred, nil is returned.
//
// AddUser should only be used within initial configuration. It is not supposed to provide full registration process.
func (db *DB) AddUser(user *model.User) error {
	// Check that login satisfies requirements.
	compile, err := regexp.Compile("^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*$")
	if err != nil {
		log.Fatal().Stack().Err(err)
		return err
	}
	if !compile.MatchString(user.Username) || len(user.Username) > 25 || len(user.Username) < 5 {
		log.Error().Err(err)
		return ErrInvalidLogin
	}

	// Check if user with this login already exists
	res := db.Db.QueryRow("SELECT * FROM users where username = $1", user.Username)
	err = res.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {

		// If login is available, compute hashed password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			return err
		}

		// Insert new user into users table
		_, err = db.Db.Exec("INSERT INTO users(id, username, password, email, last_login) VALUES($1, $2, $3, $4, $5)",
			user.ID, user.Username, hashedPassword, user.Email, time.Now())
		if err != nil {
			return err
		}

	} else if err == nil {
		return ErrUserAlreadyExists
	} else {
		return err
	}

	return nil
}

// GetUser searches a user in database by username.
// It then uses bcrypt.CompareHashAndPassword() to compare password hashes.
// If user with such login isn't found or hashes do not match, BadCredentialsError is returned. Otherwise, nil is returned.
func (db *DB) GetUser(user *model.User) error {
	// Save password that was passed as argument
	stringPassword := user.Password

	// Search user in database by login
	res := db.Db.QueryRow("SELECT * FROM users where username = $1", user.Username)
	err := res.Scan(&user.ID, &user.Username, &user.Password, &user.Email, &user.LastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		// If no such user was found, return ErrBadCredentials.
		return ErrBadCredentials
	} else if err != nil {
		return err
	}

	// Compare hashed password from database with password passed as argument.
	// If they don't match, return ErrBadCredentials.
	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(stringPassword)); err != nil {
		return ErrBadCredentials
	}

	_, err = db.Db.Exec(`UPDATE users SET last_login = $1 WHERE id=$2`, time.Now(), user.ID)
	if err != nil {
		return err
	}

	return nil
}
