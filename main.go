package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Unit struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Tags []*Tag `json:"tags"`
}

type Tag struct {
	Id     int64  `json:"id"`
	UserId int64  `json:"user_id"`
	Name   string `json:"mame"`
}

type User struct {
	Id    int64
	Name  string
	Email string
}

const (
	MAX_TAG_NAME_SIZE  = 50
	MAX_USER_ID        = math.MaxInt32
	MAX_USER_NAME_SIZE = 20
	MAX_PASSWORD_SIZE  = 100
	MAX_EMAIL_SIZE     = 100
	JWT_SECRET_CODE    = "gHqpK9FVpgxumCAHzZdRTMz52KhxpfVqZyaf"
)

var (
	db *sqlx.DB
)

func checkString(str string) bool {
	if len(str) == 0 {
		return false
	}
	return !strings.ContainsAny(str, ";'\"")
}

func getHashPassword(username string, password string) string {
	str := password + "RqJ2iWQHN5Uk" + username
	hash_str := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash_str[:])
}

func register(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	email := c.FormValue("email")
	log.Printf("username: %v", username)
	log.Printf("password: %v", password)
	log.Printf("email: %v", email)
	var userId int64

	if len(username) > MAX_USER_NAME_SIZE || !checkString(username) {
		return c.String(http.StatusBadRequest, "Error: Value username")
	}
	if len(password) > MAX_PASSWORD_SIZE || !checkString(password) {
		return c.String(http.StatusBadRequest, "Error: Value password")
	}
	if len(email) > MAX_EMAIL_SIZE || !checkString(email) {
		return c.String(http.StatusBadRequest, "Error: Value email")
	}
	password_hash := getHashPassword(username, password)

	type GetUser struct {
		Id       int64  `db:"id"`
		Username string `db:"name"`
		Email    string `db:"email"`
	}
	users := []GetUser{}
	err := db.Select(&users, "SELECT id, name, email FROM user_table")
	if err != nil {
		log.Printf("Error: register, SELECT , %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	for _, user := range users {
		if user.Email == email {
			return c.String(http.StatusBadRequest, "Error: email is used")
		}
		if user.Username == username {
			return c.String(http.StatusBadRequest, "Error: username is used")
		}
	}
	usedFlag := true
	for usedFlag {
		usedFlag = false
		id, err := rand.Int(rand.Reader, big.NewInt(MAX_USER_ID))
		if err != nil {
			log.Printf("Error: register, rand.Int , %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		if !id.IsInt64() {
			log.Println("Error: register, id.IsInt64")
			return c.NoContent(http.StatusInternalServerError)
		}
		userId = id.Int64()
		for _, user := range users {
			if user.Id == userId {
				usedFlag = true
			}
		}
	}

	_, err = db.Exec("INSERT INTO user_table (id, name, password, email) VALUES (?,?,?,?)", userId, username, password_hash, email)
	if err != nil {
		log.Printf("Error: register, INSERT , %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return nil
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if len(username) > MAX_USER_NAME_SIZE || !checkString(username) {
		return c.String(http.StatusBadRequest, "Error: Value username")
	}
	if len(password) > MAX_PASSWORD_SIZE || !checkString(password) {
		return c.String(http.StatusBadRequest, "Error: Value password")
	}
	password_hash := getHashPassword(username, password)

	type UserInfo struct {
		Id    int64  `db:"id"`
		Email string `db:"email"`
	}
	users := []UserInfo{}

	err := db.Select(&users, "SELECT id, email FROM user_table WHERE name = ? AND password = ?", username, password_hash)
	if err != nil {
		log.Printf("Error: login, SELECT COUNT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if len(users) > 1 {
		log.Printf("Error: login, many match in user_table, username = %v, password_hash = %v", username, password_hash)
		return c.NoContent(http.StatusInternalServerError)
	}
	if len(users) == 0 {
		return c.String(http.StatusUnauthorized, "no match")
	}
	userId := users[0].Id
	email := users[0].Email

	token_gen := jwt.New(jwt.SigningMethodHS256)

	claims := token_gen.Claims.(jwt.MapClaims)
	claims["jti"] = strconv.FormatInt(userId, 10)
	claims["name"] = username
	claims["password"] = password
	claims["email"] = email
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	token, err := token_gen.SignedString([]byte(JWT_SECRET_CODE))
	if err != nil {
		log.Printf("Error: login, token_gen.SignedString, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"token": token,
	})
}

func getUserInfo(c echo.Context) (User, error) {
	var user User
	//tokenStr := c.Response().Header().Get("token")
	//TODO change
	tokenStr := c.QueryParam("token")
	if tokenStr == "" {
		tokenStr = c.FormValue("token")
	}
	if tokenStr == "" {
		log.Println("not have token")
		return user, errors.New("not have token")
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_SECRET_CODE), nil
	})
	if err != nil {
		log.Printf("Error: getUserInfo, jwt.Parse(token, %v", err)
		return user, err
	}

	claims := token.Claims.(jwt.MapClaims)
	user.Id, err = strconv.ParseInt(claims["jti"].(string), 10, 64)
	user.Name = claims["name"].(string)
	user.Email = claims["email"].(string)
	if err != nil {
		log.Printf("Error: getUserInfo, ParseInt jti, %v", err)
		return user, err
	}
	return user, nil
}

//POST /tag
func createTag(c echo.Context) error {
	var tag Tag
	var err error
	user, err := getUserInfo(c)
	if err != nil {
		log.Printf("Error: createTag, getUserInfo, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	tag.UserId = user.Id
	tag.Name = c.FormValue("name")
	if len(tag.Name) > MAX_TAG_NAME_SIZE || !checkString(tag.Name) {
		return c.String(http.StatusBadRequest, "Error: Value name")
	}

	if db == nil {
		log.Println("database null")
	}
	_, err = db.Exec("INSERT INTO tag_table (user_id,name) SELECT ?,? "+
		"WHERE NOT EXISTS(SELECT id FROM tag_table WHERE user_id = ? AND name = ?)",
		tag.UserId, tag.Name, tag.UserId, tag.Name)

	if err != nil {
		log.Printf("Error: createTag, INSERT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

//POST /tag/:id
func changeTag(c echo.Context) error {
	user, err := getUserInfo(c)
	if err != nil {
		log.Printf("Error: changeTag, getUserInfo, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value id")
	}
	name := c.FormValue("name")
	if len(name) > MAX_TAG_NAME_SIZE || !checkString(name) {
		return c.String(http.StatusBadRequest, "Error: Value name")
	}

	_, err = db.Exec("UPDATE tag_table SET name = ? WHERE id = ? AND user_id = ?", name, id, user.Id)
	if err != nil {
		log.Printf("Error: changeTag, UPDATE, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

//Get /tag
func getTag(c echo.Context) error {
	var err error
	user, err := getUserInfo(c)
	if err != nil {
		log.Printf("Error: getTag, getUserInfo, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	userId := user.Id
	phrase := c.QueryParam("search_phrase")

	rows, err := db.Query("SELECT id, user_id, name from tag_table WHERE user_id = ?", userId)
	if err != nil {
		log.Printf("Error: getTag, SELECT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer rows.Close()

	var res []*Tag

	for rows.Next() {
		var id int64
		var name string
		rows.Scan(&id, &userId, &name)
		if strings.HasPrefix(name, phrase) {
			tag := Tag{
				Id:     id,
				UserId: userId,
				Name:   name,
			}
			res = append(res, &tag)
		}
	}
	err = rows.Err()
	if err != nil {
		log.Println(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, res)
}

//POST /unit
func createUnit(c echo.Context) error {
	return nil
}

func testPage(c echo.Context) error {
	log.Println("test!")
	return c.String(http.StatusOK, "Hello, World!")
}

func main() {
	var err error
	e := echo.New()

	var dataSource string
	if os.Getenv("JAWSDB_GOLD_URL") != "" {
		dataSource = "sl18tzgbp14cglnu:cc3cl5f37fcfrd21@tcp(s465z7sj4pwhp7fn.cbetxkdyhwsb.us-east-1.rds.amazonaws.com:3306)/eij8pzwnprvffh1t?parseTime=true"
	} else {
		dataSource = "user483:Te9SLqyciALe@tcp(127.0.0.1:3306)/tagtagyeah?parseTime=true"
	}
	db, err = sqlx.Open("mysql", dataSource)
	if err != nil {
		log.Fatal("failed to open database")
		return
	}
	db.SetMaxOpenConns(5)
	defer db.Close()

	e.GET("/testpage", testPage)
	e.POST("/login", login)
	e.POST("/register", register)

	r := e.Group("/restricted")
	r.Use(middleware.JWT([]byte(JWT_SECRET_CODE)))
	r.GET("/tag", getTag)
	r.POST("/tag", createTag)
	r.POST("/tag/:id", changeTag)
	r.POST("/unit", createUnit)

	port := os.Getenv("PORT")
	if port == "" {
		port = "1213"
	}

	e.Logger.Fatal(e.Start(":" + port))
}
