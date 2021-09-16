package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math"
	mrand "math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
)

type Unit struct {
	Id   int64  `json:"id"`
	Name string `json:"name"`
	Url  string `json:"url"`
	Tags []Tag  `json:"tags"`
}

type Tag struct {
	Id     int64  `json:"id"`
	UserId int64  `json:"user_id"`
	Name   string `json:"mame"`
}

type User struct {
	Id           int64     `db:"id"`
	Uuid         string    `db:"uuid"`
	Name         string    `db:"name"`
	Email        string    `db:"email"`
	ExpireUuidAt time.Time `db:"expire_uuid_at"`
	Auth         []byte    `db:"authorized"`
}

const (
	MAX_TAG_NAME_SIZE    = 50
	MAX_USER_NAME_SIZE   = 20
	MAX_PASSWORD_SIZE    = 100
	MAX_EMAIL_SIZE       = 100
	JWT_SECRET_CODE      = "gHqpK9FVpgxumCAHzZdRTMz52KhxpfVqZyaf"
	ENABLE_CHAR          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	UUID_SIZE            = 20
	MAX_UNIT_NAME_SIZE   = 100
	MAX_UNIT_URL_SIZE    = 200
	MAX_TAGS_SIZE        = 100
	MAX_TAGS_STRING_SIZE = 1000
	MAX_SQL_EXEC_SIZE    = 1500
	EXPIRE_UUID_LIMIT    = 1 //days
)

var (
	db *sqlx.DB
)

func checkStringNull(str string) bool {
	if strings.ContainsAny(str, ";'\"#*") || strings.Contains(str, "--") {
		return false
	}
	return true
}

func checkString(str string) bool {
	if len(str) == 0 {
		return false
	}
	return checkStringNull(str)
}

func getRandString(length int) string {
	s := make([]byte, length)
	for i := 0; i < length; i++ {
		s[i] = ENABLE_CHAR[mrand.Intn(len(ENABLE_CHAR))]
	}
	return string(s)
}

func getHashPassword(username string, password string) string {
	str := password + "RqJ2iWQHN5Uk" + username
	hash_str := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash_str[:])
}

func checkUuid(u User) error {
	if len(u.Uuid) != UUID_SIZE || !checkString(u.Uuid) {
		return errors.New("uuid is wrong")
	}
	if !time.Now().Before(u.ExpireUuidAt) {
		return errors.New("Forbidden")
	}
	return nil
}

func sqlRepeatInt(fn func(int64) error) (int64, error) {
	var err error
	for i := 0; i < 2; i++ {
		n := mrand.Int63n(math.MaxInt32)
		err = fn(n)
		if err == nil {
			return n, nil
		}
	}
	log.Println("Warning: sqlRepeatInt, SQL repeat finished")
	return 0, err
}
func sqlRepeatString(fn func(string) error, length int) (string, error) {
	var err error
	for i := 0; i < 2; i++ {
		str := getRandString(length)
		err = fn(str)
		if err == nil {
			return str, nil
		}
	}
	log.Println("Warning: sqlRepeatString, SQL repeat finished")
	return "", err
}
func sqlRepeatIntString(fn func(int64, string) error, length int) (int64, string, error) {
	var err error
	for i := 0; i < 2; i++ {
		n := mrand.Int63n(math.MaxInt32)
		str := getRandString(length)
		err = fn(n, str)
		if err == nil {
			return n, str, nil
		}
	}
	log.Println("Warning: sqlRepeatIntString, SQL repeat finished")
	return 0, "", err
}

func getUser(uuid string) (User, error) {
	if len(uuid) != UUID_SIZE || !checkString(uuid) {
		return User{}, errors.New("uuid is wrong")
	}
	users := []User{}
	err := db.Select(&users, "SELECT id, uuid, name, email, expire_uuid_at FROM user_table WHERE uuid = ?", uuid)
	if err != nil {
		return User{}, err
	}
	if len(users) != 1 {
		log.Printf("getUser, SELECT, len(users) == %v", len(users))
		return User{}, errors.New("match error")
	}
	err = checkUuid(users[0])

	if err != nil {
		return User{}, err
	}
	return users[0], nil
}

func sendMail(to, subject, message string) error {
	var password string
	var err error
	password = os.Getenv("gmailpassword")
	if password == "" {
		err = db.QueryRow("SELECT gmailpassword FROM secret_table").Scan(&password)
		if err != nil {
			log.Printf("Error: sendMail, rows.Scan, %v", err)
			return err
		}
	}
	auth := smtp.PlainAuth(
		"",
		"minimohuweb@gmail.com",
		password,
		"smtp.gmail.com",
	)

	return smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"minimohuweb@gmail.com",
		[]string{to},
		[]byte(
			"To: "+to+"\r\n"+
				"Subject:"+subject+"\r\n"+
				"\r\n"+
				message),
	)
}

func recreateUuid(user *User) error {
	uuid, err := sqlRepeatString(func(str string) error {
		_, err := db.Exec("UPDATE user_table SET uuid=?, expire_uuid_at=DATE_ADD(NOW(), INTERVAL ? DAY) WHERE id=?", str, EXPIRE_UUID_LIMIT, user.Id)
		return err
	}, UUID_SIZE)

	if err != nil {
		return err
	}
	user.Uuid = uuid
	user.ExpireUuidAt = time.Now().Add(EXPIRE_UUID_LIMIT * 24 * time.Hour)
	return nil
}

func register(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	email := c.FormValue("email")
	log.Printf("username: %v", username)
	log.Printf("password: %v", password)
	log.Printf("email: %v", email)

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

	users := []User{}
	err := db.Select(&users, "SELECT id, uuid, name, email, expire_uuid_at, authorized FROM user_table WHERE name = ? UNION "+
		"SELECT id, uuid, name, email, expire_uuid_at, authorized FROM user_table WHERE email = ?", username, email)
	if err != nil {
		log.Printf("Error: register, SELECT , %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	for _, user := range users {
		if user.Email == email {
			return c.String(http.StatusBadRequest, "Error: email is used")
		}
		if user.Name == username {
			return c.String(http.StatusBadRequest, "Error: username is used")
		}
	}

	_, uuid, err := sqlRepeatIntString(func(id int64, str string) error {
		_, err := db.Exec("INSERT INTO user_table (id, uuid, name, password, email, expire_uuid_at) VALUES (?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? DAY))",
			id, str, username, password_hash, email, EXPIRE_UUID_LIMIT)
		return err
	}, UUID_SIZE)

	if err != nil {
		log.Printf("Error: register, INSERT , %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	message := "以下のリンクからメールアドレスを認証してください。\n" +
		"localhost:1213/auth?uuid=" + uuid
	err = sendMail(email, "メール認証", message)
	if err != nil {
		log.Printf("Error: register, sendMail , %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return nil
}

func checkEmail(c echo.Context) error {
	uuid := c.QueryParam("uuid")
	users := []User{}
	var err error

	err = db.Select(&users, "SELECT id, uuid, name, email, expire_uuid_at, authorized FROM user_table WHERE uuid=?", uuid)
	if err != nil {
		log.Printf("Error: checkEmail, SELECT id, uuid, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if len(users) == 0 {
		log.Printf("Error: checkEmail, no match user")
		return c.NoContent(http.StatusBadRequest)
	}
	if len(users) > 1 {
		log.Printf("Error: checkEmail, many user")
		return c.NoContent(http.StatusInternalServerError)
	}
	user := users[0]

	_, err = db.Exec("UPDATE user_table SET authorized=true WHERE id=?", user.Id)
	if err != nil {
		log.Printf("Error: checkEmail, UPDATE %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	err = recreateUuid(&user)
	if err != nil {
		log.Printf("Error: checkEmail, recreateUuid, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.String(http.StatusOK, "OK, "+user.Name+" is Authorized")
}

func byteToBool(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) > 1 {
		return true
	}
	if b[0] == 0 {
		return false
	} else {
		return true
	}
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

	users := []User{}

	err := db.Select(&users, "SELECT id, uuid, name, email, expire_uuid_at, authorized FROM user_table WHERE name = ? AND password = ?", username, password_hash)
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

	user := users[0]
	if !byteToBool(user.Auth) {
		return c.String(http.StatusForbidden, "Please authorize email")
	}

	err = checkUuid(user)

	if err != nil {
		if err.Error() != "Forbidden" {
			log.Printf("Error: login, checkUuid, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		err = recreateUuid(&user)
		if err != nil {
			log.Printf("Error: login, recreateUuid, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	return c.JSON(http.StatusOK, map[string]string{
		"uuid": user.Uuid,
	})
}

//POST /tag
func createTag(c echo.Context) error {
	var tag Tag
	var err error
	var user User
	uuid := c.FormValue("uuid")
	user, err = getUser(uuid)
	if err != nil {
		log.Printf("Error: createTag, getUser, %v", err)
		if err.Error() == "Forbidden" {
			return c.NoContent(http.StatusForbidden)
		}
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

	_, err = sqlRepeatInt(func(x int64) error {
		_, err = db.Exec("INSERT INTO tag_table (id,user_id,name) SELECT ?,?,? "+
			"WHERE NOT EXISTS(SELECT id FROM tag_table WHERE user_id = ? AND name = ?)",
			x, tag.UserId, tag.Name, tag.UserId, tag.Name)
		return err
	})

	if err != nil {
		log.Printf("Error: createTag, INSERT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

//POST /tag/:id
func changeTag(c echo.Context) error {
	uuid := c.FormValue("uuid")
	user, err := getUser(uuid)
	if err != nil {
		log.Printf("Error: changeTag, getUserInfo, %v", err)
		if err.Error() == "Forbidden" {
			return c.NoContent(http.StatusForbidden)
		}
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
	uuid := c.QueryParam("uuid")
	user, err := getUser(uuid)
	if err != nil {
		log.Printf("Error: getTag, getUserInfo, %v", err)
		if err.Error() == "Forbidden" {
			return c.NoContent(http.StatusForbidden)
		}
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
	name := c.FormValue("name")
	url := c.FormValue("url")
	tag_str := c.FormValue("tags")
	uuid := c.FormValue("uuid")
	tag_str_list := strings.Split(tag_str, ",")
	if len(name) > MAX_UNIT_NAME_SIZE || !checkStringNull(name) {
		log.Println("Error: Value name")
		return c.String(http.StatusBadRequest, "Error: Value name")
	}
	if len(url) > MAX_UNIT_URL_SIZE || !checkStringNull(url) {
		log.Println("Error: Value name")
		return c.String(http.StatusBadRequest, "Error: Value name")
	}
	user, err := getUser(uuid)
	if err != nil {
		log.Printf("Error: createUnit, getUser, %v", err)
		if err.Error() == "Forbidden" {
			return c.NoContent(http.StatusForbidden)
		}
		return c.String(http.StatusBadRequest, "Error: Value uuid")
	}

	unit_id, err := sqlRepeatInt(func(id int64) error {
		_, err := db.Exec("INSERT INTO unit_table(id, user_id, name, url) VALUES (?,?,?,?)",
			id, user.Id, name, url)
		return err
	})

	if err != nil {
		log.Printf("Error: createUnit, INSERT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	if len(tag_str_list) > MAX_TAGS_SIZE {
		log.Println("Error: tags size is too large")
		return c.String(http.StatusBadRequest, "Error: tags size is too large")
	}

	exec_byte := make([]byte, 0, MAX_SQL_EXEC_SIZE)
	exec_byte = append(exec_byte, "INSERT IGNORE INTO unit_tag(unit_id, tag_id) VALUES "...)

	for i, t := range tag_str_list {
		tag, err := strconv.ParseInt(strings.Trim(t, " "), 10, 64)
		if err != nil {
			log.Println("Error: createUnit, Parse")
			return c.String(http.StatusBadRequest, "Error: Value tags")
		}
		if i > 0 {
			exec_byte = append(exec_byte, ", "...)
		}
		exec_byte = append(exec_byte, ("(" + strconv.FormatInt(unit_id, 10) + "," + strconv.FormatInt(tag, 10) + ")")...)
	}
	if len(tag_str_list) > 0 {
		_, err = db.Exec(string(exec_byte))

		if err != nil {
			log.Printf("Error: createUnit, insert unit_tag, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	return c.NoContent(http.StatusOK)
}

//GET /unit
func getUnit(c echo.Context) error {
	uuid := c.QueryParam("uuid")
	tags_str := c.QueryParam("tags")
	user, err := getUser(uuid)

	if err != nil {
		log.Printf("Error: getUnit, getUser, %v", err)
		if err.Error() == "Forbidden" {
			return c.NoContent(http.StatusForbidden)
		}
		return c.String(http.StatusBadRequest, "Error: Value uuid")
	}

	tags_list := strings.Split(tags_str, ",")
	for _, t := range tags_list {
		_, err = strconv.ParseInt(strings.Trim(t, " "), 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "Error: Value tags")
		}
	}

	rows, err := db.Query("SELECT t1.unit_id,unit_table.name,unit_table.url FROM "+
		"(SELECT unit_id, COUNT(unit_id) as cnt FROM unit_tag WHERE tag_id in (?) "+
		"GROUP BY unit_id) AS t1 LEFT JOIN unit_table ON t1.cnt = ? AND t1.unit_id = unit_table.id AND unit_table.user_id = ?",
		tags_str, len(tags_list), user.Id)

	if err != nil {
		log.Printf("Error: getUnit, SELECT t1.unit_id,unit_table.name, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	units := []Unit{}
	unit_id_list := make([]byte, 0, MAX_SQL_EXEC_SIZE)
	for rows.Next() {
		var u Unit
		err = rows.Scan(&u.Id, &u.Name, &u.Url)
		if err != nil {
			continue
		}
		units = append(units, u)
		unit_id_list = append(unit_id_list, ","...)
		unit_id_list = append(unit_id_list, strconv.FormatInt(u.Id, 10)...)
	}
	unit_id_str := string(unit_id_list[1:])

	log.Println(unit_id_str)
	rows, err = db.Query("SELECT t1.unit_id,tag_table.id,tag_table.name FROM "+
		"(SELECT unit_id, tag_id FROM unit_tag WHERE unit_id in (?)) AS t1 "+
		"LEFT JOIN tag_table ON t1.tag_id = tag_table.id",
		unit_id_str)

	if err != nil {
		log.Printf("Error: getUnit, SELECT t1.unit_id,tag_table.id, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	for rows.Next() {
		var t Tag
		var id int64
		err = rows.Scan(&id, &t.Id, &t.Name)
		if err != nil {
			continue
		}
		t.UserId = user.Id
		for i, u := range units {
			if u.Id == id {
				units[i].Tags = append(units[i].Tags, t)
			}
		}
	}

	return c.JSON(http.StatusOK, units)
}

func testPage(c echo.Context) error {
	log.Println("test!")
	return c.String(http.StatusOK, "Hello, World!")
}

func main() {
	var err error
	e := echo.New()
	mrand.Seed(time.Now().UnixNano())

	var dataSource string
	if os.Getenv("JAWSDB_GOLD_URL") != "" {
		dataSource = "sl18tzgbp14cglnu:cc3cl5f37fcfrd21@tcp(s465z7sj4pwhp7fn.cbetxkdyhwsb.us-east-1.rds.amazonaws.com:3306)/eij8pzwnprvffh1t?parseTime=true"
	} else {
		dataSource = "user483:Te9SLqyciALe@tcp(127.0.0.1:3306)/tagtagyeah?parseTime=true&loc=Asia%2FTokyo"
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
	e.GET("/auth", checkEmail)

	e.GET("/tag", getTag)
	e.POST("/tag", createTag)
	e.POST("/tag/:id", changeTag)
	e.GET("/unit", getUnit)
	e.POST("/unit", createUnit)

	port := os.Getenv("PORT")
	if port == "" {
		port = "1213"
	}

	e.Logger.Fatal(e.Start(":" + port))
}
