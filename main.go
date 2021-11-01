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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
)

type Unit struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Url  string `json:"url"`
	Tags []Tag  `json:"tags"`
}

type Tag struct {
	Id     int    `json:"id"`
	UserId int    `json:"user_id"`
	Name   string `json:"name"`
}

type User struct {
	Id           int       `db:"id" json:"id"`
	Uuid         string    `db:"uuid" json:"uuid"`
	Name         string    `db:"name" json:"name"`
	Email        string    `db:"email" json:"email"`
	ExpireUuidAt time.Time `db:"expire_uuid_at" json:"expire_uuid_at"`
	Auth         []byte    `db:"authorized" json:"-"`
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
	SENDING_MAIL_LIMIT   = 10
	LIMIT_OUTPUT_TAG     = 100
)

var (
	db                    *sqlx.DB
	working_directory     string
	sending_mail_times    map[int]int = make(map[int]int)
	last_sending_mail_day time.Time   = time.Now()
	cloud                 string
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
func checkStringRestrict(str string) bool { // username, uuid
	if len(str) == 0 {
		return false
	}
	for _, c := range str {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) {
			return false
		}
	}
	return true
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

func sqlRepeatInt(fn func(int) error) (int, error) {
	var err error
	for i := 0; i < 2; i++ {
		n := mrand.Intn(math.MaxInt32)
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
func sqlRepeatIntString(fn func(int, string) error, length int) (int, string, error) {
	var err error
	for i := 0; i < 2; i++ {
		n := mrand.Intn(math.MaxInt32)
		str := getRandString(length)
		err = fn(n, str)
		if err == nil {
			return n, str, nil
		}
	}
	log.Println("Warning: sqlRepeatIntString, SQL repeat finished")
	return 0, "", err
}

func getUser(uuid string, c *echo.Context) (User, bool, error) {
	if len(uuid) != UUID_SIZE || !checkString(uuid) {
		log.Println("Error: getUser, uuid is wrong")
		return User{}, false, (*c).String(http.StatusBadRequest, "Error: Value uuid")
	}
	users := []User{}
	err := db.Select(&users, "SELECT id, uuid, name, email, expire_uuid_at FROM user_table WHERE uuid = ?", uuid)
	if err != nil {
		log.Printf("Error: getUser, SELECT, %v", err)
		return User{}, false, (*c).NoContent(http.StatusInternalServerError)
	}
	if len(users) != 1 {
		log.Printf("getUser, SELECT, len(users) == %v", len(users))
		return User{}, false, (*c).NoContent(http.StatusInternalServerError)
	}

	err = checkUuid(users[0])

	if err != nil {
		if err.Error() == "Forbidden" {
			return User{}, false, (*c).String(http.StatusForbidden, "uuid is expired")
		}
		log.Printf("getUser, checkUuid, %v", err)
		return User{}, false, (*c).NoContent(http.StatusInternalServerError)
	}
	return users[0], true, nil
}

func get_aws_parameger(param string) (string, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region: aws.String("ap-northeast-3"),
		},
		Profile: "default",
	})
	if err != nil {
		log.Printf("Error: get_aws_parameger, NewSessionWithOptions, %v", err)
		return "", err
	}
	svc := ssm.New(sess)

	res, err := svc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(param),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		log.Printf("Error: get_aws_parameger, GetParameter, %v", err)
		return "", err
	}

	return *(res.Parameter.Value), nil
}

func sendEmail(to, subject, message string) error {
	log.Println("sending mail ...")
	defer log.Println("sending mail finished")

	var password string
	var err error
	if cloud == "heroku" {
		password = os.Getenv("gmailpassword")
	} else if cloud == "AWS" {
		password, err = get_aws_parameger("/app2/dev/gmailpassword")
		if err != nil {
			log.Printf("Error: sendMail, get_aws_parameger, %v", err)
			return err
		}
	} else {
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

func sendAuthorizeEmail(to, subject, message, uuid string, id int) error {
	tm := time.Now()

	if tm.Day() != last_sending_mail_day.Day() || tm.Month() != last_sending_mail_day.Month() || tm.Year() != last_sending_mail_day.Year() {
		sending_mail_times = make(map[int]int)
	}
	_, ok := sending_mail_times[id]
	if !ok {
		sending_mail_times[id] = 0
	}
	if sending_mail_times[id] >= SENDING_MAIL_LIMIT {
		return errors.New("send too many mails in 1 day")
	}
	sending_mail_times[id]++
	last_sending_mail_day = time.Now()

	if subject == "" {
		subject = "メール認証"
	}
	if message == "" {
		message = "以下のリンクからメールアドレスを認証してください。\n<url>\n"
	}
	message = strings.Replace(message, "<url>", working_directory+"/auth?uuid="+uuid, -1)

	err := sendEmail(to, subject, message)
	return err
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

	if len(username) > MAX_USER_NAME_SIZE || !checkStringRestrict(username) {
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

	id, uuid, err := sqlRepeatIntString(func(id int, str string) error {
		_, err := db.Exec("INSERT INTO user_table (id, uuid, name, password, email, expire_uuid_at) VALUES (?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? DAY))",
			id, str, username, password_hash, email, EXPIRE_UUID_LIMIT)
		return err
	}, UUID_SIZE)

	if err != nil {
		log.Printf("Error: register, INSERT , %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	err = sendAuthorizeEmail(email, "", "", uuid, id)
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

//POST /auth
func sendAuthEmailByUsername(c echo.Context) error {
	username := c.FormValue("username")
	if !checkStringRestrict(username) {
		log.Println("Error: Value username")
		return c.String(http.StatusBadRequest, "Error: Value username")
	}
	users := []User{}
	err := db.Select(&users, "SELECT id, uuid, name, email, expire_uuid_at, authorized FROM user_table "+
		"WHERE name = ?", username)
	if err != nil || len(users) == 0 || len(users) > 1 {
		log.Printf("Error: sendAuthEmailByUsername, SELECT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	user := users[0]
	err = checkUuid(user)
	if err != nil {
		if err.Error() != "Forbidden" {
			log.Printf("Error: sendAuthEmailByUsername, checkUuid, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		err = recreateUuid(&user)
		if err != nil {
			log.Printf("Error: sendAuthEmailByUsername, recreateUuid, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	err = sendAuthorizeEmail(user.Email, "", "", user.Uuid, user.Id)
	if err != nil {
		log.Printf("Error: sendAuthEmailByUsername, sendAuthorizeEmail, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

//POST /tag
func createTag(c echo.Context) error {
	var tag Tag
	var err error
	uuid := c.FormValue("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	tag.UserId = user.Id
	tag.Name = c.FormValue("name")
	if len(tag.Name) > MAX_TAG_NAME_SIZE || !checkString(tag.Name) {
		return c.String(http.StatusBadRequest, "Error: Value name")
	}

	if db == nil {
		log.Println("database null")
	}

	tag.Id, err = sqlRepeatInt(func(x int) error {
		_, err = db.Exec("INSERT INTO tag_table (id,user_id,name) SELECT ?,?,? "+
			"WHERE NOT EXISTS(SELECT id FROM tag_table WHERE user_id = ? AND name = ?)",
			x, tag.UserId, tag.Name, tag.UserId, tag.Name)
		return err
	})

	if err != nil {
		log.Printf("Error: createTag, INSERT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, map[string]int{"id": tag.Id})
}

//PUT /tag
func updateTag(c echo.Context) error {
	uuid := c.FormValue("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	id, err := strconv.ParseInt(c.FormValue("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value id")
	}
	name := c.FormValue("name")
	if len(name) > MAX_TAG_NAME_SIZE || !checkString(name) {
		return c.String(http.StatusBadRequest, "Error: Value name")
	}

	s, err := db.Exec("UPDATE tag_table SET name = ? WHERE id = ? AND user_id = ?", name, id, user.Id)
	if err != nil {
		log.Printf("Error: updateTag, UPDATE, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	r, err := s.RowsAffected()
	if err != nil {
		log.Printf("Error: updateTag, UPDATE, RowsAffected, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if r != 1 {
		log.Printf("Error: updateTag, Forbidden")
		return c.NoContent(http.StatusForbidden)
	}

	return c.NoContent(http.StatusOK)
}

// func similarity_string(phrase, sa string) int {
// 	const N = 2 // n gram
// 	var ra = []rune(phrase)
// 	var rb = []rune(sa)
// 	var s = 0
// 	for i := 0; i+N <= len(ra); i++ {
// 		var flag = false
// 		for j := 0; j+N <= len(rb); j++ {
// 			if string(ra[i:i+N]) == string(rb[j:j+N]) {
// 				flag = true
// 				break
// 			}
// 		}
// 		if flag {
// 			s++
// 		}
// 	}
// 	return s
// }

func getTag(c echo.Context) error {
	var err error
	uuid := c.QueryParam("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	userId := user.Id
	phrase := c.QueryParam("search_phrase")
	limit_str := c.QueryParam("limit")
	var limit int
	if limit_str == "" {
		limit = LIMIT_OUTPUT_TAG + 1
	} else {
		limit, err = strconv.Atoi(limit_str)
		if err != nil {
			return c.String(http.StatusBadRequest, "Error: Value limit")
		}
		if LIMIT_OUTPUT_TAG < limit {
			limit = LIMIT_OUTPUT_TAG
		}
	}
	phrase_map := map[string]int{}
	for i := 0; i+1 < len(phrase); i++ {
		phrase_map[phrase[i:i+2]]++
	}

	rows, err := db.Query("SELECT id, user_id, name from tag_table WHERE user_id = ?", userId)
	if err != nil {
		log.Printf("Error: getTag, SELECT, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer rows.Close()

	var res []*Tag
	var index = -1

	tag_ids := map[int][]int{}
	sim_list := []int{}

	for rows.Next() {
		index = index + 1
		var id int
		var name string
		err = rows.Scan(&id, &userId, &name)
		if err != nil {
			continue
		}
		i := len(res)
		tag := Tag{
			Id:     id,
			UserId: userId,
			Name:   name,
		}
		res = append(res, &tag)
		sim := 0
		for j := 0; j+1 < len(name); j++ {
			v, ok := phrase_map[name[j:j+2]]
			if ok {
				sim += v
			}
		}
		_, ok := tag_ids[sim]
		if !ok {
			sim_list = append(sim_list, sim)
		}
		tag_ids[sim] = append(tag_ids[sim], i)
	}

	err = rows.Err()
	if err != nil {
		log.Println(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	if phrase == "" && LIMIT_OUTPUT_TAG < limit {
		return c.JSON(http.StatusOK, res)
	}
	if LIMIT_OUTPUT_TAG < limit || limit <= 0 {
		limit = LIMIT_OUTPUT_TAG
	}
	sort.Slice(sim_list, func(i, j int) bool { return sim_list[i] > sim_list[j] })
	var ans []*Tag
	for _, sim := range sim_list {
		for _, v := range tag_ids[sim] {
			ans = append(ans, res[v])
			if limit <= len(ans) {
				break
			}
		}
		if limit <= len(ans) {
			break
		}
	}

	return c.JSON(http.StatusOK, ans)
}

//DELETE /tag:id
func deleteTag(c echo.Context) error {
	var err error
	uuid := c.QueryParam("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value id")
	}

	s, err := db.Exec("DELETE FROM tag_table WHERE id = ? AND user_id = ?", id, user.Id)
	if err != nil {
		log.Printf("Error: deleteTag, DELETE FROM tag_table, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	r, err := s.RowsAffected()
	if err != nil {
		log.Printf("Error: deleteTag, DELETE FROM tag_table, RowsAffected, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if r != 1 {
		log.Printf("Error: deleteTag, Forbidden")
		return c.NoContent(http.StatusForbidden)
	}
	_, err = db.Exec("DELETE FROM unit_tag WHERE tag_id = ?", id)
	if err != nil {
		log.Printf("Error: deleteTag, DELETE FROM unit_tag, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.NoContent(http.StatusOK)
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
		log.Println("Error: Value url")
		return c.String(http.StatusBadRequest, "Error: Value url")
	}
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}

	unit_id, err := sqlRepeatInt(func(id int) error {
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
		exec_byte = append(exec_byte, ("(" + strconv.Itoa(unit_id) + "," + strconv.FormatInt(tag, 10) + ")")...)
	}
	if len(tag_str_list) > 0 {
		_, err = db.Exec(string(exec_byte))

		if err != nil {
			log.Printf("Error: createUnit, insert unit_tag, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	return c.JSON(http.StatusOK, map[string]int{"id": unit_id})
}

func getAllUnit(c echo.Context, user User) error {
	units := []Unit{}
	rows, err := db.Query("SELECT t1.id,t1.name,t1.url,tag_table.id,tag_table.name FROM "+
		"(SELECT unit_tag.tag_id,unit_table.id,unit_table.name,unit_table.url FROM unit_tag "+
		"LEFT JOIN unit_table ON unit_tag.unit_id = unit_table.id AND unit_table.user_id = ?) AS t1 "+
		"LEFT JOIN tag_table ON t1.tag_id = tag_table.id",
		user.Id)
	if err != nil {
		log.Printf("Error: getUnit, SELECT t1.unit_id,tag_table.id, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	for rows.Next() {
		var t Tag
		var id int
		var uname, uurl string
		err = rows.Scan(&id, &uname, &uurl, &t.Id, &t.Name)
		if err != nil {
			continue
		}
		t.UserId = user.Id
		flag := false
		for i, u := range units {
			if u.Id == id {
				units[i].Tags = append(units[i].Tags, t)
				flag = true
			}
		}
		if !flag {
			units = append(units, Unit{Id: id, Name: uname, Url: uurl,
				Tags: []Tag{t}})
		}
	}

	return c.JSON(http.StatusOK, units)
}

//GET /unit
func getUnit(c echo.Context) error {
	uuid := c.QueryParam("uuid")
	tags_str := strings.Trim(c.QueryParam("tags"), " ")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	if tags_str == "" {
		return getAllUnit(c, user)
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
		unit_id_list = append(unit_id_list, strconv.Itoa(u.Id)...)
	}
	unit_id_str := string(unit_id_list[1:])

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
		var id int
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

//PUT /unit
func updateUnit(c echo.Context) error {
	id_str := c.FormValue("id")
	name := c.FormValue("name")
	url := c.FormValue("url")
	tag_str := c.FormValue("tags")
	uuid := c.FormValue("uuid")
	if len(name) > MAX_UNIT_NAME_SIZE || !checkStringNull(name) {
		log.Println("Error: updateUnit, Value name")
		return c.String(http.StatusBadRequest, "Error: Value name")
	}
	if len(url) > MAX_UNIT_URL_SIZE || !checkStringNull(url) {
		log.Println("Error: updateUnit, Value url")
		return c.String(http.StatusBadRequest, "Error: Value url")
	}
	id, err := strconv.ParseInt(id_str, 10, 64)
	if err != nil {
		log.Println("Error: id, ParseInt")
		return c.String(http.StatusBadRequest, "Error: Value id")
	}
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	sets := []string{}
	if name != "" {
		sets = append(sets, "name='"+name+"'")
	}
	if url != "" {
		sets = append(sets, "url='"+url+"'")
	}
	if len(sets) > 0 {
		s, err := db.Exec("UPDATE unit_table SET "+strings.Join(sets, ",")+" WHERE id = ? AND user_id = ?",
			id, user.Id)
		if err != nil {
			log.Printf("Error: updateUnit, UPDATE unit_table, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		r, err := s.RowsAffected()
		if err != nil {
			log.Printf("Error: updateUnit, UPDATE unit_table, RowsAffected, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		if r != 1 {
			log.Printf("Error: updateUnit, Forbidden")
			return c.NoContent(http.StatusForbidden)
		}
	} else {
		var cnt int
		err = db.QueryRow("SELECT COUNT(id) FROM unit_table WHERE id = ? AND user_id = ?",
			id, user.Id).Scan(&cnt)
		if err != nil {
			log.Printf("Error: updateUnit, SELECT COUNT(id), %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		if cnt != 1 {
			log.Println("Error: updateUnit, Forbidden")
			return c.NoContent(http.StatusForbidden)
		}
	}

	if tag_str != "" {
		tag_list := strings.Split(tag_str, ",")
		insert_tag_list := []string{}
		for _, t := range tag_list {
			t = strings.Trim(t, " ")
			_, err = strconv.ParseInt(t, 10, 64)
			if err != nil {
				log.Printf("Error: updateUnit, ParseInt, tag, %v", err)
			}
			insert_tag_list = append(insert_tag_list,
				"("+id_str+","+t+")")
		}

		_, err = db.Exec("DELETE FROM unit_tag WHERE unit_id = ?", id)
		if err != nil {
			log.Printf("Error: updateUnit, DELETE FROM unit_tag, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		_, err = db.Exec("INSERT INTO unit_tag(unit_id, tag_id) VALUES " + strings.Join(insert_tag_list, ","))
		if err != nil {
			log.Printf("Error: updateUnit, INSERT INTO unit_tag, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	return c.NoContent(http.StatusOK)
}

//DELETE /unit/:id
func deleteUnit(c echo.Context) error {
	var err error
	uuid := c.QueryParam("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value id")
	}

	s, err := db.Exec("DELETE FROM unit_table WHERE id = ? AND user_id = ?", id, user.Id)
	if err != nil {
		log.Printf("Error: deleteUnit, DELETE FROM unit_table, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	r, err := s.RowsAffected()
	if err != nil {
		log.Printf("Error: deleteUnit, DELETE FROM unit_table, RowsAffected, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	if r != 1 {
		log.Printf("Error: deleteUnit, Forbidden")
		return c.NoContent(http.StatusForbidden)
	}
	_, err = db.Exec("DELETE FROM unit_tag WHERE unit_id = ?", id)
	if err != nil {
		log.Printf("Error: deleteUnit, DELETE FROM unit_tag, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.NoContent(http.StatusOK)
}

func getUserAPI(c echo.Context) error {
	uuid := c.QueryParam("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	return c.JSON(http.StatusOK, user)
}

func updateUser(c echo.Context) error {
	var err error
	uuid := c.FormValue("uuid")
	name := c.FormValue("username")
	pass := c.FormValue("password")
	email := c.FormValue("email")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	if len(name) > MAX_USER_NAME_SIZE || (name != "" && !checkStringRestrict(name)) {
		return c.String(http.StatusBadRequest, "Error: Value username")
	}
	if len(pass) > MAX_PASSWORD_SIZE || !checkStringNull(pass) {
		return c.String(http.StatusBadRequest, "Error: Value password")
	}
	if len(email) > MAX_EMAIL_SIZE || !checkStringNull(email) {
		return c.String(http.StatusBadRequest, "Error: Value email")
	}

	if name == "" && pass == "" && email == "" {
		return c.NoContent(http.StatusBadGateway)
	}
	sets := []string{}
	sets_name := []string{}
	if name != "" && name != user.Name {
		sets = append(sets, "name='"+name+"'")
		sets_name = append(sets_name, "ユーザー名")
	}
	if pass != "" {
		sets = append(sets, "password='"+pass+"'")
		sets_name = append(sets_name, "パスワード")
	}
	if email != "" && email != user.Email {
		sets = append(sets, "email='"+email+"'")
		sets = append(sets, "authorized=false")
		sets_name = append(sets_name, "メールアドレス")
	}
	message := strings.Join(sets_name, "、") + "が変更されました。\n" +
		"心当たりがない場合は開発者に連絡してください。\n"
	if email != "" {
		message += "メールアドレスが変更されたため、以下のリンクから認証してください。\n<url>\n"
	} else {
		email = user.Email
	}

	_, err = db.Exec("UPDATE user_table SET "+strings.Join(sets, ",")+" WHERE id=?", user.Id)
	if err != nil {
		log.Printf("Error: updateUser, UPDATE, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	err = sendAuthorizeEmail(email, "ユーザー情報変更", message, user.Uuid, user.Id)
	if err != nil {
		log.Printf("Error: updateUser, sendAuthorizeEmail, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

//DELETE /user/:uuid
func deleteUser(c echo.Context) error {
	var err error
	uuid := c.Param("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}

	_, err = db.Exec("DELETE FROM unit_tag WHERE unit_id in (SELECT id FROM unit_table WHERE user_id = ?)", user.Id)
	if err != nil {
		log.Printf("Error: deleteUser, DELETE FROM unit_tag, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	_, err = db.Exec("DELETE FROM unit_table WHERE user_id = ?", user.Id)
	if err != nil {
		log.Printf("Error: deleteUser, DELETE FROM unit_table, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	_, err = db.Exec("DELETE FROM tag_table WHERE user_id = ?", user.Id)
	if err != nil {
		log.Printf("Error: deleteUser, DELETE FROM tag_table, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	_, err = db.Exec("DELETE FROM user_table WHERE id=?", user.Id)
	if err != nil {
		log.Printf("Error: deleteUser, DELETE FROM user_table, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return nil
}

func testPage(c echo.Context) error {
	log.Println("test!")
	return c.String(http.StatusOK, "Hello, World!")
}

func testCreateTag(c echo.Context) error {
	const N = 10000
	const M = 10
	uuid := c.FormValue("uuid")
	user, ok, err := getUser(uuid, &c)
	if !ok {
		return err
	}
	userId := user.Id

	if db == nil {
		log.Println("database null")
	}

	for j := 0; j < M; j++ {
		_, err = sqlRepeatInt(func(x int) error {
			if math.MaxInt32-N < x {
				return errors.New("x range error")
			}
			cmd := "INSERT INTO tag_table (id,user_id,name) VALUES "
			for i := 0; i < N; i++ {
				if i > 0 {
					cmd += ","
				}
				cmd += "(" + strconv.Itoa(x+i) + "," + strconv.Itoa(userId) + ",'" + getRandString(20) + "')"
			}
			_, err = db.Exec(cmd)
			return err
		})
		if err != nil {
			log.Printf("Error: createTag, INSERT, %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	return c.String(http.StatusOK, "Create OK!")
}

func main() {
	var err error
	e := echo.New()
	mrand.Seed(time.Now().UnixNano())

	var dataSource, port string
	cloud = os.Getenv("CLOUD")
	if cloud == "heroku" {
		log.Println("Execute in heroku")
		dataSource = "sl18tzgbp14cglnu:cc3cl5f37fcfrd21@tcp(s465z7sj4pwhp7fn.cbetxkdyhwsb.us-east-1.rds.amazonaws.com:3306)/eij8pzwnprvffh1t?parseTime=true&loc=Asia%2FTokyo"
		working_directory = "https://tagtagyeah.herokuapp.com"
		port = os.Getenv("PORT")
	} else if cloud == "AWS" {
		log.Println("Execute in AWS")
		dataSource = "jH69d8bS:bhWReNAgKxRKuVhB8EhS@tcp(127.0.0.1:3306)/tagtagyeah?parseTime=true&loc=Asia%2FTokyo"
		working_directory = "http://15.152.125.29"
		port = "80"
	} else {
		log.Println("Execute in local")
		dataSource = "user483:Te9SLqyciALe@tcp(127.0.0.1:3306)/tagtagyeah?parseTime=true&loc=Asia%2FTokyo"
		working_directory = "localhost:1213"
		port = "1213"
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
	e.POST("/auth", sendAuthEmailByUsername)

	e.GET("/tag", getTag)
	e.POST("/tag", createTag)
	e.PUT("/tag", updateTag)
	e.DELETE("/tag/:id", deleteTag)
	e.GET("/unit", getUnit)
	e.POST("/unit", createUnit)
	e.PUT("/unit", updateUnit)
	e.DELETE("/unit/:id", deleteUnit)
	e.GET("/user", getUserAPI)
	e.PUT("/user", updateUser)
	e.DELETE("/user/:uuid", deleteUser)

	// beta version
	e.POST("/beta/tag", testCreateTag)

	e.Logger.Fatal(e.Start(":" + port))
}
