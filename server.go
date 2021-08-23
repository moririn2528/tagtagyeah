package main

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/labstack/echo/v4"
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

const (
	MAX_TAG_NAME_SIZE = 50
)

var (
	db *sql.DB
)

func checkString(str string) bool {
	if len(str) == 0 {
		return false
	}
	return !strings.ContainsAny(str, ";'\"")
}

//POST /tag
func createTag(c echo.Context) error {
	var tag Tag
	userId, err := strconv.ParseInt(c.FormValue("user_id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value user id")
	}
	tag.UserId = userId
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
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value id")
	}
	name := c.FormValue("name")
	if len(name) > MAX_TAG_NAME_SIZE || !checkString(name) {
		return c.String(http.StatusBadRequest, "Error: Value name")
	}

	_, err = db.Exec("UPDATE tag_table SET name = ? WHERE id = ?", name, id)
	if err != nil {
		log.Printf("Error: changeTag, UPDATE, %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

//Get /tag
func getTag(c echo.Context) error {
	var userId int64
	var err error
	userId, err = strconv.ParseInt(c.QueryParam("user_id"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Error: Value user id")
	}
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
	e := echo.New()

	var err error
	db, err = sql.Open("mysql", "user483:Te9SLqyciALe@tcp(127.0.0.1:3306)/tagtagyeah")
	if err != nil {
		log.Fatal("failed to open database")
		return
	}
	db.SetMaxOpenConns(5)
	defer db.Close()

	e.GET("/", testPage)
	e.GET("/tag", getTag)
	e.POST("/tag", createTag)
	e.POST("/tag/:id", changeTag)
	e.POST("/unit", createUnit)
	e.Logger.Fatal(e.Start(":1323"))
}
