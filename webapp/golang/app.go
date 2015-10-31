package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	db        *sql.DB
	store     *sessions.CookieStore
	apidata   map[string]map[string]map[string]interface{}
	endpoints map[string]map[string]string
)

type User struct {
	ID    int
	Email string
	Grade string
}

type Arg map[string]*Service

type Service struct {
	Token  string            `json:"token"`
	Keys   []string          `json:"keys"`
	Params map[string]string `json:"params"`
}

type Data struct {
	Service string                 `json:"service"`
	Data    map[string]interface{} `json:"data"`
}

var saltChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isucon5q-go.session")
	return session
}

func getTemplatePath(file string) string {
	return path.Join("templates", file)
}

func render(w http.ResponseWriter, r *http.Request, status int, file string, data interface{}) {
	tpl := template.Must(template.New(file).ParseFiles(getTemplatePath(file)))
	w.WriteHeader(status)
	checkErr(tpl.Execute(w, data))
}

func authenticate(w http.ResponseWriter, r *http.Request, email, passwd string) *User {
	query := `SELECT id, email, grade FROM users WHERE email=$1 AND passhash=digest(salt || $2, 'sha512')`
	row := db.QueryRow(query, email, passwd)
	user := User{}
	err := row.Scan(&user.ID, &user.Email, &user.Grade)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		checkErr(err)
	}
	session := getSession(w, r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
	return &user
}

func getCurrentUser(w http.ResponseWriter, r *http.Request) *User {
	u := context.Get(r, "user")
	if u != nil {
		user := u.(User)
		return &user
	}
	session := getSession(w, r)
	userID, ok := session.Values["user_id"]
	if !ok || userID == nil {
		return nil
	}
	row := db.QueryRow(`SELECT id,email,grade FROM users WHERE id=$1`, userID)
	user := User{}
	err := row.Scan(&user.ID, &user.Email, &user.Grade)
	if err == sql.ErrNoRows {
		clearSession(w, r)
		return nil
	}
	checkErr(err)
	context.Set(r, "user", user)
	return &user
}

func generateSalt() string {
	salt := make([]rune, 32)
	for i := range salt {
		salt[i] = saltChars[rand.Intn(len(saltChars))]
	}
	return string(salt)
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	delete(session.Values, "user_id")
	session.Save(r, w)
}

func GetSignUp(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	render(w, r, http.StatusOK, "signup.html", nil)
}

func PostSignUp(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	passwd := r.FormValue("password")
	grade := r.FormValue("grade")
	salt := generateSalt()
	insertUserQuery := `INSERT INTO users (email,salt,passhash,grade) VALUES ($1,$2,digest($3 || $4, 'sha512'),$5) RETURNING id`
	insertSubscriptionQuery := `INSERT INTO subscriptions2 user_id, VALUES $1`
	tx, err := db.Begin()
	checkErr(err)
	row := tx.QueryRow(insertUserQuery, email, salt, salt, passwd, grade)

	var userId int
	err = row.Scan(&userId)
	if err != nil {
		tx.Rollback()
		checkErr(err)
	}
	_, err = tx.Exec(insertSubscriptionQuery, userId)
	if err != nil {
		tx.Rollback()
		checkErr(err)
	}
	checkErr(tx.Commit())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func PostCancel(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/signup", http.StatusSeeOther)
}

func GetLogin(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	render(w, r, http.StatusOK, "login.html", nil)
}

func PostLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	passwd := r.FormValue("password")
	authenticate(w, r, email, passwd)
	if getCurrentUser(w, r) == nil {
		http.Error(w, "Failed to login.", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetLogout(w http.ResponseWriter, r *http.Request) {
	clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func GetIndex(w http.ResponseWriter, r *http.Request) {
	if getCurrentUser(w, r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	render(w, r, http.StatusOK, "main.html", struct{ User User }{*getCurrentUser(w, r)})
}

func GetUserJs(w http.ResponseWriter, r *http.Request) {
	if getCurrentUser(w, r) == nil {
		http.Error(w, "Failed to login.", http.StatusForbidden)
		return
	}
	grade := getCurrentUser(w, r).Grade
	switch grade {
	case "micro", "small":
		render(w, r, http.StatusOK, "user_small.js", nil)
	case "standard":
		render(w, r, http.StatusOK, "user_standard.js", nil)
	case "premium":
		render(w, r, http.StatusOK, "user_premium.js", nil)
	}
}

func GetModify(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	if user == nil {
		http.Error(w, "Failed to login.", http.StatusForbidden)
		return
	}
	// row := db.QueryRow(`SELECT arg FROM subscriptions WHERE user_id=$1`, user.ID)
	var arg string
	// err := row.Scan(&arg)
	// if err == sql.ErrNoRows {
	arg = "{}"
	// }
	render(w, r, http.StatusOK, "modify.html", struct {
		User User
		Arg  string
	}{*user, arg})
}

func PostModify(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	if user == nil {
		http.Error(w, "Failed to login.", http.StatusForbidden)
		return
	}

	service := r.FormValue("service")
	token := r.FormValue("token")
	keysStr := r.FormValue("keys")
	keys := []string{}
	if keysStr != "" {
		keys = regexp.MustCompile("\\s+").Split(keysStr, -1)
	}
	//paramName := r.FormValue("param_name")
	paramValue := r.FormValue("param_value")

	selectQuery := `SELECT ken, ken2, surname, givenname, tenki, FROM subscriptions2 WHERE user_id=$1 FOR UPDATE`
	updateQuery := `UPDATE subscriptions2 SET ken=$1, ken2=$2, surname=$3, givenname=$4, tenki=$5 WHERE user_id=$6`

	tx, err := db.Begin()
	checkErr(err)
	row := tx.QueryRow(selectQuery, user.ID)
	ken, ken2, surname, givenname, tenki := "", "", "", "", ""
	err = row.Scan(&ken, &ken2, &surname, &givenname, &tenki)
	if err == sql.ErrNoRows {
	} else if err != nil {
		tx.Rollback()
		checkErr(err)
	}

	switch service {
	case "ken":
		ken = keys[0]
	case "ken2":
		ken2 = paramValue
	case "surname":
		surname = paramValue
	case "givenname":
		givenname = paramValue
	case "tenki":
		tenki = token
	}

	_, err = tx.Exec(updateQuery, ken, ken2, surname, givenname, tenki, user.ID)
	checkErr(err)

	tx.Commit()

	http.Redirect(w, r, "/modify", http.StatusSeeOther)
}

func fetchApi(method, uri string, headers, params map[string]string, service string, key string) map[string]interface{} {

	client := &http.Client{}
	if strings.HasPrefix(uri, "https://") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client.Transport = tr
	}
	values := url.Values{}
	for k, v := range params {
		values.Add(k, v)
	}

	var req *http.Request
	var err error
	switch method {
	case "GET":
		req, err = http.NewRequest(method, uri, nil)
		checkErr(err)
		req.URL.RawQuery = values.Encode()
		break
	case "POST":
		req, err = http.NewRequest(method, uri, strings.NewReader(values.Encode()))
		checkErr(err)
		break
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}
	resp, err := client.Do(req)
	checkErr(err)

	defer resp.Body.Close()

	var data map[string]interface{}
	d := json.NewDecoder(resp.Body)
	d.UseNumber()
	checkErr(d.Decode(&data))

	if service != "tenki" || service != "perfectsec" || service != "perfectsec_attacked" {
		_, exist := apidata[service]
		if !exist {
			apidata[service] = make(map[string]map[string]interface{})
			apidata[service][key] = make(map[string]interface{})
			apidata[service][key] = data
		}

		_, exist = apidata[service][key]
		if !exist {
			apidata[service][key] = make(map[string]interface{})
			apidata[service][key] = data
		}
	}

	return data
}

func GetData(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(w, r)
	if user == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ken, ken2, surname, givenname, tenki, perfectsec_req, perfectsec_token, perfectsec_attacked := "", "", "", "", "", "", "", ""
	//var ken, ken2, surname, givenname, tenki, perfectsec_req, perfectsec_token, perfectsec_attacked string
	row := db.QueryRow(`SELECT ken, ken2, surname, givenname, tenki, perfectsec_req, perfectsec_token, perfectsec_attacked FROM subscriptions2 WHERE user_id=$1`, user.ID)
	checkErr(row.Scan(&ken, &ken2, &surname, &givenname, &tenki, &perfectsec_req, &perfectsec_token, &perfectsec_attacked))

	var usedServices = []string{}
	var services = []string{"ken", "ken2", "surname", "givenname", "tenki", "perfectsec", "perfectsec_attacked"}

	for _, eachService := range services {
		switch eachService {
		case "ken":
			if ken != "" {
				usedServices = append(usedServices, eachService)
			}
		case "ken2":
			if ken2 != "" {
				usedServices = append(usedServices, eachService)
			}
		case "surname":
			if surname != "" {
				usedServices = append(usedServices, eachService)
			}
		case "givenname":
			if givenname != "" {
				usedServices = append(usedServices, eachService)
			}
		case "tenki":
			if tenki != "" {
				usedServices = append(usedServices, eachService)
			}
		case "perfectsec":
			if perfectsec_token != "" {
				usedServices = append(usedServices, eachService)
			}
		case "perfectsec_attacked":
			if perfectsec_attacked != "" {
				usedServices = append(usedServices, eachService)
			}
		}
	}

	data := make([]Data, 0, len(usedServices))
	for _, service := range usedServices {

		// ken : keys
		// ken2: params zipcode
		// surname: params q
		// givenname: params q
		// tenki: token

		var serviceKey string
		var params = make(map[string]string)
		var token string

		switch service {
		case "ken":
			serviceKey = ken
		case "ken2":
			// serviceKey = params["zipcode"]
			serviceKey = ken2
			params["zipcode"] = ken2
		case "surname":
			//serviceKey = params["q"]
			serviceKey = surname
			params["q"] = surname
		case "givenname":
			//serviceKey = params["q"]
			serviceKey = givenname
			params["q"] = givenname
		case "tenki":
			//serviceKey = conf.Token
			serviceKey = tenki
			params["zipcode"] = tenki
		case "perfectsec":
			token = perfectsec_token
			params["req"] = perfectsec_req
		case "perfectsec_attacked":
			token = perfectsec_attacked
		}

		var flg = 0
		_, exist := apidata[service]

		if exist {
			_, exist = apidata[service][serviceKey]

			if exist {
				flg = 1
				serviceData, _ := apidata[service][serviceKey]
				data = append(data, Data{service, serviceData})
			}
		}

		if flg == 0 {
			method := endpoints[service]["method"]
			tokenType := endpoints[service]["tokenType"]
			tokenKey := endpoints[service]["tokenKey"]
			uriTemplate := endpoints[service]["uri"]

			headers := make(map[string]string)
			if params == nil {
				params = make(map[string]string)
			}

			if tokenType != "" && tokenKey != "" {
				switch tokenType {
				case "header":
					headers[tokenKey] = token
					// 	break
					// case "param":
					// 	params[tokenKey] = conf.Token
					// 	break
				}
			}

			var uri string
			if service != "ken" {
				uri = uriTemplate + ken
			} else {
				uri = uriTemplate
			}

			data = append(data, Data{service, fetchApi(method, uri, headers, params, service, serviceKey)})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(data)
	checkErr(err)
	w.Write(body)
}

func GetInitialize(w http.ResponseWriter, r *http.Request) {
	fname := "../sql/initialize_others.sql"
	fname2 := "../sql/initialize_subscription.sql"
	file, err := filepath.Abs(fname)
	checkErr(err)
	_, err = exec.Command("psql", "-f", file, "isucon5f").Output()
	checkErr(err)

	file2, err := filepath.Abs(fname2)
	checkErr(err)
	_, err = exec.Command("psql", "-f", file2, "isucon5f").Output()
	checkErr(err)

	resp2, err := http.Get("http://203.104.208.244/initalize")
	checkErr(err)
	defer resp2.Body.Close()
	time.Sleep(5)
}

func main() {
	cpuprofile := "isucon.prof"
	f, err := os.Create(cpuprofile)
	if err != nil {
		log.Fatal(err)
	}

	pprof.StartCPUProfile(f)

	defer pprof.StopCPUProfile()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			log.Printf("captured %v, stopping profiler and exiting...", sig)
			pprof.StopCPUProfile()
			os.Exit(1)
		}
	}()

	host := os.Getenv("ISUCON5_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUCON5_DB_PORT")
	if portstr == "" {
		portstr = "5432"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCON5_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCON5_DB_USER")
	if user == "" {
		user = "isucon"
	}
	password := os.Getenv("ISUCON5_DB_PASSWORD")
	dbname := os.Getenv("ISUCON5_DB_NAME")
	if dbname == "" {
		dbname = "isucon5f"
	}
	ssecret := os.Getenv("ISUCON5_SESSION_SECRET")
	if ssecret == "" {
		ssecret = "tonymoris"
	}

	db, err = sql.Open("postgres", "host="+host+" port="+strconv.Itoa(port)+" user="+user+" dbname="+dbname+" sslmode=disable password="+password)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	apidata = make(map[string]map[string]map[string]interface{})

	// ken                 | GET  |            |                          | http://api.five-final.isucon.net:8080/%s
	// ken2                | GET  |            |                          | http://api.five-final.isucon.net:8080/
	// surname             | GET  |            |                          | http://api.five-final.isucon.net:8081/surname
	// givenname           | GET  |            |                          | http://api.five-final.isucon.net:8081/givenname
	// tenki               | GET  | param      | zipcode                  | http://api.five-final.isucon.net:8988/
	// perfectsec          | GET  | header     | X-PERFECT-SECURITY-TOKEN | https://api.five-final.isucon.net:8443/tokens
	// perfectsec_attacked | GET  | header     | X-PERFECT-SECURITY-TOKEN | https://api.five-final.isucon.net:8443/attacked_list
	endpoints = make(map[string]map[string]string)

	endpoints["ken"] = make(map[string]string)
	endpoints["ken"]["method"] = "GET"
	endpoints["ken"]["tokenType"] = ""
	endpoints["ken"]["tokenKey"] = ""
	endpoints["ken"]["uri"] = "http://api.five-final.isucon.net:8080/"

	endpoints["ken2"] = make(map[string]string)
	endpoints["ken2"]["method"] = "GET"
	endpoints["ken2"]["tokenType"] = ""
	endpoints["ken2"]["tokenKey"] = ""
	endpoints["ken2"]["uri"] = "http://api.five-final.isucon.net:8080/"

	endpoints["surname"] = make(map[string]string)
	endpoints["surname"]["method"] = "GET"
	endpoints["surname"]["tokenType"] = ""
	endpoints["surname"]["tokenKey"] = ""
	endpoints["surname"]["uri"] = "http://api.five-final.isucon.net:8081/surname"

	endpoints["givenname"] = make(map[string]string)
	endpoints["givenname"]["method"] = "GET"
	endpoints["givenname"]["tokenType"] = ""
	endpoints["givenname"]["tokenKey"] = ""
	endpoints["givenname"]["uri"] = "http://api.five-final.isucon.net:8081/givenname"

	endpoints["tenki"] = make(map[string]string)
	endpoints["tenki"]["method"] = "GET"
	endpoints["tenki"]["tokenType"] = "param"
	endpoints["tenki"]["tokenKey"] = "zipcode"
	endpoints["tenki"]["uri"] = "http://api.five-final.isucon.net:8988/"

	endpoints["perfectsec"] = make(map[string]string)
	endpoints["perfectsec"]["method"] = "GET"
	endpoints["perfectsec"]["tokenType"] = "header"
	endpoints["perfectsec"]["tokenKey"] = "X-PERFECT-SECURITY-TOKEN"
	endpoints["perfectsec"]["uri"] = "https://api.five-final.isucon.net:8443/tokens"

	endpoints["perfectsec_attacked"] = make(map[string]string)
	endpoints["perfectsec_attacked"]["method"] = "GET"
	endpoints["perfectsec_attacked"]["tokenType"] = "header"
	endpoints["perfectsec_attacked"]["tokenKey"] = "X-PERFECT-SECURITY-TOKEN"
	endpoints["perfectsec_attacked"]["uri"] = "https://api.five-final.isucon.net:8443/attacked_list"

	store = sessions.NewCookieStore([]byte(ssecret))

	r := mux.NewRouter()

	s := r.Path("/signup").Subrouter()
	s.Methods("GET").HandlerFunc(GetSignUp)
	s.Methods("POST").HandlerFunc(PostSignUp)

	l := r.Path("/login").Subrouter()
	l.Methods("GET").HandlerFunc(GetLogin)
	l.Methods("POST").HandlerFunc(PostLogin)

	r.HandleFunc("/logout", GetLogout).Methods("GET")

	m := r.Path("/modify").Subrouter()
	m.Methods("GET").HandlerFunc(GetModify)
	m.Methods("POST").HandlerFunc(PostModify)

	r.HandleFunc("/data", GetData).Methods("GET")

	r.HandleFunc("/cancel", PostCancel).Methods("POST")

	r.HandleFunc("/user.js", GetUserJs).Methods("GET")

	r.HandleFunc("/initialize", GetInitialize).Methods("GET")

	r.HandleFunc("/", GetIndex)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("../static")))

	sock := "/dev/shm/app.sock"
	os.Remove(sock)
	ll, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Println("%s\n", err)
		return
	}
	os.Chmod(sock, 0777)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func(c chan os.Signal) {
		sig := <-c
		log.Printf("Caught signal %s: shutting down", sig)
		ll.Close()
		os.Exit(0)
	}(sigc)

	err = http.Serve(ll, r)
	if err != nil {
		panic(err)
	}
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
