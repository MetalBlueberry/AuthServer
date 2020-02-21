package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// Create the JWT key used to create the signature
var jwtKey = []byte("my_secret_key")

type UserData struct {
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	AccessLevel int    `json:"access_level,omitempty"`
}

type Claims struct {
	User *UserData `json:"user"`
	jwt.StandardClaims
}

var basePath string

func main() {
	flag.StringVar(&basePath, "base-path", "/", "indicates the base path where the app is running")
	flag.Parse()

	r := mux.NewRouter().
		PathPrefix(basePath).
		Subrouter()
	r.Path("/auth").Methods("GET").HandlerFunc(authHandler)
	r.Path("/login").Methods("POST").HandlerFunc(loginPOSTHandler)
	r.Path("/logout").Methods("POST").HandlerFunc(logoutPOSTHandler)
	r.PathPrefix("/").Methods("GET").HandlerFunc(loginGETHandler)

	http.Handle("/", r)

	log.Println("ready")
	http.ListenAndServe(":8080", nil)
}

func loginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	user := loginUser(username, password)
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
	})

	http.Redirect(w, r, basePath, http.StatusFound)
}

func loginGETHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var templateName string
	if claims == nil {
		templateName = "login.tmpl"
	} else {
		templateName = "logout.tmpl"
	}

	pages := template.Must(template.ParseGlob("templates/*.tmpl"))
	pages.ExecuteTemplate(w, templateName, claims)
}

func loginUser(username string, password string) *UserData {
	// TODO: Now any user can login, implement proper validation
	return &UserData{
		Name: username,
	}
}

func logoutPOSTHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, basePath, http.StatusFound)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := getSession(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.Encode(claims.User)
}

func getSession(r *http.Request) (*Claims, error) {
	c, err := r.Cookie("token")
	switch {
	case err == http.ErrNoCookie:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("Could not get token cookie. cause %w", err)
	}

	tokenString := c.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	switch {
	case err == jwt.ErrSignatureInvalid:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("Could not parse jwt, cause %w", err)
	case !tkn.Valid:
		return nil, nil
	}

	return claims, nil
}
