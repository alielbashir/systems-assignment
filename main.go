package main

// TODO: write verify, readme, and stats endpoints

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
)

const (
	publicKeyPath  = "public.pem"
	privateKeyPath = "private.pem"
	tokenTimeLimit = 5 * time.Second // lifetime of jwt after issuance
)

func getIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello")
}

func getToken(w http.ResponseWriter, r *http.Request) {
	var err error

	serverError := func() {
		// Server error details not returned to client to hide implementation. only logged
		fmt.Print(err)
		w.WriteHeader(500)
		w.Write([]byte("An error occured. If this persists please contact us at support@example.com"))
	}

	publicKeyString, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		serverError()
		return
	}

	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		serverError()
		return
	}

	username := chi.URLParam(r, "username")

	expiryTime := time.Now().Add(tokenTimeLimit)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiryTime),
		Subject:   username,
	})

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		serverError()
		return
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		serverError()
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		HttpOnly: true, // to prevent cross-site scripting
		Expires:  expiryTime,
		Path:     "/",
	})

	w.Write(publicKeyString)
}

func verifyToken(w http.ResponseWriter, r *http.Request) {

	var err error

	handleError := func(statusCode int, message string) {
		switch {
		case 500 <= statusCode:
			// Server error
			fmt.Print(err)
			w.WriteHeader(statusCode)
			w.Write([]byte("An error has occured. If this persists please contact us at support@example.com"))
		default:
			// All other errors
			fmt.Print(err)
			w.WriteHeader(statusCode)
			w.Write([]byte(message))
		}
	}

	tokenString, err := r.Cookie("token")

	if err != nil {
		handleError(400, "No token cookie received. The cookie may be expired. Please obtain a new JWT from /auth/:username\n")
		return
	}

	publicKeyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		handleError(500, "")
		return
	}

	fmt.Print("token = ", tokenString.Value, "\n")
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		handleError(500, "")
		return
	}

	token, err := jwt.Parse(tokenString.Value, func(token *jwt.Token) (interface{}, error) {

		return publicKey, err
	})

	if err != nil {
		handleError(400, err.Error())
		return
	}

	// if okay, verify
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username := fmt.Sprintf("%v", claims["sub"])
		w.WriteHeader(200)
		w.Write([]byte(username))
		return
	} else {
		handleError(400, "Token invalid. Please obtain a new JWT cookie from /auth/:username\n")
		return
	}

}

func main() {
	// Create router
	r := chi.NewRouter()

	r.Get("/", getIndex)

	// GET /auth/:username
	r.Get("/auth/{username}", getToken)

	// GET /verify
	r.Get("/verify", verifyToken)

	// GET /README.txt

	// GET /stats

	log.Fatal(http.ListenAndServe(":8001", r))

}
