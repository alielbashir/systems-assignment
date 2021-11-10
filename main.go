package main

// TODO: write verify, readme, and stats endpoints

import (
	"crypto/rsa"
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
	readMePath     = "README.txt"
	tokenTimeLimit = 5 * time.Second // lifetime of jwt after issuance
)

var (
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	publicKeyBytes []byte
	readmeBytes []byte
	stats       = map[string]*Statistic{}
)

type Statistic struct {
	// holds a user's verify and auth attempts
	authVisits   int
	verifyVisits int
}

func getIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello")
}

func recordAuthVisit(username string) {
	_, exists := stats[username]

	if exists {
		stats[username].authVisits++
	} else {
		stats[username] = &Statistic{
			authVisits:   1,
			verifyVisits: 0,
		}
	}
	fmt.Println(username, *stats[username])
}

func recordVerifyVisit(username string) {
	_, exists := stats[username]

	if exists {
		stats[username].verifyVisits++
	} else {
		stats[username] = &Statistic{
			authVisits:   0,
			verifyVisits: 1,
		}
	}
	fmt.Println(username, *stats[username])
}

func getToken(w http.ResponseWriter, r *http.Request) {
	var err error

	serverError := func() {
		// Server error details not returned to client to hide implementation. only logged
		fmt.Print(err)
		w.WriteHeader(500)
		w.Write([]byte("An error occured. If this persists please contact us at support@example.com"))
	}

	username := chi.URLParam(r, "username")

	expiryTime := time.Now().Add(tokenTimeLimit)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiryTime),
		Subject:   username,
	})

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

	recordAuthVisit(username)

	w.Write(publicKeyBytes)
}

func verifyToken(w http.ResponseWriter, r *http.Request) {
	var err error

	handleError := func(statusCode int, message string) {
		fmt.Print(err)
		w.WriteHeader(statusCode)
		w.Write([]byte(message))
	}

	tokenCookie, err := r.Cookie("token")

	if err != nil {
		handleError(400, "No token cookie received. The cookie may be expired. Please obtain a new JWT from /auth/:username\n")
		return
	}

	fmt.Print("token = ", tokenCookie.Value, "\n")

	token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {

		return publicKey, err
	})

	if err != nil {
		handleError(400, err.Error())
		return
	}

	// if okay, verify
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok || !token.Valid {
		handleError(400, "Token invalid. Please obtain a new JWT cookie from /auth/:username\n")
		return
	}

	username := fmt.Sprintf("%v", claims["sub"])

	recordVerifyVisit(username)
	w.Write([]byte(username))
}

func getREADME(w http.ResponseWriter, r *http.Request) {
	w.Write(readmeBytes)
}

func getStats(w http.ResponseWriter, r *http.Request) {
	//
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func setupKeys() {
	var err error
	
	publicKeyBytes, err = ioutil.ReadFile(publicKeyPath)
	fatal(err)

	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	fatal(err)

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	fatal(err)

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	fatal(err)
}

func setupReadMe() {
	var err error
	readmeBytes, err = ioutil.ReadFile(readMePath)
	fatal(err)
}

func init() {
	setupKeys()
	setupReadMe()
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
	r.Get("/README.txt", getREADME)

	// GET /stats
	r.Get("/stats", getStats)

	log.Fatal(http.ListenAndServe(":8001", r))

}
