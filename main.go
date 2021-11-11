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
	tokenTimeLimit = 24 * time.Hour // lifetime of jwt after issuance
)

var (
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	publicKeyBytes []byte
	readmeBytes    []byte
	stats          = map[string]*Statistic{}
)

type Statistic struct {
	// holds a user's verify and auth attempts and averages
	averageEncodeMicroseconds float64
	averageDecodeMicroseconds float64
	authVisits        int
	verifyVisits      int
}

func approxRollingAverage(avg float64, newTime int64, n int) (newAvg float64) {
	// Adapted from https://stackoverflow.com/a/16757630/13886854
	if avg == 0 {
		// handle case of first average
		avg = float64(newTime)
		return avg
	}
	avg -= avg / float64(n)
	avg += float64(newTime) / float64(n)
	return avg
}

func recordAuthVisit(username string, startTime time.Time) {
	elapsed := time.Since(startTime)

	_, exists := stats[username]

	if exists {
		stats[username].authVisits++

		oldAverage := stats[username].averageEncodeMicroseconds
		visits := stats[username].authVisits
		stats[username].averageEncodeMicroseconds = approxRollingAverage(oldAverage, elapsed.Microseconds(), visits)

	} else {
		stats[username] = &Statistic{
			averageEncodeMicroseconds: float64(elapsed.Microseconds()),
			averageDecodeMicroseconds: 0,
			authVisits:        1,
			verifyVisits:      0,
		}
	}
	fmt.Printf("/auth endpoint visited by %v\n", username)
	fmt.Printf("%+v\n", *stats[username])
	fmt.Print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n")
}

func recordVerifyVisit(username string, startTime time.Time) {
	elapsed := time.Since(startTime)

	_, exists := stats[username]

	if exists {
		stats[username].verifyVisits++

		oldAverage := stats[username].averageDecodeMicroseconds
		visits := stats[username].verifyVisits
		stats[username].averageDecodeMicroseconds = approxRollingAverage(oldAverage, elapsed.Microseconds(), visits)

	} else {
		stats[username] = &Statistic{
			averageEncodeMicroseconds: 0,
			averageDecodeMicroseconds: float64(elapsed.Microseconds()),
			authVisits:        0,
			verifyVisits:      1,
		}
	}
	fmt.Printf("/verify endpoint visited by %v\n", username)
	fmt.Printf("%+v\n", *stats[username])
	fmt.Print("----------------------------------------------------------------------------------------\n\n")
}

func getToken(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var err error

	serverError := func() {
		// Server error details not returned to client to hide implementation. only logged
		fmt.Print(err, "\n")
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

	recordAuthVisit(username, start)

	w.Write(publicKeyBytes)
}

func verifyToken(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var err error

	handleError := func(statusCode int, message string) {
		fmt.Print(err, "\n")
		w.WriteHeader(statusCode)
		w.Write([]byte(message))
	}

	tokenCookie, err := r.Cookie("token")

	if err != nil {
		handleError(400, "No token cookie received. The cookie may be expired. Please obtain a new JWT from /auth/:username\n")
		return
	}

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

	recordVerifyVisit(username, start)
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
