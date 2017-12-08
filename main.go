package main

import (
  "os"
  "fmt"
  "log"
  "time"
  "errors"
  "strings"
  "net/http"
  "io/ioutil"
  "encoding/json"
  "github.com/dgrijalva/jwt-go"
  "github.com/julienschmidt/httprouter"
)

func main() {
  router := httprouter.New()
  router.POST("/authorization-microservice", basicAuth())
  log.Fatal(http.ListenAndServe(authorizationMicroservicePort, router))
}

const accessUserPatch, authorizationMicroservicePort string = "./data.json", ":2379"

/* Accsess values. */
type accessUserJson struct {
  Username   string `json:"name"`
  Password   string `json:"password"`
  Name       string `json:"claims_name"`
  Secret     string `json:"secret"`
}

/* Error struct. */
type exception struct {
  Message string `json:"message"`
}

func loadAccessUser() (username, password, name, secret string, err error) {
  file, err1 := ioutil.ReadFile(accessUserPatch)
  if err1 != nil {
    fmt.Printf("File error: %v\n", err1)
    os.Exit(1)
  }
  data := accessUserJson{}
  err2 := json.Unmarshal(file, &data)
  if err2 != nil {
    fmt.Println("error:", err2)
    os.Exit(2)
  }
  if data.Username == "" {
    return username, password, name, secret, errors.New("No username!")
  }
  if data.Password == "" {
    return username, password, name, secret, errors.New("No password!")
  }
  if data.Name == "" {
    return username, password, name, secret, errors.New("No claims_name!")
  }
  if data.Secret == "" {
    return username, password, name, secret, errors.New("No secret!")
  }
  return data.Username, data.Password, data.Name, data.Secret, err
}

func basicAuth() httprouter.Handle {
  username, pass, name, secret, err := loadAccessUser();
  if err != nil {
    fmt.Println("error:", err)
    os.Exit(3)
  }
  return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    user, password, hasAuth := r.BasicAuth()
    if hasAuth != true {
      http.Error(w, "Error: Malformed credentials. HTTP Basic-Auth required.", http.StatusBadRequest)
      return
    }
    // Get the Basic Authentication credentials.
    if user == username && password == pass {
      // Create the token
      token := jwt.New(jwt.SigningMethodHS256)
      // Create a map to store our claims.
      claims := token.Claims.(jwt.MapClaims)
      // Set token claims.
      claims["admin"] = true
      claims["name"] = name
      claims["exp"] = time.Now().Add(time.Hour).Unix()
      // Sign the token with our secret
      tokenString, _ := token.SignedString([]byte(secret))
      // Finally, write the token to the browser window.
      w.Write([]byte(tokenString))
    } else {
      // Request Basic Authentication otherwise.
      w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
      http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
    }
  }
}

func protectedEndpoint (h httprouter.Handle) httprouter.Handle {
  _, _, _, secret, err := loadAccessUser();
  if err != nil {
    fmt.Println("error:", err)
    os.Exit(3)
  }
  return func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
    authorizationHeader := req.Header.Get("authorization")
    if authorizationHeader != "" {
      bearerToken := strings.Split(authorizationHeader, " ")
      if len(bearerToken) == 2 {
        token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
          if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("There was an error")
          }
          return []byte(secret), nil
        })
        if error != nil {
          json.NewEncoder(w).Encode(exception{Message: error.Error()})
          return
        }
        if token.Valid {
          // Credentials corect. Start callback.
          h(w, req, ps)
        } else {
          json.NewEncoder(w).Encode(exception{Message: "Invalid authorization token"})
        }
      }
    } else {
      json.NewEncoder(w).Encode(exception{Message: "An authorization header is required"})
    }
  }
}