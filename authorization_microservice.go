package authorization_microservice

import (
  "os"
  "fmt"
  "time"
  "errors"
  "strings"
  "net/http"
  "io/ioutil"
  "encoding/json"
  "github.com/dgrijalva/jwt-go"
  "github.com/julienschmidt/httprouter"
)

/* Accsess values. */
type AccessUserJson struct {
  Username   string `json:"name"`
  Password   string `json:"password"`
  Name       string `json:"claims_name"`
  Secret     string `json:"secret"`
}

/* Error struct. */
type Exception struct {
  Message string `json:"message"`
}

func LoadAccessUser(AccessUserPatch string) (username, password, name, secret string, err error) {
  file, err1 := ioutil.ReadFile(AccessUserPatch)
  if err1 != nil {
    fmt.Printf("File error: %v\n", err1)
    os.Exit(1)
  }
  data := AccessUserJson{}
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

func BasicAuth(AccessUserPatch string) httprouter.Handle {
  username, pass, name, secret, err := LoadAccessUser(AccessUserPatch);
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
      m := make(map[string]interface{})
      m["token"] = tokenString
      result, err := json.Marshal(m)
      if err != nil {
        json.NewEncoder(w).Encode(Exception{Message: err.Error()})
        return
      }
      w.Write([]byte(string(result)))
    } else {
      // Request Basic Authentication otherwise.
      w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
      http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
    }
  }
}

func ProtectedEndpoint (h httprouter.Handle, AccessUserPatch string) httprouter.Handle {
  _, _, _, secret, err := LoadAccessUser(AccessUserPatch);
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
          json.NewEncoder(w).Encode(Exception{Message: error.Error()})
          return
        }
        if token.Valid {
          // Credentials corect. Start callback.
          h(w, req, ps)
        } else {
          json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
        }
      }
    } else {
      json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
    }
  }
}