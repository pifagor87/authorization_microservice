# Authorization with basic authorization and token for microservice.
A simple authentication system implemented using jwt-go.
For building paths, we use a lightweight high-performance HTTP request router.
To start using "authorization_microservice" you need:
* Install and configure the latest version of Golang
* Be sure to modify the data access data in the data.json to more complex.
* Move the data.json file to a secure location on the server. Provide the necessary access rights.
In file main.go, specify the correct path to the file data.json. Replace "./data.json" with the desired path to the file.
* To use authentication in your microservices, add in import - "github.com/pifagor87/authorization_microservice".
When constructing your own microservice, use them in the following way, for example:
  router := httprouter.New()
  router.POST('my_url', protectedEndpoint (my_callback)).

## Dependencies
* github.com/dgrijalva/jwt-go
* github.com/julienschmidt/httprouter