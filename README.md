# Authorization with basic authorization and token for microservice.
A simple authentication system implemented using jwt-go.
For building paths, we use a lightweight high-performance HTTP request router.
To start using "authorization_microservice" you need:
* Install and configure the latest version of Golang
* Be sure to copy data.json and modify the data. Add access rights to the data.json to more complex.
* Move the data.json file to a secure location on the server. Provide the necessary access rights.
* To use authentication in your microservices, add in import - "github.com/pifagor87/authorization_microservice".
When constructing your own microservice, use them in the following way, for example:

router := httprouter.New()

router.POST("my_url", authorization_microservice.BasicAuth(patch_to_data_json))

router.POST("my_url", authorization_microservice.ProtectedEndpoint(my_callback, patch_to_data_json))

Change the correct path to the file data.json. Replace "patch_to_data_json" with the desired path to the file.

## Dependencies
* github.com/dgrijalva/jwt-go
* github.com/julienschmidt/httprouter