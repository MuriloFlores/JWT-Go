package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const JWT_SIGNING_KEY = "chaveDeverasSecreta"

// Struct que ira representar os dados enviados pelo cliente
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

func GenerateJwtToken(user string) (string, error) {
	now := time.Now()
	expires := now.Add(time.Minute * 15).Unix()

	claims := jwt.MapClaims{
		"sub":     user,
		"expires": expires,
	}

	//gerando o token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//assinando token
	return token.SignedString([]byte(JWT_SIGNING_KEY))
}

func ValidateToken(tokenStr string) (jwt.MapClaims, error) {
	//fazer um split do token
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Invalid token")
		}

		return []byte(JWT_SIGNING_KEY), nil
	})

	if err != nil {
		return nil, fmt.Errorf("Invalid token")
	}

	//checando se o token é valido
	if !token.Valid {
		return nil, fmt.Errorf("Invalid token")
	}

	//Pegando as Claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Invalid token")
	}

	//checando o tempo de expiração
	expValue := claims["expires"].(float64)
	expires := int64(expValue)
	if time.Now().Unix() > expires {
		return nil, fmt.Errorf("token")
	}
	return claims, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	//Criando a variavel "LoginParams" para receber as informações que serão enviadas via json para a API
	var LoginParams LoginRequest

	//Recebendo as informações vindas do cliente e decodificando os campos do JSON correspondente para a variavel loginParams
	err := json.NewDecoder(r.Body).Decode(&LoginParams)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
	}

	//Aqui seria onde entraria uma pesquisa no banco de dados por um usuario com as credencias correspondentes
	if LoginParams.Username == "Murilo" && LoginParams.Password == "1234" {
		//gerando o token
		token, err := GenerateJwtToken("Murilo")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		//Atribuindo o valor do token a uma resposta para o client
		response := LoginResponse{
			Token: token,
		}

		//Retornando o Json com o token para o cliente
		err = json.NewEncoder(w).Encode(&response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		return
	}

	//Caso os paramentros não sejam compativeis com a validação anterior retorna para o usuario um erro de credencial
	http.Error(w, "Invalid Credentials", http.StatusBadRequest)
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Api-Token")
		if len(token) == 0 {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		//validando o token
		claims, err := ValidateToken(token)
		if err != nil {
			http.Error(w, "not authorized", http.StatusUnauthorized)
			return
		}
		fmt.Println(claims)
		next.ServeHTTP(w, r)
	}
}

func SecureHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Your are authenticated"))
}

func PublicHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("everyone can view this endpoint"))
}

func main() {
	http.HandleFunc("/api/auth", LoginHandler)
	http.HandleFunc("/api/public", PublicHandler)
	http.HandleFunc("/api/secure", AuthMiddleware(SecureHandler))
	http.ListenAndServe(":3000", nil)
}
