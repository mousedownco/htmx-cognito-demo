package auth

import (
	"github.com/mousedownco/htmx-cognito-demo/views"
	"net/http"
)

type UserHandlerFunc func(http.ResponseWriter, *http.Request, User)

func HandleAuth(h UserHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: Extract User Information from JWT
		jwt, e := DecodeJwtPayload(r.Header.Get("Authorization"))
		if e != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		user := JwtUser(jwt)
		h(w, r, user)
	})
}

func HandleAppConfig(userPoolId, clientId string, view *views.View) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		view.Render(w, r, map[string]interface{}{
			"UserPoolId": userPoolId,
			"ClientId":   clientId,
		})
	}
}

func HandleSignUp(view *views.View) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view.Render(w, r, nil)
	}
}

func HandleSignUpConfirm(view *views.View) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		sub := r.URL.Query().Get("sub")
		view.Render(w, r, map[string]interface{}{
			"Sub": sub,
		})
	}
}

func HandleSignIn(view *views.View) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		view.Render(w, r, nil)
	}
}
