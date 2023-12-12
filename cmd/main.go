package main

import (
	"embed"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/gorillamux"
	"github.com/gorilla/mux"
	"github.com/mousedownco/htmx-cognito-demo/auth"
	"github.com/mousedownco/htmx-cognito-demo/profile"
	"github.com/mousedownco/htmx-cognito-demo/views"
	"log"
	"net/http"
	"os"
)

//go:embed static
var staticDir embed.FS

var port = ":8080"

func main() {
	cog := auth.NewCognito(
		os.Getenv("COGNITO_ENDPOINT"),
		os.Getenv("COGNITO_CLIENT_ID"),
		os.Getenv("COGNITO_REDIRECT_URI"))

	r := mux.NewRouter()

	r.Handle("/", views.ViewHandler(
		views.NewView("layout", "home.gohtml")))
	r.Handle("/app-config.js",
		auth.HandleAppConfig(
			os.Getenv("COGNITO_POOL_ID"),
			os.Getenv("COGNITO_CLIENT_ID"),
			views.NewView("partial", "auth/app-config.gohtml"))).
		Methods("GET")
	r.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticDir)))

	ar := r.PathPrefix("/auth").Subrouter()
	ar.Handle("/sign-up", auth.HandleSignUp(
		views.NewView("layout", "auth/sign-up.gohtml"))).Methods("GET")
	ar.Handle("/sign-up-confirm", auth.HandleSignUpConfirm(
		views.NewView("layout", "auth/sign-up-confirm.gohtml"))).Methods("GET")
	ar.Handle("/sign-in", auth.HandleSignIn(
		views.NewView("layout", "auth/sign-in.gohtml"))).Methods("GET")
	ar.Handle("/code", auth.HandleCognitoCallback(cog, "/contacts")).Methods("GET")
	ar.Handle("/profile", auth.HandleProfile(
		views.NewView("partial", "auth/nav-sign-in.gohtml"),
		views.NewView("partial", "auth/nav-profile.gohtml"))).Methods("GET")

	pr := r.PathPrefix("/profile").Subrouter()
	pr.Handle("", auth.HandleAuth(profile.HandleIndex(views.NewView("layout", "profile/index.gohtml")))).Methods("GET")

	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		log.Printf("Running Lambda function %s", os.Getenv("AWS_LAMBDA_FUNCTION_NAME"))
		muxLambda := gorillamux.New(r)
		lambda.Start(muxLambda.Proxy)
	} else {
		log.Printf("Starting server on port %s", port)
		http.Handle("/", r)
		_ = http.ListenAndServe(port, nil)
	}
}
