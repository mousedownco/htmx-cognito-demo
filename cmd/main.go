package main

import (
	"embed"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/gorillamux"
	"github.com/gorilla/mux"
	"github.com/mousedownco/htmx-cognito-demo/auth"
	"github.com/mousedownco/htmx-cognito-demo/contacts"
	"github.com/mousedownco/htmx-cognito-demo/protected"
	"github.com/mousedownco/htmx-cognito-demo/views"
	"log"
	"net/http"
	"os"
)

//go:embed static
var staticDir embed.FS

var port = ":8080"

func main() {
	cs := contacts.NewService()

	cog := auth.NewCognito(
		os.Getenv("COGNITO_ENDPOINT"),
		os.Getenv("COGNITO_CLIENT_ID"),
		os.Getenv("COGNITO_REDIRECT_URI"))

	r := mux.NewRouter()

	r.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticDir)))
	r.Handle("/",
		http.RedirectHandler("/contacts", http.StatusTemporaryRedirect))

	r.Handle("/app-config.js",
		auth.HandleAppConfig(
			os.Getenv("COGNITO_POOL_ID"),
			os.Getenv("COGNITO_CLIENT_ID"),
			views.NewView("partial", "auth/app-config.gohtml"))).
		Methods("GET")

	ar := r.PathPrefix("/auth").Subrouter()

	ar.Handle("/sign-up", auth.HandleSignUp(views.NewView("layout", "auth/sign-up.gohtml"))).Methods("GET")
	ar.Handle("/sign-up-confirm", auth.HandleSignUpConfirm(views.NewView("layout", "auth/sign-up-confirm.gohtml"))).Methods("GET")
	ar.Handle("/sign-in", auth.HandleSignIn(views.NewView("layout", "auth/sign-in.gohtml"))).Methods("GET")
	ar.Handle("/code", auth.HandleCognitoCallback(cog, "/contacts")).Methods("GET")

	pr := r.PathPrefix("/protected").Subrouter()
	pr.Handle("", auth.HandleAuth(protected.HandleIndex(views.NewView("layout", "protected/index.gohtml")))).Methods("GET")

	cr := r.PathPrefix("/contacts").Subrouter()
	cr.Handle("", contacts.HandleIndex(cs, views.NewView("partial", "contacts/rows.gohtml"))).Headers("HX-Trigger", "search")

	// This handler differs from the book's implementation, see README for details
	cr.Handle("/delete",
		contacts.HandleDeleteSelected(cs,
			views.NewView("layout", "contacts/index.gohtml", "contacts/rows.gohtml"))).Methods("POST")
	cr.Handle("", contacts.HandleIndex(cs,
		views.NewView("layout", "contacts/index.gohtml", "contacts/rows.gohtml")))
	cr.Handle("/count", contacts.HandleCountGet(cs)).Methods("GET")
	cr.Handle("/new",
		contacts.HandleNew(views.NewView("layout", "contacts/new.gohtml"))).
		Methods("GET")
	cr.Handle("/new",
		contacts.HandleNewPost(cs, views.NewView("layout", "contacts/new.gohtml"))).Methods("POST")
	cr.Handle("/{id:[0-9]+}",
		contacts.HandleView(cs, views.NewView("layout", "contacts/show.gohtml"))).Methods("GET")
	cr.Handle("/{id:[0-9]+}/edit",
		contacts.HandleEdit(cs, views.NewView("layout", "contacts/edit.gohtml"))).Methods("GET")
	cr.Handle("/{id:[0-9]+}/edit",
		contacts.HandleEditPost(cs, views.NewView("layout", "contacts/edit.gohtml"))).Methods("POST")
	cr.Handle("/{id:[0-9]+}/email", contacts.HandleEmailGet(cs)).Methods("GET")
	cr.Handle("/{id:[0-9]+}",
		contacts.HandleDelete(cs, views.NewView("layout", "contacts/edit.gohtml"))).Methods("DELETE")

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
