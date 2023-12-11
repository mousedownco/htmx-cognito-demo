package protected

import (
	"github.com/mousedownco/htmx-cognito-demo/auth"
	"github.com/mousedownco/htmx-cognito-demo/views"
	"net/http"
)

func HandleIndex(view *views.View) auth.UserHandlerFunc {
	return func(writer http.ResponseWriter, r *http.Request, u auth.User) {
		view.Render(writer, r, map[string]interface{}{"User": u})
	}
}
