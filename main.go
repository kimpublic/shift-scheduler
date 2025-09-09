package main

import (
	"html/template"
	"log"
	"net/http"
)

var tmpl = template.Must(template.ParseGlob("templates/*.html"))

func indexHandler(w http.ResponseWriter, r *http.Request) {

	tmpl.ExecuteTemplate(w, "base.html", nil)
}

func main() {
	http.HandleFunc("/", indexHandler)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Println("Server starting on :8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}

}
