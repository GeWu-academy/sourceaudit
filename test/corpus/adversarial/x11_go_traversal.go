package main
import ("net/http";"os";"path/filepath")
func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	p := filepath.Join("/srv/files", name)
	b, _ := os.ReadFile(p)
	w.Write(b)
}
