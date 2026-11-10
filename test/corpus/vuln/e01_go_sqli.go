package main
func q(db *sql.DB, id string) {
	db.Query("SELECT * FROM t WHERE id = " + id)
}
