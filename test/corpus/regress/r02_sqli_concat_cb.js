function find(db, id) {
  return db.query("SELECT * FROM t WHERE id = " + id, function (e, r) { return r; });
}
