function find(db, id) {
  return db.query('SELECT * FROM t WHERE id = $1', [id]);
}
