function login(db, req) {
  return db.collection('users').find({
    username: req.body.username,
    password: { $ne: null }
  });
}
