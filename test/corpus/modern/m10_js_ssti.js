const ejs = require('ejs');

function render(req, res) {
  const tpl = req.query.tpl;
  res.send(ejs.render(tpl, { user: 'a' }));
}
