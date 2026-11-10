function scan(text, re) {
  const m = re.exec(text);
  return m ? m[0] : null;
}
