public class A {
  public void q(Connection c, String id) throws Exception {
    Statement s = c.createStatement();
    s.executeQuery("SELECT * FROM t WHERE id = " + id);
  }
}
