public class A {
  public void q(Connection c, String id) throws Exception {
    PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");
    p.setString(1, id);
    p.executeQuery();
  }
}
