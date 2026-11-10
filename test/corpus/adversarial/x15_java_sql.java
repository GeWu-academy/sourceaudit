import java.sql.*;
public class U {
  public ResultSet q(Connection c, String id) throws Exception {
    Statement s = c.createStatement();
    return s.executeQuery("SELECT * FROM u WHERE id=" + id);
  }
}
