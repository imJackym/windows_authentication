import com.microsoft.sqlserver.jdbc.SQLServerDataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class scode_window_authentication_NTLM {
  public static void main(String[] args) {
    // Set up the NTLM authentication properties
    String serverName = "BEA-LAB.COM";
    String databaseName = "BEA_IVR";
    String authenticationScheme = "NTLM";
    int port = 1433;
    String domain = "BEA-LAB.COM";
    String user = "administrator";
    String password = "Admin_1018";
    boolean integratedSecurity = true;
    boolean trustServerCertificate = true;

    try {
      // Create a SQLServerDataSource object
      SQLServerDataSource ds = new SQLServerDataSource();
      ds.setServerName(serverName);
      ds.setPortNumber(port);
      ds.setDatabaseName(databaseName);
      ds.setTrustServerCertificate(trustServerCertificate);
      ds.setIntegratedSecurity(integratedSecurity);
      ds.setAuthenticationScheme(authenticationScheme);
      ds.setDomain(domain);
      ds.setUser(user);
      ds.setPassword(password);

      // Establish the connection
      Connection conn = ds.getConnection();

      // Create and execute a SQL statement
      Statement statement = conn.createStatement();
      String sql = "SELECT * FROM IVR_Action";
      ResultSet resultSet = statement.executeQuery(sql);

      // Process the result set
      while (resultSet.next()) {
        int id = resultSet.getInt("ID");
        String name = resultSet.getString("Note");
        System.out.println("ID: " + id + ", Name: " + name);
      }

      // Close the connections and resources
      resultSet.close();
      statement.close();
      conn.close();
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }
}