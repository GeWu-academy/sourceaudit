import javax.naming.InitialContext;

public class Lookup {
    public Object resolve(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        InitialContext ctx = new InitialContext();
        return ctx.lookup(name);
    }
}
