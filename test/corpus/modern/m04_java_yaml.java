public class Cfg {
    public Object load(HttpServletRequest request) {
        String y = request.getParameter("y");
        return new Yaml().load(y);
    }
}
