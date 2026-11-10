public class Parse {
    public Object body(HttpServletRequest request) {
        String body = request.getParameter("json");
        return JSON.parseObject(body);
    }
}
