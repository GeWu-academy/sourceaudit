public interface UserMapper {
    @Select("SELECT * FROM users WHERE id = ${id}")
    User findById(String id);
}
