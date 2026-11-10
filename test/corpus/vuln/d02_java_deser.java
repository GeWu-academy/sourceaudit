public class B {
  public Object load(byte[] b) throws Exception {
    ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(b));
    return in.readObject();
  }
}
