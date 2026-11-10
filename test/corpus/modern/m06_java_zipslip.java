public class Unzip {
    public void extract(ZipInputStream zis, File destDir) throws IOException {
        ZipEntry e;
        while ((e = zis.getNextEntry()) != null) {
            File out = new File(destDir, e.getName());
            Files.copy(zis, out.toPath());
        }
    }
}
