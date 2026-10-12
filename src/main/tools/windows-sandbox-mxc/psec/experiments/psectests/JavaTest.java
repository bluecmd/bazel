import java.nio.file.*;
public class JavaTest {
  public static void main(String[] a) throws Exception {
    String rf = System.getenv("RUNFILES_MANIFEST_FILE");
    System.out.println("RUNFILES_MANIFEST_FILE=" + rf + " TEST_TMPDIR=" + System.getenv("TEST_TMPDIR"));
    String path = null;
    for (String line : Files.readAllLines(Paths.get(rf))) {
      if (line.startsWith("_main/psectests/data.txt ")) path = line.substring(line.indexOf(' ') + 1);
    }
    String s = Files.readString(Paths.get(path)).trim();
    System.out.println("data: '" + s + "'");
    if (!s.equals("hello data")) System.exit(1);
    Files.writeString(Paths.get(System.getenv("TEST_TMPDIR"), "t.txt"), "x");
    System.out.println("PASS");
  }
}
