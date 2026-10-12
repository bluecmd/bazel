#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
// Runfiles on Windows are manifest-based: look data.txt up in RUNFILES_MANIFEST_FILE.
int main() {
  const char* tmp = getenv("TEST_TMPDIR");
  const char* undecl = getenv("TEST_UNDECLARED_OUTPUTS_DIR");
  const char* mf = getenv("RUNFILES_MANIFEST_FILE");
  printf("TEST_TMPDIR=%s\nUNDECLARED=%s\nMANIFEST=%s\n", tmp ? tmp : "(null)", undecl ? undecl : "(null)", mf ? mf : "(null)");
  std::string path;
  if (mf) { std::ifstream m(mf); std::string line; while (std::getline(m, line)) if (line.rfind("_main/psectests/data.txt ", 0) == 0) path = line.substr(line.find(' ') + 1); }
  if (path.empty()) path = "psectests/data.txt";
  std::ifstream in(path);
  std::string s; std::getline(in, s);
  printf("data (%s): '%s'\n", path.c_str(), s.c_str());
  if (s != "hello data") { printf("FAIL: runfile data not readable\n"); return 1; }
  std::ofstream out(std::string(tmp ? tmp : ".") + "/t.txt"); out << "x"; out.close();
  if (undecl) { std::ofstream u(std::string(undecl) + "/u.txt"); u << "undeclared"; }
  printf("PASS\n");
  return 0;
}
