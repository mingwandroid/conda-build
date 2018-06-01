#include <zlib.h>

int main(int argc, char * argv[]) {
  gzFile * file = gzopen("/tmp/no", "rb");
}
