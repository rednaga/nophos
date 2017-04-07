#include <stdio.h>
#include <strings.h> // For bzero
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define OAS_SET_CHARDEV_PING       0
#define OAS_SET_MEMCPY             1
#define OAS_SET_SECRET_KEY         2
#define OAS_SET_IMMEDIATE_EXIT     3
#define OAS_SET_LOG_LEVEL          4
#define OAS_SET_DIAGNOSTICS_ENABLE 5


#define OAS_GET_KEXT_SCHEMA_LEVEL  1
#define OAS_GET_KEXT_LOG_LEVEL     2

#define SWI_GET_SOCKET_INFO        0 // Causes hard system hang
#define SWI_GET_REDIRECT_PORT      1
#define SWI_GET_KEXT_LOG_LEVEL     2
#define SWI_GET_KEXT_SCHEMA_LEVEL  3
#define SWI_GET_KEXT_UNKNOWN  4

int main() {
  printf("Sophos fun...\n");

  int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

  struct sockaddr_ctl       addr;
  int                       ret = 1;
 
  if (fd != -1) {
    bzero(&addr, sizeof(addr)); // sets the sc_unit field to 0
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    // Web sockets : com.sophos.nke.swi
    // OaS: com.sophos.kext.oas
    //strncpy(info.ctl_name, "com.sophos.kext.oas", sizeof(info.ctl_name));
    strncpy(info.ctl_name, "com.sophos.nke.swi", sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info)) {
      printf("Could not get ID for kernel control.\n");
      return -1; // exit(-1);
    }

    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;

    int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (result) {
      fprintf(stderr, "connect failed %d\n", result);
    }

    printf("result = 0x%02x\n", result);

    int kEPCommand1 = 2;


    // getsockopt swi command 3 for getting expected schema : returns 6
    // getsockopt oas command 1 for getting expected schema : returns 7
    
    if(!result) {
      size_t o;
      socklen_t len = sizeof(o);
      result = getsockopt(fd, SO_ACCEPTCONN, 1, &o, &len);
	    //result = getsockopt(fd, SO_ACCEPTCONN, 3, &o, &len);
      if (result){
        fprintf(stderr, "getsockopt failed on cmd call - result was %d\n", result);
      } else {
	printf("getsockopt success : 0x%02x\n", o);
      }
    }
    
    if (!result) {
      char *secret = "3";
      socklen_t len = sizeof(secret);
      result = setsockopt( fd, SYSPROTO_CONTROL, OAS_SET_DIAGNOSTICS_ENABLE, secret, len);
      if (result){
	fprintf(stderr, "setsockopt failed on cmd call - result was %d\n", result);
      } else {
	printf("getsockopt success : 0x%02x\n", result);
      }
    }

  }

  printf("Closing socket...\n");
  if(close(fd)) {
    fprintf(stderr, "close failed\n");
  }
  
  printf("Done...\n");
}
