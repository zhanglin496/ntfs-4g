    #include <sys/mount.h>
#include <stdio.h>

int main()
{
      printf("%d\n", mount("/dev/sdb1", "./test",
                 	"ntfs-4g", 0, NULL));
}
