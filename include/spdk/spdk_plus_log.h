#define DEBUGLOG(fmt, args...) printf("\033[0;33;40m[ DEBUG ]\033[0m\033[2m %s:%d: \033[0m"fmt,__FUNCTION__,__LINE__,##args)
#define ERRLOG(fmt, args...) printf("\033[0;31;40m[ ERROR ]\033[0m\033[2m %s:%d: \033[0m"fmt,__FUNCTION__,__LINE__, ##args)
#define INFOLOG(fmt, args...) printf("\033[0;32;40m[ BRIEF ]\033[0m\033[2m %s:%d: \033[0m"fmt,__FUNCTION__,__LINE__, ##args)