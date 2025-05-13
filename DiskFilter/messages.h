//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_RPC_RUNTIME             0x2
#define FACILITY_RPC_STUBS               0x3
#define FACILITY_IO_ERROR_CODE           0x4
#define FACILITY_DRIVER_ERROR_CODE       0x7


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: MSG_DRIVER_LOAD_DENIED
//
// MessageText:
//
// Denied load driver %2.
//
#define MSG_DRIVER_LOAD_DENIED           ((NTSTATUS)0x40070001L)

//
// MessageId: MSG_FAILED_TO_INIT
//
// MessageText:
//
// Failed to initialize the driver. DiskFilter will be disabled.
//
#define MSG_FAILED_TO_INIT               ((NTSTATUS)0xC0070002L)

//
// MessageId: MSG_FAILED_TO_LOAD_CONFIG
//
// MessageText:
//
// Failed to load the config (%2). DiskFilter will be disabled.
//
#define MSG_FAILED_TO_LOAD_CONFIG        ((NTSTATUS)0xC0070003L)

//
// MessageId: MSG_INIT_SUCCESS
//
// MessageText:
//
// Initialization success.
//
#define MSG_INIT_SUCCESS                 ((NTSTATUS)0x40070004L)

//
// MessageId: MSG_FAILED_LOGIN_ATTEMPT
//
// MessageText:
//
// Attempted to login with wrong password (%2).
//
#define MSG_FAILED_LOGIN_ATTEMPT         ((NTSTATUS)0x80070005L)

//
// MessageId: MSG_PROTECTION_ENABLED
//
// MessageText:
//
// Protection is enabled.
//
#define MSG_PROTECTION_ENABLED           ((NTSTATUS)0x40070006L)

//
// MessageId: MSG_PROTECTION_DISABLED
//
// MessageText:
//
// Protection is disabled.
//
#define MSG_PROTECTION_DISABLED          ((NTSTATUS)0x40070007L)

//
// MessageId: MSG_DRIVER_ALLOW_LOAD
//
// MessageText:
//
// Driver is allowed to load.
//
#define MSG_DRIVER_ALLOW_LOAD            ((NTSTATUS)0x40070008L)

//
// MessageId: MSG_DRIVER_WHITELIST
//
// MessageText:
//
// Driver load policy is white list.
//
#define MSG_DRIVER_WHITELIST             ((NTSTATUS)0x40070009L)

//
// MessageId: MSG_DRIVER_BLACKLIST
//
// MessageText:
//
// Driver load policy is black list.
//
#define MSG_DRIVER_BLACKLIST             ((NTSTATUS)0x4007000AL)

//
// MessageId: MSG_DRIVER_DENY_LOAD
//
// MessageText:
//
// Driver is denied to load.
//
#define MSG_DRIVER_DENY_LOAD             ((NTSTATUS)0x4007000BL)

//
// MessageId: MSG_THAWSPACE_ENABLED
//
// MessageText:
//
// ThawSpace is enabled.
//
#define MSG_THAWSPACE_ENABLED            ((NTSTATUS)0x4007000CL)

//
// MessageId: MSG_FAILED_TO_INIT_THAWSPACE
//
// MessageText:
//
// Failed to initialize ThawSpace. ThawSpace will be disabled.
//
#define MSG_FAILED_TO_INIT_THAWSPACE     ((NTSTATUS)0xC007000DL)

//
// MessageId: MSG_THAWSPACE_LOAD_OK
//
// MessageText:
//
// ThawSpace load success (%2).
//
#define MSG_THAWSPACE_LOAD_OK            ((NTSTATUS)0x4007000EL)

//
// MessageId: MSG_THAWSPACE_LOAD_FAILED
//
// MessageText:
//
// ThawSpace load failed (%2). 
//
#define MSG_THAWSPACE_LOAD_FAILED        ((NTSTATUS)0xC007000FL)

//
// MessageId: MSG_THAWSPACE_HIDE
//
// MessageText:
//
// ThawSpace is hidden (%2). 
//
#define MSG_THAWSPACE_HIDE               ((NTSTATUS)0x40070010L)

//
// MessageId: MSG_PROTECT_VOLUME_LOAD_FAILED
//
// MessageText:
//
// Failed to load protected volume %2. Filter on this volume will be disabled.
//
#define MSG_PROTECT_VOLUME_LOAD_FAILED   ((NTSTATUS)0xC0070011L)

//
// MessageId: MSG_PROTECT_VOLUME_LOAD_OK
//
// MessageText:
//
// Protected volume %2 load success.
//
#define MSG_PROTECT_VOLUME_LOAD_OK       ((NTSTATUS)0x40070012L)

//
// MessageId: MSG_DIRECT_MOUNT_OK
//
// MessageText:
//
// Protected volume %2 mount success.
//
#define MSG_DIRECT_MOUNT_OK              ((NTSTATUS)0x40070013L)

//
// MessageId: MSG_DIRECT_UNMOUNT_OK
//
// MessageText:
//
// Protected volume %2 unmount success.
//
#define MSG_DIRECT_UNMOUNT_OK            ((NTSTATUS)0x40070014L)

