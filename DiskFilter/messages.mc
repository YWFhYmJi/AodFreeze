MessageIdTypedef = NTSTATUS

SeverityNames = (
	Success = 0x0:STATUS_SEVERITY_SUCCESS
	Informational = 0x1:STATUS_SEVERITY_INFORMATIONAL
	Warning = 0x2:STATUS_SEVERITY_WARNING
	Error = 0x3:STATUS_SEVERITY_ERROR
)

FacilityNames = (
	System = 0x0
	RpcRuntime = 0x2:FACILITY_RPC_RUNTIME
	RpcStubs = 0x3:FACILITY_RPC_STUBS
	Io = 0x4:FACILITY_IO_ERROR_CODE
	Driver = 0x7:FACILITY_DRIVER_ERROR_CODE
)

MessageId=0x0001
Facility=Driver
Severity=Informational
SymbolicName=MSG_DRIVER_LOAD_DENIED
Language=English
Denied load driver %2.
.

MessageId=0x0002
Facility=Driver
Severity=Error
SymbolicName=MSG_FAILED_TO_INIT
Language=English
Failed to initialize the driver. DiskFilter will be disabled.
.

MessageId=0x0003
Facility=Driver
Severity=Error
SymbolicName=MSG_FAILED_TO_LOAD_CONFIG
Language=English
Failed to load the config (%2). DiskFilter will be disabled.
.

MessageId=0x0004
Facility=Driver
Severity=Informational
SymbolicName=MSG_INIT_SUCCESS
Language=English
Initialization success.
.

MessageId=0x0005
Facility=Driver
Severity=Warning
SymbolicName=MSG_FAILED_LOGIN_ATTEMPT
Language=English
Attempted to login with wrong password (%2).
.

MessageId=0x0006
Facility=Driver
Severity=Informational
SymbolicName=MSG_PROTECTION_ENABLED
Language=English
Protection is enabled.
.

MessageId=0x0007
Facility=Driver
Severity=Informational
SymbolicName=MSG_PROTECTION_DISABLED
Language=English
Protection is disabled.
.

MessageId=0x0008
Facility=Driver
Severity=Informational
SymbolicName=MSG_DRIVER_ALLOW_LOAD
Language=English
Driver is allowed to load.
.

MessageId=0x0009
Facility=Driver
Severity=Informational
SymbolicName=MSG_DRIVER_WHITELIST
Language=English
Driver load policy is white list.
.

MessageId=0x000A
Facility=Driver
Severity=Informational
SymbolicName=MSG_DRIVER_BLACKLIST
Language=English
Driver load policy is black list.
.

MessageId=0x000B
Facility=Driver
Severity=Informational
SymbolicName=MSG_DRIVER_DENY_LOAD
Language=English
Driver is denied to load.
.

MessageId=0x000C
Facility=Driver
Severity=Informational
SymbolicName=MSG_THAWSPACE_ENABLED
Language=English
ThawSpace is enabled.
.

MessageId=0x000D
Facility=Driver
Severity=Error
SymbolicName=MSG_FAILED_TO_INIT_THAWSPACE
Language=English
Failed to initialize ThawSpace. ThawSpace will be disabled.
.

MessageId=0x000E
Facility=Driver
Severity=Informational
SymbolicName=MSG_THAWSPACE_LOAD_OK
Language=English
ThawSpace load success (%2).
.

MessageId=0x000F
Facility=Driver
Severity=Error
SymbolicName=MSG_THAWSPACE_LOAD_FAILED
Language=English
ThawSpace load failed (%2). 
.

MessageId=0x0010
Facility=Driver
Severity=Informational
SymbolicName=MSG_THAWSPACE_HIDE
Language=English
ThawSpace is hidden (%2). 
.

MessageId=0x0011
Facility=Driver
Severity=Error
SymbolicName=MSG_PROTECT_VOLUME_LOAD_FAILED
Language=English
Failed to load protected volume %2. Filter on this volume will be disabled.
.

MessageId=0x0012
Facility=Driver
Severity=Informational
SymbolicName=MSG_PROTECT_VOLUME_LOAD_OK
Language=English
Protected volume %2 load success.
.

MessageId=0x0013
Facility=Driver
Severity=Informational
SymbolicName=MSG_DIRECT_MOUNT_OK
Language=English
Protected volume %2 mount success.
.

MessageId=0x0014
Facility=Driver
Severity=Informational
SymbolicName=MSG_DIRECT_UNMOUNT_OK
Language=English
Protected volume %2 unmount success.
.

MessageId=0x0015
Facility=Driver
Severity=Informational
SymbolicName=MSG_SET_SAVEDATA_OK
Language=English
The data on volume %2 will be saved at shutdown.
.

MessageId=0x0016
Facility=Driver
Severity=Informational
SymbolicName=MSG_CANCEL_SAVEDATA_OK
Language=English
The data on volume %2 will not be saved on shutdown.
.
