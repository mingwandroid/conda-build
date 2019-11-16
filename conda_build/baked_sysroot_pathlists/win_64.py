try:
    from pathlib2 import PurePath
except:
    from pathlib import PurePath
DEFAULT_WIN_WHITELIST_BAKED = (PurePath('/System32/advapi32.dll'),  # noqa
                               PurePath('/System32/bcrypt.dll'),  # noqa
                               PurePath('/System32/comctl32.dll'),  # noqa
                               PurePath('/System32/comdlg32.dll'),  # noqa
                               PurePath('/System32/crypt32.dll'),  # noqa
                               PurePath('/System32/dbghelp.dll'),  # noqa
                               PurePath('/System32/gdi32.dll'),  # noqa
                               PurePath('/System32/imm32.dll'),  # noqa
                               PurePath('/System32/kernel32.dll'),  # noqa
                               PurePath('/System32/msvcrt.dll'),  # noqa
                               PurePath('/System32/netapi32.dll'),  # noqa
                               PurePath('/System32/ntdll.dll'),  # noqa
                               PurePath('/System32/ole32.dll'),  # noqa
                               PurePath('/System32/oleaut32.dll'),  # noqa
                               PurePath('/System32/psapi.dll'),  # noqa
                               PurePath('/System32/rpcrt4.dll'),  # noqa
                               PurePath('/System32/shell32.dll'),  # noqa
                               PurePath('/System32/user32.dll'),  # noqa
                               PurePath('/System32/userenv.dll'),  # noqa
                               PurePath('/System32/winhttp.dll'),  # noqa
                               PurePath('/System32/ws2_32.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-base-util-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-com-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-comm-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-console-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-datetime-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-datetime-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-debug-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-debug-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-delayload-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-errorhandling-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-errorhandling-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-fibers-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-fibers-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-file-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-file-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-file-l1-2-1.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-core-file-l2-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-core-file-l2-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-handle-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-heap-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Core-Heap-Obsolete-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-interlocked-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-io-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-io-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-kernel32-legacy-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-kernel32-legacy-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Core-Kernel32-Private-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Core-Kernel32-Private-L1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-libraryloader-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-libraryloader-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-localization-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-localization-l1-2-1.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-core-localization-obsolete-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-memory-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-memory-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-memory-l1-1-2.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-namedpipe-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-privateprofile-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-privateprofile-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-processenvironment-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-processenvironment-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-processthreads-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-processthreads-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-processthreads-l1-1-2.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-processtopology-obsolete-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-profile-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-realtime-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-registry-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-registry-l2-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-rtlsupport-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-shlwapi-legacy-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-shlwapi-obsolete-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-shutdown-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-string-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-core-string-l2-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-core-string-obsolete-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-stringansi-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-stringloader-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-synch-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-synch-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-sysinfo-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-sysinfo-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-sysinfo-l1-2-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-threadpool-l1-2-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-threadpool-legacy-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-threadpool-private-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-timezone-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-url-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-util-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-version-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-wow64-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-core-xstate-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-core-xstate-l2-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-conio-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-convert-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-environment-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-filesystem-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-heap-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-locale-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-math-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-multibyte-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-private-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-process-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-runtime-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-stdio-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-string-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-time-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-crt-utility-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-devices-config-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-devices-config-L1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Eventing-ClassicProvider-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-eventing-consumer-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Eventing-Controller-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Eventing-Legacy-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Eventing-Provider-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-EventLog-Legacy-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-security-base-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-security-cryptoapi-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Security-Lsalookup-L2-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-Security-Lsalookup-L2-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-security-lsapolicy-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/API-MS-Win-security-provider-L1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-security-sddl-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-core-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-core-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-management-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-management-l2-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-private-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-private-l1-1-1.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-service-winsvc-l1-1-0.dll'),  # noqa
                               PurePath('/System32/downlevel/api-ms-win-shcore-stream-l1-1-0.dll'),  # noqa
)
