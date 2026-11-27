using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ClaudeStudio.ControlPlane {
    public enum SpaceId {
        None = 0,
        A = 1,
        B = 2
    }

    public enum SpaceNetworkState {
        Stopped,
        ColdBlocked,
        ProxyOnline,
        FaultCutoff,
        RollingBack
    }

    public enum ProjectAccessMode {
        Denied,
        ReadOnly,
        ReadWrite
    }

    public sealed class SpaceProfileConfig {
        public SpaceId Id { get; set; }
        public string DisplayName { get; set; }
        public string AccentHex { get; set; }
        public string LocalAccountName { get; set; }
        public string SyntheticEmail { get; set; }
        public string UiLanguage { get; set; }
        public string AcceptLanguage { get; set; }
        public string RendererTimezone { get; set; }
        public int RendererOffsetMinutes { get; set; }
        public string ChildLangEnv { get; set; }
        public int ProxyPort { get; set; }
        public string IsolatedProfileLabel { get; set; }
    }

    public sealed class WinNativeTimezoneReading {
        public uint Id { get; set; }
        public int BiasMinutes { get; set; }
        public string StandardName { get; set; }
        public string DaylightName { get; set; }
    }

    public sealed class LocaleTimezoneReadings {
        public string WindowLanguage { get; set; }
        public string WindowTitle { get; set; }
        public string RendererTimezone { get; set; }
        public string RendererRefUtcFormatted { get; set; }
        public string RequestAcceptLanguage { get; set; }
        public string ChildLangEnv { get; set; }
        public string ChildTzEnv { get; set; }
        public WinNativeTimezoneReading WindowsNativeTimezone { get; set; }
        public string NativeTimezoneBoundaryNote { get; set; }
    }

    public sealed class SpaceRuntimeSnapshot {
        public SpaceId Id { get; set; }
        public SpaceNetworkState State { get; set; }
        public int Pid { get; set; }
        public long WindowHandle { get; set; }
        public string ContainerSid { get; set; }
        public ushort WfpSublayerWeight { get; set; }
        public string WfpManifestSha256Prefix12 { get; set; }
        public bool StaticBlockActive { get; set; }
        public bool DynamicExceptionOpen { get; set; }
        public int ProxyOwnerPid { get; set; }
        public int ProxyPort { get; set; }
        public int DnsSendCount { get; set; }
        public string LastTransitionUtc { get; set; }
        public string LastNote { get; set; }
        public LocaleTimezoneReadings LocaleReadings { get; set; }
    }

    public sealed class ProjectMountRecord {
        public string DisplayName { get; set; }
        public string CanonicalPath { get; set; }
        public SpaceId WriterSpace { get; set; }
        public bool SpaceAReadOnly { get; set; }
        public bool SpaceBReadOnly { get; set; }
        public string LastUpdatedUtc { get; set; }
    }

    public sealed class LeaseOperationResult {
        public bool Ok { get; set; }
        public string Code { get; set; }
        public string Message { get; set; }
        public string CanonicalPath { get; set; }
        public SpaceId Holder { get; set; }
    }

    public sealed class TemplateSyncResult {
        public bool Ok { get; set; }
        public string Code { get; set; }
        public string Message { get; set; }
        public string SourceSha256Prefix12 { get; set; }
    }

    public sealed class AuditLogEntry {
        public string Utc { get; set; }
        public string Category { get; set; }
        public string Space { get; set; }
        public string Message { get; set; }
    }

    public static class NativeTimezoneHelper {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SystemTime {
            public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct TimeZoneInfoNative {
            public int Bias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string StandardName;
            public SystemTime StandardDate;
            public int StandardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string DaylightName;
            public SystemTime DaylightDate;
            public int DaylightBias;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern uint GetTimeZoneInformation(out TimeZoneInfoNative info);

        public static WinNativeTimezoneReading ReadWin32NativeTimezone() {
            TimeZoneInfoNative tzi;
            uint id = GetTimeZoneInformation(out tzi);
            return new WinNativeTimezoneReading {
                Id = id,
                BiasMinutes = tzi.Bias,
                StandardName = tzi.StandardName ?? "",
                DaylightName = tzi.DaylightName ?? ""
            };
        }

        public static string FormatFixedUtcWithOffset(int offsetMinutes) {
            var baseUtc = new DateTimeOffset(2026, 7, 1, 12, 0, 0, TimeSpan.Zero);
            var shifted = baseUtc.ToOffset(TimeSpan.FromMinutes(offsetMinutes));
            return shifted.ToString("yyyy-MM-ddTHH:mm:sszzz");
        }
    }
}
