using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Processes;
using Microsoft.Windows.EventTracing.Cpu;
using System.Text.Json;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;

// WMI enumerates processes over an interval. Helpers can exit before that
// enumeration returns. Follow the matched ETW lifetimes through process exit.
if (args is ["table", var tablePort, var tableUplink]) {
    Console.WriteLine(JsonSerializer.Serialize(ReadTable(Int32.Parse(tablePort), IPAddress.Parse(tableUplink))));
    return;
}
if (args is ["settle", var settlePort, var settleUplink, var settleOutput]) {
    var port = Int32.Parse(settlePort);
    var uplink = IPAddress.Parse(settleUplink);
    var timer = Stopwatch.StartNew();
    var observations = new List<TableObservation>();
    while (true) {
        var sample = ReadTable(port, uplink);
        observations.Add(sample);
        if (sample.TargetRows == 0 || timer.Elapsed >= TimeSpan.FromMinutes(8)) break;
        Thread.Sleep(TimeSpan.FromSeconds(2));
    }
    File.WriteAllText(settleOutput, JsonSerializer.Serialize(observations));
    if (observations[^1].TargetRows != 0) throw new InvalidDataException("Benchmark TCP rows still present: "+JsonSerializer.Serialize(observations[^1]));
    return;
}
if (args is ["burn"]) {
    using var self = Process.GetCurrentProcess();
    var cpuStart = self.TotalProcessorTime;
    while (self.TotalProcessorTime - cpuStart < TimeSpan.FromMilliseconds(500)) Thread.SpinWait(32768);
    return;
}
if (args is ["calibrate", var calibrationInput]) {
    using var self = Process.GetCurrentProcess();
    var start = DateTimeOffset.UtcNow;
    using var child = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "burn") { UseShellExecute = false })!;
    if (!child.WaitForExit(15000) || child.ExitCode != 0) throw new InvalidDataException("Calibration child failed.");
    var end = DateTimeOffset.UtcNow;
    var calibration = new {
        rootsAt=start, roots=new[]{new Root(self.Id, Environment.ProcessPath!)},
        samples=new[]{new Window(1,0,1,start,end)}, calibrationChild=child.Id, expectedChildSeconds=child.TotalProcessorTime.TotalSeconds
    };
    File.WriteAllText(calibrationInput,JsonSerializer.Serialize(calibration));
    return;
}
if (args.Length != 3) throw new ArgumentException("Provide ETL, measured windows JSON, and result path.");
var input = JsonSerializer.Deserialize<Measurement>(File.ReadAllText(args[1]), new JsonSerializerOptions(JsonSerializerDefaults.Web))
    ?? throw new InvalidDataException("Missing measurement.");
if (input.Roots.Length == 0 || input.Samples.Length == 0) throw new InvalidDataException("Missing roots/windows.");
using var trace = TraceProcessor.Create(args[0], new TraceProcessorSettings { AllowLostEvents = false, SuppressFirstTimeSetupMessage = true });
var processes = trace.UseProcesses();
var usage = trace.UseCpuSchedulingData();
trace.Process();
var roots = new HashSet<IProcess>();
var from = input.RootsFrom ?? input.RootsAt;
if (from > input.RootsAt) throw new InvalidDataException("Invalid process inventory interval.");
foreach (var root in input.Roots) {
    var lifetimes = processes.Result.Processes.Where(p => p.Id == root.Pid).ToArray();
    var overlaps = lifetimes.Where(p =>
        String.Equals(Path.GetFileName(p.ImageName), Path.GetFileName(root.Image), StringComparison.OrdinalIgnoreCase) &&
        (p.CreateTime is null || p.CreateTime.Value.DateTimeOffset <= input.RootsAt) &&
        (p.ExitTime is null || p.ExitTime.Value.DateTimeOffset >= from)).ToArray();
    if (overlaps.Length != 1) {
        var seen = String.Join(", ", lifetimes.Select(p =>
            $"{p.ImageName} [{p.CreateTime?.DateTimeOffset:O}, {p.ExitTime?.DateTimeOffset:O}]"));
        throw new InvalidDataException($"Expected one lifetime for PID {root.Pid} {root.Image} created {root.CreatedAt:O}, observed [{from:O}, {input.RootsAt:O}]. Trace: {seen}");
    }
    roots.Add(overlaps[0]);
}
bool Included(IProcess? p) {
    while (p is not null) {
        if (roots.Contains(p)) return true;
        p = p.Parent;
    }
    return false;
}
var members = processes.Result.Processes.Where(Included).ToHashSet();
if (input.InstallDirectory is string install) {
    var prefix = Path.TrimEndingDirectorySeparator(install) + Path.DirectorySeparatorChar;
    var first = input.Samples.Min(w=>w.StartUtc);
    var last = input.Samples.Max(w=>w.EndUtc);
    foreach (var p in processes.Result.Processes) {
        if (members.Contains(p) || p.ExitTime?.DateTimeOffset < first || p.CreateTime?.DateTimeOffset > last) continue;
        if (p.Images.Any(i=>i.Path != null && i.Path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)
            && String.Equals(Path.GetFileName(i.Path),p.ImageName,StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("A separately launched installed process was absent from CPU accounting: "+p.ImageName);
    }
}
var cpu = new long[input.Samples.Length];
var counted = new HashSet<IProcess>();
long calibrationTicks = 0;
foreach (var slice in usage.Result.CpuTimeSlices) {
    if (!members.Contains(slice.Process)) continue;
    var lo = slice.StartTime.DateTimeOffset.UtcTicks;
    var hi = slice.StopTime.DateTimeOffset.UtcTicks;
    for (int i=0; i<cpu.Length; i++) {
        var window = input.Samples[i];
        var ticks = Math.Min(hi,window.EndUtc.UtcTicks) - Math.Max(lo,window.StartUtc.UtcTicks);
        if (ticks <= 0) continue;
        cpu[i] += ticks;
        if (slice.Process.Id == input.CalibrationChild) calibrationTicks += ticks;
        counted.Add(slice.Process);
    }
}
if (cpu.Any(n=>n<=0)) throw new InvalidDataException("No measured product CPU in a traffic window.");
if (input.CalibrationChild is int childId) {
    var duration = TimeSpan.FromTicks(calibrationTicks).TotalSeconds;
    if (!counted.Any(p=>p.Id == childId && p.ExitTime.HasValue) || duration < 0.45 ||
        Math.Abs(duration-input.ExpectedChildSeconds) > Math.Max(0.10,0.15*input.ExpectedChildSeconds))
        throw new InvalidDataException("Trace missed CPU from the short-lived calibration child.");
}
File.WriteAllText(args[2],JsonSerializer.Serialize(new {
    members = members.Count,
    scheduled = counted.Count,
    exited = counted.Count(p=>p.ExitTime.HasValue),
    windows = input.Samples.Select((s,i)=>new { s.Streams, s.Pass, s.Bytes, cpuSeconds=TimeSpan.FromTicks(cpu[i]).TotalSeconds })
}));
static TableObservation ReadTable(int port, IPAddress uplink) {
    if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
    var target = IPAddress.Parse("198.19.128.2");
    var rows = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
    static bool Same(IPAddress a, IPAddress b) => a.Equals(b) || a.MapToIPv6().Equals(b.MapToIPv6());
    var matched = rows.Where(row =>
        (row.RemoteEndPoint.Port == port && (Same(row.RemoteEndPoint.Address,target) || Same(row.RemoteEndPoint.Address,uplink))) ||
        (row.LocalEndPoint.Port == port && Same(row.LocalEndPoint.Address,uplink))).ToArray();
    return new TableObservation(DateTimeOffset.UtcNow, rows.Length,
        rows.Count(row => row.State == TcpState.TimeWait), matched.Length,
        matched.Count(row => row.State == TcpState.TimeWait));
}
record TableObservation(DateTimeOffset Utc,int TotalRows,int AllTimeWait,int TargetRows,int TargetTimeWait);
record Root(int Pid,string Image,DateTimeOffset? CreatedAt=null);
record Window(int Streams,int Pass,long Bytes,DateTimeOffset StartUtc,DateTimeOffset EndUtc);
record Measurement(DateTimeOffset RootsAt,Root[] Roots,Window[] Samples,int? CalibrationChild,double ExpectedChildSeconds,string? InstallDirectory,DateTimeOffset? RootsFrom=null);
