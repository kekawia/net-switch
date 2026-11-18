using Microsoft.Windows.EventTracing;
using Microsoft.Windows.EventTracing.Processes;
using Microsoft.Windows.EventTracing.Cpu;
using System.Text.Json;
using System.Diagnostics;

// PIDs are sampled before the first traffic window. Match the lifetime at that
// instant, then follow ETW's lifetime-resolved parent links through process exit.
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
var sampling = trace.UseCpuSamplingData();
trace.Process();
var roots = new HashSet<IProcess>();
foreach (var root in input.Roots) {
    var process = processes.Result.Processes.Single(p => p.Id == root.Pid &&
        (p.CreateTime is null || p.CreateTime.Value.DateTimeOffset <= input.RootsAt) &&
        (p.ExitTime is null || p.ExitTime.Value.DateTimeOffset >= input.RootsAt));
    if (!String.Equals(Path.GetFileName(process.ImageName), Path.GetFileName(root.Image), StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException("Recorded process identity differs from the root inventory.");
    roots.Add(process);
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
var byImage = new Dictionary<string,long>();
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
        var name = slice.Process.ImageName + "/" + slice.Process.Id;
        byImage[name] = byImage.GetValueOrDefault(name) + ticks;
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
var samplesByStack=new Dictionary<string,int>();
foreach(var sample in sampling.Result.Samples) {
    if (!members.Contains(sample.Process) || !input.Samples.Any(w=>sample.Timestamp.DateTimeOffset>=w.StartUtc && sample.Timestamp.DateTimeOffset<w.EndUtc)) continue;
    string Frame(Microsoft.Windows.EventTracing.Symbols.StackFrame f) {
        if (!f.HasValue) return "unknown";
        var image=Path.GetFileName(f.Image?.Path ?? "unknown");
        return image.Equals("netswitch-engine.exe",StringComparison.OrdinalIgnoreCase) ? image+"+"+f.RelativeVirtualAddress : image;
    }
    var path=sample.Process.ImageName+"|"+Frame(sample.TopStackFrame)+"|"+(sample.Stack==null?"":String.Join(";",sample.Stack.Frames.Select(Frame).Take(48)));
    samplesByStack[path]=samplesByStack.GetValueOrDefault(path)+1;
}
File.WriteAllText(args[2],JsonSerializer.Serialize(new {
    samplesByStack,
    byImageSeconds = byImage.ToDictionary(p=>p.Key,p=>TimeSpan.FromTicks(p.Value).TotalSeconds),
    members = members.Count,
    scheduled = counted.Count,
    exited = counted.Count(p=>p.ExitTime.HasValue),
    windows = input.Samples.Select((s,i)=>new { s.Streams, s.Pass, s.Bytes, cpuSeconds=TimeSpan.FromTicks(cpu[i]).TotalSeconds })
}));
record Root(int Pid,string Image);
record Window(int Streams,int Pass,long Bytes,DateTimeOffset StartUtc,DateTimeOffset EndUtc);
record Measurement(DateTimeOffset RootsAt,Root[] Roots,Window[] Samples,int? CalibrationChild,double ExpectedChildSeconds,string? InstallDirectory);
