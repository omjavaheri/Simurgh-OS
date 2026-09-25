# check-wav-tone.ps1 - evidence for the HDA driver (docs/audio-plan.md).
#
# Reads a 16-bit PCM wav written by QEMU (-audiodev wav,id=a0,path=...), and
# reports: sample rate, channels, seconds of audio, seconds that are not
# silent, peak and RMS amplitude, and the dominant frequency of the loudest
# stretch (Goertzel scan, 50 Hz steps refined to 1 Hz). QEMU may leave the
# header sizes unset when it is killed, so the data chunk is read to end of
# file. Exit code 0 when a tone within -ToleranceHz of -ExpectedHz is found and
# at least -MinSeconds of it is non-silent, 1 otherwise.
#
#   .\scripts\check-wav-tone.ps1 C:\Temp\hda-demo.wav -ExpectedHz 440
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [double]$ExpectedHz = 440,
    [double]$ToleranceHz = 5,
    [double]$MinSeconds = 0.3,
    [switch]$Quiet
)
$bytes = [System.IO.File]::ReadAllBytes($Path)
if ($bytes.Length -lt 44 -or [Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'RIFF') { Write-Host "not a wav file"; exit 1 }
$pos = 12; $rate = 0; $chan = 0; $bits = 0; $dataOff = -1
while ($pos + 8 -le $bytes.Length) {
    $id = [Text.Encoding]::ASCII.GetString($bytes, $pos, 4)
    $len = [BitConverter]::ToUInt32($bytes, $pos + 4)
    if ($id -eq 'fmt ') {
        $chan = [BitConverter]::ToUInt16($bytes, $pos + 10)
        $rate = [BitConverter]::ToUInt32($bytes, $pos + 12)
        $bits = [BitConverter]::ToUInt16($bytes, $pos + 22)
    } elseif ($id -eq 'data') { $dataOff = $pos + 8; break }
    $pos += 8 + $len
}
if ($dataOff -lt 0 -or $bits -ne 16 -or $chan -lt 1) { Write-Host "unsupported wav (bits=$bits channels=$chan)"; exit 1 }
Add-Type -TypeDefinition @"
using System;
public static class WavTone {
    public static double[] Analyse(byte[] b, int off, int chan, int rate) {
        int frames = (b.Length - off) / (2 * chan);
        double[] s = new double[frames];
        for (int i = 0; i < frames; i++) s[i] = BitConverter.ToInt16(b, off + i * 2 * chan);
        // Non-silent frames (|x| > 200) and peak / rms over them.
        int active = 0; double peak = 0, sum = 0; int first = -1, last = -1;
        for (int i = 0; i < frames; i++) {
            double a = Math.Abs(s[i]);
            if (a > 200) { active++; sum += s[i] * s[i]; if (first < 0) first = i; last = i; }
            if (a > peak) peak = a;
        }
        double rms = active > 0 ? Math.Sqrt(sum / active) : 0;
        // Goertzel over the loudest 0.25 s window inside the active region.
        double bestF = 0, bestP = 0;
        if (active > rate / 10) {
            int win = Math.Min(rate / 4, last - first);
            int bestStart = first; double bestE = 0;
            for (int st = first; st + win <= last + 1; st += win / 4) {
                double e = 0; for (int i = st; i < st + win; i += 4) e += s[i] * s[i];
                if (e > bestE) { bestE = e; bestStart = st; }
            }
            Func<double, double> g = (f) => {
                double w = 2 * Math.PI * f / rate, c = 2 * Math.Cos(w), s1 = 0, s2 = 0;
                for (int i = bestStart; i < bestStart + win; i++) { double x = s[i] + c * s1 - s2; s2 = s1; s1 = x; }
                return s1 * s1 + s2 * s2 - c * s1 * s2;
            };
            for (double f = 100; f <= 4000; f += 50) { double p = g(f); if (p > bestP) { bestP = p; bestF = f; } }
            double c0 = bestF; bestP = 0;
            for (double f = c0 - 50; f <= c0 + 50; f += 1) { double p = g(f); if (p > bestP) { bestP = p; bestF = f; } }
        }
        return new double[] { frames, active, peak, rms, bestF };
    }
}
"@
$r = [WavTone]::Analyse($bytes, $dataOff, $chan, $rate)
$total = $r[0] / $rate; $act = $r[1] / $rate
if (-not $Quiet) {
    "file          : $Path"
    "format        : $rate Hz, $chan ch, $bits bit"
    "length        : {0:N2} s" -f $total
    "non-silent    : {0:N2} s" -f $act
    "peak / rms    : {0:N0} / {1:N0}  (full scale 32767)" -f $r[2], $r[3]
    "dominant freq : {0:N0} Hz" -f $r[4]
}
$ok = ($act -ge $MinSeconds) -and ([Math]::Abs($r[4] - $ExpectedHz) -le $ToleranceHz)
if ($ok) { "RESULT: tone of $($r[4]) Hz found ({0:N2} s non-silent)" -f $act; exit 0 }
"RESULT: expected ~$ExpectedHz Hz for >= $MinSeconds s, not found"; exit 1
