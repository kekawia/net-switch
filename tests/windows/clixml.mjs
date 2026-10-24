// Windows PowerShell 5.1 serialises a child's stderr as CLIXML when the
// stream is redirected. A cold start writes a "Preparing modules for first
// use" progress record there; that is not a failure. Only records marked
// S="Error" carry a real error, and the process exit code still decides
// whether the call succeeded.

const entities = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function decode(text) {
  return text
    .replace(/_x000D__x000A_/g, '\n')
    .replace(/_x000D_/g, '\r')
    .replace(/_x000A_/g, '\n')
    .replace(/&(amp|lt|gt|quot|apos);/g, (_, name) => entities[name]);
}

// The error records in a CLIXML stream, in order. Progress, warning, verbose
// and information records are not errors.
export function clixmlErrors(stderr) {
  const errors = [];
  for (const match of String(stderr ?? '').matchAll(/<S S="Error">([\s\S]*?)<\/S>/g)) {
    errors.push(decode(match[1]).trimEnd());
  }
  return errors;
}

// The first useful line of a failed PowerShell call. A real error record wins;
// progress-only stderr leaves the exit code to name the failure. Other errors
// (a malformed answer, for example) keep their own message.
export function describePowerShellFailure(error) {
  const [first] = clixmlErrors(error?.stderr);
  if (first) return first.split(/\r?\n/).map((line) => line.trim()).find(Boolean)?.slice(0, 200) ?? 'PowerShell reported an error';
  const lines = String(error?.stderr ?? '')
    .replace(/#< CLIXML[\s\S]*$/, '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length > 0) return lines[0].slice(0, 200);
  if (error?.killed) return 'PowerShell did not answer within its deadline';
  const message = String(error?.message ?? '');
  if (!message.startsWith('Command failed:')) return message.slice(0, 200);
  return `PowerShell exited with code ${error?.code ?? 'unknown'}`;
}
