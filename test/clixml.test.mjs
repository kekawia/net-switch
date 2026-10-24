import assert from 'node:assert/strict';
import test from 'node:test';
import { clixmlErrors, describePowerShellFailure } from '../tests/windows/clixml.mjs';

const progress = `#< CLIXML
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>`;

const failure = (stderr, code = 1) => Object.assign(new Error('Command failed: powershell.exe -EncodedCommand AAAA'), { code, stderr });

test('a progress-only CLIXML stream has no error records', () => {
  assert.deepEqual(clixmlErrors(progress), []);
});

test('an error record is decoded, and a non-zero exit still names the failure', () => {
  const error = failure(`${progress}<Objs><S S="Error">Get-Process : Cannot find a process._x000D__x000A_</S><S S="Error">At line:2 char:2_x000D__x000A_</S><S S="Error">+ CategoryInfo : ObjectNotFound: (&lt;pid&gt;) [Get-Process]</S></Objs>`);
  assert.deepEqual(clixmlErrors(error.stderr), [
    'Get-Process : Cannot find a process.',
    'At line:2 char:2',
    '+ CategoryInfo : ObjectNotFound: (<pid>) [Get-Process]',
  ]);
  assert.equal(describePowerShellFailure(error), 'Get-Process : Cannot find a process.');
  assert.equal(describePowerShellFailure(failure(progress)), 'PowerShell exited with code 1');
});

test('a malformed answer keeps its own message', () => {
  assert.equal(describePowerShellFailure(new Error('Unexpected token < in JSON')), 'Unexpected token < in JSON');
});
