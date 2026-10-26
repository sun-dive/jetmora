// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// A TEST RUN'S TEMP FOLDER, and the processes the run starts, gone however the run ends. Node only. ⚠ /tmp can be
// RAM (tmpfs), so a folder left behind is memory lost until a reboot.
//
//   const run = runFolder('writer')      first clears what a dead run of the same test left, then makes the folder
//   run.dir                              the folder, /tmp/jetmora-writer-XXXXXX
//   run.start(command, args, options)    spawn, in a process group of its own, the group noted in the folder
//   run.stop(child)                      the child's whole group killed
//
// On exit, and on SIGINT, SIGTERM or SIGHUP (exit code 130), every group still running is killed and the folder removed.
// A run killed outright (SIGKILL) runs no handler. So each folder holds a note of who made it: the pid and the moment that
// process started. The next run of the same test reads the note; when that process has gone (or the pid now belongs to
// a process started at another moment), it kills each group the dead run noted whose command line still names the
// folder, so a pid since given to something else is never touched, and removes the folder.
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawn } from 'node:child_process'
import { appendFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'

const NOTE = 'made-by.json', GROUPS = 'groups'
/** Where every run's folder is made: the system's temp folder */
const RUNS = tmpdir()

/** The moment a process started: field 22 of /proc/<pid>/stat, clock ticks since boot. null when it cannot be read. */
function startOf(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8')
    // the name in field 2 may hold spaces, so fields are counted from the ')' that closes it: field 3 is the first after
    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[22 - 3] ?? null
  } catch { return null }
}

/** Whether the process a note names still runs: the same pid, started at the same moment. */
function stillRunning(note) {
  if (!Number.isInteger(note?.pid) || note.pid <= 0) return false
  const start = startOf(note.pid)
  if (start !== null) return note.start === null || start === note.start
  try { process.kill(note.pid, 0); return true } catch (e) { return e.code === 'EPERM' }
}

/** Clear every folder a dead run of this test left: its noted groups first, then the folder. */
function clearDead(tag) {
  const head = `jetmora-${tag}-`
  for (const name of readdirSync(RUNS).filter(n => n.startsWith(head))) {
    const dir = join(RUNS, name)
    let note = null
    try { note = JSON.parse(readFileSync(join(dir, NOTE), 'utf8')) } catch {}
    if (note !== null && stillRunning(note)) continue
    // no note: a run that died the moment it began, or one being made right now. Only an old one is cleared.
    if (note === null) { try { if (Date.now() - statSync(dir).mtimeMs < 60_000) continue } catch { continue } }
    let groups = ''
    try { groups = readFileSync(join(dir, GROUPS), 'utf8') } catch {}
    for (const g of groups.split('\n').map(Number).filter(n => Number.isInteger(n) && n > 0)) {
      let command = ''
      try { command = readFileSync(`/proc/${g}/cmdline`, 'utf8') } catch {}
      if (command.includes(dir)) try { process.kill(-g, 'SIGKILL') } catch {}
    }
    rmSync(dir, { recursive: true, force: true })
  }
}

/**
 * @param {string} tag  names the test: its folders are jetmora-<tag>-*
 * @returns {{dir: string, start: Function, stop: Function}}
 */
export function runFolder(tag) {
  clearDead(tag)
  const dir = mkdtempSync(join(RUNS, `jetmora-${tag}-`))
  writeFileSync(join(dir, NOTE), JSON.stringify({ pid: process.pid, start: startOf(process.pid) }))
  const live = new Map()
  const stop = child => {
    try { process.kill(-child.pid, 'SIGKILL') } catch { try { child.kill('SIGKILL') } catch {} }
    live.delete(child.pid)
  }
  // exit handlers run synchronously: the groups are killed and the folder removed before the process is gone
  process.once('exit', () => { [...live.values()].forEach(stop); rmSync(dir, { recursive: true, force: true }) })
  ;['SIGHUP', 'SIGINT', 'SIGTERM'].forEach(signal => process.once(signal, () => process.exit(130)))
  const start = (command, args, options = {}) => {
    const child = spawn(command, args, { ...options, detached: true })
    if (child.pid) {
      live.set(child.pid, child)
      child.on('exit', () => live.delete(child.pid))
      appendFileSync(join(dir, GROUPS), `${child.pid}\n`)
    }
    return child
  }
  return { dir, start, stop }
}
