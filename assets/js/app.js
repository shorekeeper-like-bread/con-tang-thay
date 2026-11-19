/* ==========================================================================
   TRI ÂN THẦY HỒ HUỲNH PHONG · 20/11/2026
   Pure-JS SHA-256 + XOR Stream Decrypt + Web Audio Synth + Interactive Flow
   ========================================================================== */
(function () {
  "use strict";

  const CFG = window.CONFIG || {};
  try {
    delete window.CONFIG;
  } catch (_) {
    window.CONFIG = undefined;
  }

  /* ------------------------------------------------------------------------
     1. TIỆN ÍCH CHUẨN HÓA, SHA-256 THUẦN JS & GIẢI MÃ XOR (CHẠY CẢ file://)
     ------------------------------------------------------------------------ */
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256Bytes(str) {
    const raw = new TextEncoder().encode(String(str));
    const bitLen = raw.length * 8;
    const padLen = Math.ceil((raw.length + 9) / 64) * 64;
    const msg = new Uint8Array(padLen);
    msg.set(raw);
    msg[raw.length] = 0x80;
    const view = new DataView(msg.buffer);
    view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(padLen - 4, bitLen >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
        const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((val, idx) => outView.setUint32(idx * 4, val, false));
    return out;
  }

  function sha256(str) {
    const bytes = sha256Bytes(str);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
    return hex;
  }

  function dec(hexStr, keyStr) {
    const clean = String(hexStr || "").trim();
    const out = new Uint8Array(clean.length / 2);
    let curBlock = -1;
    let ks = null;
    for (let i = 0; i < out.length; i++) {
      const b = Math.floor(i / 32);
      if (b !== curBlock) {
        curBlock = b;
        ks = sha256Bytes(`${keyStr}|${b}`);
      }
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16) ^ ks[i % 32];
    }
    return new TextDecoder().decode(out);
  }

  function normCommon(s) {
    return String(s || "")
      .replace(/[đĐ]/g, "d")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");
  }

  function normPhrase(s) {
    return String(s || "")
      .replace(/[đĐ]/g, "d")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const $ = (id) => document.getElementById(id);

  function burstConfetti(power = 1) {
    if (typeof window.confetti !== "function") return;
    const colors = ["#d4af37", "#f6d878", "#38bdf8", "#ffffff", "#ef4444"];
    window.confetti({
      particleCount: Math.round(75 * power),
      spread: 75,
      origin: { y: 0.65 },
      colors,
    });
    if (power >= 1.2) {
      setTimeout(() => {
        window.confetti({ particleCount: 55, angle: 60, spread: 60, origin: { x: 0, y: 0.7 }, colors });
        window.confetti({ particleCount: 55, angle: 120, spread: 60, origin: { x: 1, y: 0.7 }, colors });
      }, 220);
    }
  }

  /* ------------------------------------------------------------------------
     2. MODULE ÂM THANH WEB AUDIO (HACK 118 BPM + SOFT CEREMONIAL + IPHONE)
     ------------------------------------------------------------------------ */
  const music = (() => {
    let ctx = null;
    let master = null;
    let timer = null;
    let mode = null; // "hack" | "soft"
    let step = 0;
    let muted = false;
    let noiseBuf = null;

    // Am - F - C - G (MIDI notes)
    const chords = [
      { bass: 45, notes: [57, 60, 64, 69] }, // Am
      { bass: 41, notes: [53, 57, 60, 65] }, // F
      { bass: 48, notes: [60, 64, 67, 72] }, // C
      { bass: 43, notes: [55, 59, 62, 67] }, // G
    ];
    const mtof = (m) => 440 * Math.pow(2, (m - 69) / 12);

    function ensureNoise() {
      if (noiseBuf || !ctx) return;
      const len = ctx.sampleRate * 0.4;
      noiseBuf = ctx.createBuffer(1, len, ctx.sampleRate);
      const data = noiseBuf.getChannelData(0);
      for (let i = 0; i < len; i++) data[i] = Math.random() * 2 - 1;
    }

    function unlock() {
      try {
        if (navigator.audioSession) {
          navigator.audioSession.type = "playback";
        }
      } catch (_) {}
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return false;
      if (!ctx) {
        ctx = new AC();
        master = ctx.createGain();
        master.gain.value = muted ? 0 : 0.34;
        master.connect(ctx.destination);
        ensureNoise();
      }
      if (ctx.state === "suspended") {
        ctx.resume().catch(() => {});
      }
      return true;
    }

    function playKick(t) {
      const osc = ctx.createOscillator();
      const g = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(132, t);
      osc.frequency.exponentialRampToValueAtTime(42, t + 0.14);
      g.gain.setValueAtTime(0.65, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.16);
      osc.connect(g).connect(master);
      osc.start(t);
      osc.stop(t + 0.17);
    }

    function playHat(t, open = false) {
      const src = ctx.createBufferSource();
      src.buffer = noiseBuf;
      const hp = ctx.createBiquadFilter();
      hp.type = "highpass";
      hp.frequency.value = 7200;
      const g = ctx.createGain();
      g.gain.setValueAtTime(open ? 0.13 : 0.08, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + (open ? 0.12 : 0.045));
      src.connect(hp).connect(g).connect(master);
      src.start(t);
      src.stop(t + (open ? 0.13 : 0.05));
    }

    function playSnare(t) {
      const src = ctx.createBufferSource();
      src.buffer = noiseBuf;
      const bp = ctx.createBiquadFilter();
      bp.type = "bandpass";
      bp.frequency.value = 1800;
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.28, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.14);
      src.connect(bp).connect(g).connect(master);
      src.start(t);
      src.stop(t + 0.15);
    }

    function playBass(t, midi, dur) {
      const osc = ctx.createOscillator();
      const flt = ctx.createBiquadFilter();
      const g = ctx.createGain();
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(mtof(midi), t);
      flt.type = "lowpass";
      flt.frequency.setValueAtTime(340, t);
      flt.frequency.exponentialRampToValueAtTime(150, t + dur);
      g.gain.setValueAtTime(0.24, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + dur);
      osc.connect(flt).connect(g).connect(master);
      osc.start(t);
      osc.stop(t + dur + 0.02);
    }

    function playArp(t, midi, dur, softMode = false, sweep = 1800) {
      const osc = ctx.createOscillator();
      const flt = ctx.createBiquadFilter();
      const g = ctx.createGain();
      osc.type = softMode ? "sine" : "square";
      osc.frequency.setValueAtTime(mtof(midi), t);
      flt.type = "lowpass";
      flt.Q.value = softMode ? 1 : 4;
      flt.frequency.setValueAtTime(softMode ? 1200 : sweep, t);
      flt.frequency.exponentialRampToValueAtTime(softMode ? 650 : 420, t + dur);
      g.gain.setValueAtTime(0.001, t);
      g.gain.linearRampToValueAtTime(softMode ? 0.13 : 0.09, t + 0.015);
      g.gain.exponentialRampToValueAtTime(0.001, t + dur);
      osc.connect(flt).connect(g).connect(master);
      osc.start(t);
      osc.stop(t + dur + 0.02);
    }

    function playPad(t, chordNotes, dur) {
      chordNotes.slice(0, 3).forEach((m) => {
        const osc = ctx.createOscillator();
        const g = ctx.createGain();
        osc.type = "triangle";
        osc.frequency.setValueAtTime(mtof(m), t);
        g.gain.setValueAtTime(0.001, t);
        g.gain.linearRampToValueAtTime(0.06, t + 0.35);
        g.gain.exponentialRampToValueAtTime(0.001, t + dur);
        osc.connect(g).connect(master);
        osc.start(t);
        osc.stop(t + dur + 0.05);
      });
    }

    function tickHack() {
      if (!ctx || muted) return;
      const t = ctx.currentTime + 0.02;
      const bar = Math.floor(step / 16) % 4;
      const pos = step % 16;
      const chord = chords[bar];

      if (pos % 4 === 0) playKick(t);
      if (pos === 4 || pos === 12) playSnare(t);
      if (pos % 2 === 1) playHat(t, pos === 7 || pos === 15);
      if (pos % 2 === 0) playBass(t, chord.bass, 0.2);

      const arpNote = chord.notes[pos % chord.notes.length] + (pos >= 8 ? 12 : 0);
      const sweep = 900 + Math.sin(step * 0.25) * 700 + 700;
      playArp(t, arpNote, 0.13, false, sweep);
      step++;
    }

    function tickSoft() {
      if (!ctx || muted) return;
      const t = ctx.currentTime + 0.02;
      const bar = Math.floor(step / 8) % 4;
      const pos = step % 8;
      const chord = chords[bar];
      if (pos === 0) playPad(t, chord.notes, 3.0);
      const n = chord.notes[pos % chord.notes.length] + (pos >= 4 ? 12 : 0);
      playArp(t, n, 0.45, true);
      step++;
    }

    function startLoop(newMode, intervalMs, fn) {
      if (mode === newMode && timer) return;
      clearInterval(timer);
      mode = newMode;
      step = 0;
      fn();
      timer = setInterval(fn, intervalMs);
    }

    function hack() {
      if (!unlock()) return;
      // 118 BPM -> 16th note = 60000 / 118 / 4 ≈ 127ms
      startLoop("hack", Math.round(60000 / 118 / 4), tickHack);
    }

    function soft() {
      if (!unlock()) return;
      // 76 BPM -> 8th note ≈ 394ms
      startLoop("soft", 394, tickSoft);
    }

    function note(val, maxVal = 14) {
      if (muted || !unlock() || !ctx) return;
      const t = ctx.currentTime + 0.01;
      const freq = 240 + (val / maxVal) * 520;
      const osc = ctx.createOscillator();
      const g = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(freq, t);
      g.gain.setValueAtTime(0.08, t);
      g.gain.exponentialRampToValueAtTime(0.001, t + 0.08);
      osc.connect(g).connect(master);
      osc.start(t);
      osc.stop(t + 0.09);
    }

    function toggle() {
      muted = !muted;
      if (master && ctx) {
        master.gain.setTargetAtTime(muted ? 0 : 0.34, ctx.currentTime, 0.04);
      }
      const btn = $("music-toggle");
      if (btn) {
        btn.classList.toggle("muted", muted);
        btn.textContent = "♪";
      }
      if (!muted && mode === "soft" && !timer) soft();
      if (!muted && mode === "hack" && !timer) hack();
    }

    return { unlock, hack, soft, note, toggle, getMode: () => mode };
  })();

  /* ------------------------------------------------------------------------
     3. MÀN 1 & MÀN 2: GATE (10 LỚP TƯỜNG LỬA + ROOT) + LOCK + HACKER TERMINAL
     ------------------------------------------------------------------------ */
  const gate = (() => {
    const gateLog = $("gate-log");
    const fwPanel = $("fw-panel");
    const fwCells = $("fw-cells");
    const fwCount = $("fw-count");
    const fwSubject = $("fw-subject");
    const fwQ = $("fw-q");
    const fwOpts = $("fw-opts");
    const fwFeedback = $("fw-feedback");
    const fwQBox = $("fw-question-box");
    const rootPanel = $("root-panel");
    const rootForm = $("root-form");
    const rootPw = $("root-pw");
    const rootStatus = $("root-status");
    const rootHints = $("root-hints");

    let currentLayer = 0;
    let firewallLocked = false;
    let firewallPassed = false;
    let fwChain = "fw0";
    let unlockedRootHints = [];
    let rootAttempts = 0;
    const shownHintThresholds = new Set();
    let MAIN = null;
    let onMainEnter = null;

    let fastMode = false;
    let matrixTimer = null;

    function appendLog(container, text, cls = "") {
      const div = document.createElement("div");
      div.className = `t-line ${cls}`.trim();
      div.textContent = text;
      container.appendChild(div);
      container.scrollTop = container.scrollHeight;
      return div;
    }

    async function type(container, text, cls = "", speed = 16) {
      const div = appendLog(container, "", cls);
      for (let i = 0; i < text.length; i++) {
        div.textContent += text[i];
        container.scrollTop = container.scrollHeight;
        await sleep(fastMode ? Math.max(2, Math.floor(speed / 5)) : speed);
      }
      return div;
    }

    async function dump(container, lines, cls = "", delay = 70) {
      for (const line of lines) {
        appendLog(container, line, cls);
        await sleep(fastMode ? Math.max(12, Math.floor(delay / 4)) : delay);
      }
    }

    async function spin(container, label, ms = 750) {
      const frames = ["|", "/", "-", "\\"];
      const line = appendLog(container, `${label} ${frames[0]}`, "t-warn");
      const start = Date.now();
      let idx = 0;
      while (Date.now() - start < (fastMode ? ms / 3 : ms)) {
        idx = (idx + 1) % frames.length;
        line.textContent = `${label} ${frames[idx]}`;
        await sleep(75);
      }
      line.textContent = `${label} [OK]`;
      line.className = "t-line t-ok";
    }

    async function hexdump(container) {
      const lines = [
        "00000000: 5452 492d 414e 2032 302f 3131 2056 4141  TRI-AN 20/11 VAA",
        "00000010: 484f 2048 5559 4e48 2050 484f 4e47 0a00  HO HUYNH PHONG..",
        "00000020: 4353 444c 207c 2043 5444 4c20 7c20 414e  CSDL | CTDL | AN",
      ];
      await dump(container, lines, "t-line", 65);
    }

    async function bar() {
      const box = $("hack-progress");
      const fill = $("hack-bar-fill");
      const pct = $("hack-bar-pct");
      box.classList.remove("hidden");
      for (let p = 0; p <= 100; p += 4) {
        fill.style.width = `${p}%`;
        pct.textContent = `${p}%`;
        await sleep(fastMode ? 12 : 42);
      }
    }

    function renderCells() {
      fwCells.innerHTML = "";
      for (let i = 0; i < 10; i++) {
        const c = document.createElement("div");
        c.className = "fw-cell";
        if (i < currentLayer) c.classList.add("done");
        else if (i === currentLayer) c.classList.add("active");
        fwCells.appendChild(c);
      }
      fwCount.textContent = `${currentLayer}/10`;
    }

    function ask(idx) {
      currentLayer = idx;
      firewallLocked = false;
      renderCells();
      const item = CFG.firewall[idx];
      fwSubject.textContent = `LỚP ${String(idx + 1).padStart(2, "0")}/10 · ${item.subject}`;
      fwQ.textContent = item.q;
      fwFeedback.textContent = "";
      fwFeedback.className = "fw-feedback";
      fwOpts.innerHTML = "";

      const keys = ["A", "B", "C", "D"];
      item.opts.forEach((optText, optIdx) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "fw-opt";
        btn.innerHTML = `<span class="fw-key">[${keys[optIdx]}]</span><span></span>`;
        btn.querySelector("span:last-child").textContent = optText;
        btn.addEventListener("click", () => handleAnswer(idx, optIdx, btn));
        fwOpts.appendChild(btn);
      });
    }

    async function handleAnswer(idx, optIdx, btnEl) {
      if (firewallLocked || firewallPassed) return;
      const item = CFG.firewall[idx];
      const stepKey = sha256(`${fwChain}|${idx}|${optIdx}`);
      if (sha256(`h|${stepKey}`) === item.h) {
        firewallLocked = true;
        btnEl.classList.add("correct");
        fwOpts.querySelectorAll("button").forEach((b) => (b.disabled = true));
        const okText = dec(item.okEnc, `ok|${stepKey}`);
        fwChain = stepKey;
        fwFeedback.textContent = `✓ ${okText}`;
        fwFeedback.className = "fw-feedback ok";
        appendLog(gateLog, `[FW-${String(idx + 1).padStart(2, "0")}] VERIFIED: ${okText}`, "t-ok");

        await sleep(900);
        if (idx + 1 < CFG.firewall.length) {
          ask(idx + 1);
        } else {
          currentLayer = 10;
          renderCells();
          firewallPassed = true;
          fwPanel.classList.add("hidden");
          askRoot();
        }
      } else {
        btnEl.classList.add("wrong");
        fwQBox.classList.remove("shake");
        void fwQBox.offsetWidth;
        fwQBox.classList.add("shake");
        fwFeedback.textContent = `✕ ACCESS DENIED · ${item.hint}`;
        fwFeedback.className = "fw-feedback err";
      }
    }

    function askRoot() {
      try {
        unlockedRootHints = JSON.parse(dec(CFG.rootHintsEnc, `rh|${fwChain}`));
      } catch (_) {
        unlockedRootHints = [];
      }
      appendLog(gateLog, "[+] 10/10 Firewall layers cleared. Escalating privilege...", "t-warn");
      rootPanel.classList.remove("hidden");
      setTimeout(() => rootPw.focus(), 60);
    }

    function showLockScreen() {
      $("gate").classList.remove("active");
      $("lock-screen").classList.add("active");
      music.hack();
      startMatrix();
    }

    function startMatrix() {
      const cv = $("matrix-cv");
      const c = cv.getContext("2d");
      const resize = () => {
        cv.width = window.innerWidth;
        cv.height = window.innerHeight;
      };
      resize();
      window.addEventListener("resize", resize);

      const chars = "0123456789ABCDEFVAA2011SQLBFSDATASEC";
      const fontSize = 15;
      let drops = Array.from({ length: Math.ceil(window.innerWidth / fontSize) }, () => Math.random() * 40);

      clearInterval(matrixTimer);
      matrixTimer = setInterval(() => {
        if (!$("lock-screen").classList.contains("active")) return;
        const cols = Math.ceil(cv.width / fontSize);
        if (drops.length !== cols) {
          drops = Array.from({ length: cols }, (_, i) => drops[i] || 1);
        }
        c.fillStyle = "rgba(3, 7, 17, 0.09)";
        c.fillRect(0, 0, cv.width, cv.height);
        c.font = `${fontSize}px JetBrains Mono, monospace`;
        for (let i = 0; i < cols; i++) {
          const ch = chars[Math.floor(Math.random() * chars.length)];
          c.fillStyle = Math.random() > 0.85 ? "#f6d878" : "#22c55e";
          c.fillText(ch, i * fontSize, drops[i] * fontSize);
          if (drops[i] * fontSize > cv.height && Math.random() > 0.975) drops[i] = 0;
          drops[i]++;
        }
      }, 45);
    }

    async function runHackSequence() {
      if (!MAIN) return;
      clearInterval(matrixTimer);
      $("lock-screen").classList.remove("active");
      $("hack-screen").classList.add("active");
      music.hack();

      const hlog = $("hack-log");
      hlog.innerHTML = "";
      $("fp-box").classList.add("hidden");
      $("hack-progress").classList.add("hidden");
      fastMode = false;
      $("btn-speed").classList.remove("fast");

      await type(hlog, "root@vaa-mainframe:~# whoami", "t-cmd");
      await dump(hlog, ["root (uid=0, gid=0 · Quyền tối cao Khoa CNTT – VAA)"], "t-ok");

      await type(hlog, "root@vaa-mainframe:~# nmap -sV -p 20,11,2026 vaa-tribute.local", "t-cmd");
      await dump(hlog, [
        "PORT     STATE SERVICE    VERSION",
        "20/tcp   open  gratitude  Teacher-Day-20.11",
        "11/tcp   open  knowledge  DB + DSA + InfoSec",
        "2026/tcp open  vault-tls  AES-256-GCM",
      ]);

      await type(hlog, 'root@vaa-mainframe:~# osint --target "Hồ Huỳnh Phong"', "t-cmd");
      await spin(hlog, "[*] Đang đối chiếu hồ sơ giảng viên Khoa CNTT · VAA", 650);

      await type(hlog, "root@vaa-mainframe:~# cat target_profile.txt", "t-cmd");
      const dossier = document.createElement("div");
      dossier.className = "t-dossier";
      dossier.textContent = [
        "HỒ SƠ MỤC TIÊU: THẦY HỒ HUỲNH PHONG",
        "Đơn vị: Khoa CNTT · Học viện Hàng không Việt Nam (VAA)",
        `Giảng dạy: ${(MAIN.subjects || []).join(" · ")}`,
      ].join("\n");
      hlog.appendChild(dossier);
      hlog.scrollTop = hlog.scrollHeight;
      await sleep(fastMode ? 120 : 420);

      await type(hlog, "root@vaa-mainframe:~# mysql -u root -p vaa_db", "t-cmd");
      const sqlBox = document.createElement("div");
      sqlBox.className = "t-sql";
      sqlBox.textContent = [
        "SELECT ho_ten, don_vi, uy_tin FROM giang_vien WHERE ten LIKE '%Phong%' \\G",
        "*************************** 1. row ***************************",
        "ho_ten: Hồ Huỳnh Phong",
        "don_vi: Khoa CNTT · Học viện Hàng không Việt Nam (VAA)",
        "uy_tin: 100% Tận tâm & Chuẩn mực",
        "START TRANSACTION;",
        "UPDATE tri_an SET trang_thai = 'SAN_SANG_MO_KET', ngay = '2026-11-20';",
        "COMMIT;",
      ].join("\n");
      hlog.appendChild(sqlBox);
      hlog.scrollTop = hlog.scrollHeight;
      await sleep(fastMode ? 140 : 480);

      await type(hlog, "root@vaa-mainframe:~# ./exploit --unlock-vault --biometric", "t-cmd");
      $("fp-box").classList.remove("hidden");
      await spin(hlog, "[*] Quét khóa sinh trắc học & chữ ký số", 700);

      await type(hlog, "root@vaa-mainframe:~# xxd -l 48 /dev/vault/tri_an.enc", "t-cmd");
      await hexdump(hlog);

      await type(hlog, "root@vaa-mainframe:~# openssl enc -d -aes-256-cbc -in tri_an.enc", "t-cmd");
      await bar();

      const granted = appendLog(hlog, ">>> ACCESS GRANTED · MỞ KÉT SẮT TRI ÂN! <<<", "t-ok");
      granted.style.fontSize = "1.05rem";
      granted.style.fontWeight = "700";
      $("hack-screen").querySelector(".hack-window").classList.add("glitch");
      await sleep(fastMode ? 320 : 850);

      openVault();
    }

    async function openVault() {
      if (!MAIN) return;
      $("hack-screen").classList.remove("active");
      const vault = $("vault");
      vault.classList.remove("unlocking", "open");
      vault.classList.add("active");

      await sleep(220);
      vault.classList.add("unlocking");
      await sleep(850);
      vault.classList.add("open");

      $("main").classList.remove("hidden");
      music.soft();
      burstConfetti(1.4);

      if (typeof onMainEnter === "function") {
        onMainEnter();
      }
      await sleep(1150);
      vault.classList.remove("active", "unlocking", "open");
    }

    function firewall() {
      if (!Array.isArray(CFG.firewall) || !CFG.firewall.length) return;
      fwPanel.classList.remove("hidden");
      ask(0);

      window.addEventListener("keydown", (e) => {
        if (!$("gate").classList.contains("active") || firewallPassed) return;
        const tag = (e.target && e.target.tagName) || "";
        if (tag === "INPUT" || tag === "TEXTAREA") return;
        const k = e.key.toUpperCase();
        const map = { A: 0, B: 1, C: 2, D: 3, "1": 0, "2": 1, "3": 2, "4": 3 };
        if (k in map) {
          const btns = fwOpts.querySelectorAll("button");
          if (btns[map[k]]) btns[map[k]].click();
        }
      });
    }

    rootForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const pwNorm = normCommon(rootPw.value);
      const hash = sha256(`${fwChain}|pw|${pwNorm}`);
      if (hash === CFG.accessHash) {
        if (!MAIN) {
          const masterKey = sha256(`${fwChain}|master|${pwNorm}`);
          MAIN = JSON.parse(dec(CFG.mainEnc, masterKey));
          onMainEnter = initMainSections(MAIN, showLockScreen);
        }
        rootStatus.textContent = "IDENTITY VERIFIED · CHÀO MỪNG THẦY!";
        rootStatus.className = "root-status ok";
        appendLog(gateLog, "[+] IDENTITY VERIFIED -> Chuyển vào cổng giải mã.", "t-ok");
        await sleep(650);
        showLockScreen();
      } else {
        rootAttempts++;
        rootStatus.textContent = `ACCESS DENIED (Sai ${rootAttempts} lần)`;
        rootStatus.className = "root-status";
        rootForm.classList.remove("shake");
        void rootForm.offsetWidth;
        rootForm.classList.add("shake");
        rootPw.value = "";
        rootPw.focus();

        (unlockedRootHints || []).forEach((h) => {
          if (rootAttempts >= h.after && !shownHintThresholds.has(h.after)) {
            shownHintThresholds.add(h.after);
            const div = document.createElement("div");
            div.className = "root-hint-item";
            div.textContent = h.text;
            rootHints.appendChild(div);
          }
        });
      }
    });

    $("btn-decrypt").addEventListener("click", runHackSequence);
    $("btn-speed").addEventListener("click", () => {
      fastMode = !fastMode;
      $("btn-speed").classList.toggle("fast", fastMode);
      $("btn-speed").textContent = fastMode ? "Đang tăng tốc »»" : "Tăng tốc »";
    });

    // Unlock audio & start hacker beat on first user interaction anywhere in gate/lock
    const firstGesture = () => {
      music.unlock();
      if (!music.getMode() && ($("lock-screen").classList.contains("active") || $("hack-screen").classList.contains("active"))) {
        music.hack();
      }
      window.removeEventListener("pointerdown", firstGesture);
      window.removeEventListener("keydown", firstGesture);
    };
    window.addEventListener("pointerdown", firstGesture, { passive: true });
    window.addEventListener("keydown", firstGesture, { passive: true });

    async function boot() {
      await dump(gateLog, [
        "[BOOT] VAA-CNTT Secure Bootloader v20.11 ... [OK]",
        "[INIT] Loading modules: Database / Algorithms / InfoSec ... [OK]",
        "[SEC ] 10-Layer Academic Firewall armed. Verify identity to continue.",
      ], "t-ok", 140);
      firewall();
    }

    return { boot, showLockScreen };
  })();

  /* ------------------------------------------------------------------------
     4. TRANG CHÍNH: HERO, PROFILE, 9 THẺ 3D, GIẢI THUẬT, CTF, BINARY, CASES
     ------------------------------------------------------------------------ */
  function initMainSections(MAIN, onReplay) {
    let heroStarted = false;

    // 4.1 Hero animations
    async function playHero() {
      if (heroStarted) return;
      heroStarted = true;

      const nameEl = $("hero-name");
      const titleEl = $("hero-title");
      const schoolEl = $("hero-school");
      const chipsEl = $("hero-subjects");

      const fullName = `Thầy ${MAIN.teacher || "Hồ Huỳnh Phong"}`;
      nameEl.textContent = "";
      for (let i = 0; i < fullName.length; i++) {
        nameEl.textContent += fullName[i];
        await sleep(55);
      }

      // Scramble-decrypt title (cùng độ dài từ, giữ nguyên khoảng trắng để tránh nhảy dòng)
      const targetTitle = MAIN.teacherTitle || "Giảng viên Khoa Công nghệ Thông tin";
      schoolEl.textContent = MAIN.school || "";
      const pool = "abcdefghijklmnopqrstuvwxyz0123456789*";
      for (let step = 0; step <= targetTitle.length; step++) {
        let out = "";
        for (let i = 0; i < targetTitle.length; i++) {
          if (i < step || targetTitle[i] === " ") out += targetTitle[i];
          else out += pool[Math.floor(Math.random() * pool.length)];
        }
        titleEl.textContent = out;
        await sleep(22);
      }
      titleEl.textContent = targetTitle;

      chipsEl.innerHTML = "";
      (MAIN.subjects || []).forEach((subj, i) => {
        const chip = document.createElement("span");
        chip.className = "subject-chip";
        chip.textContent = subj;
        chipsEl.appendChild(chip);
        setTimeout(() => chip.classList.add("show"), 120 + i * 180);
      });
    }

    // 4.2 Hồ sơ mật – con dấu "ĐÃ XÁC MINH"
    $("profile-subjects").textContent = (MAIN.subjects || []).join(" · ");
    const stampObs = new IntersectionObserver(
      (entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting) {
            $("profile-stamp").classList.add("stamped");
            stampObs.disconnect();
          }
        });
      },
      { threshold: 0.35 }
    );
    stampObs.observe($("profile"));

    // 4.3 9 Thẻ lời chúc 3D
    const wishesGrid = $("wishes-grid");
    wishesGrid.innerHTML = "";
    (MAIN.wishes || []).forEach((w) => {
      const card = document.createElement("div");
      card.className = "wish-card";
      card.tabIndex = 0;
      card.setAttribute("role", "button");
      card.setAttribute("aria-label", `Lật thẻ ${w.title}`);
      card.innerHTML = `
        <div class="wish-inner">
          <div class="wish-face wish-front">
            <span class="wish-tag"></span>
            <span class="wish-title"></span>
            <span class="wish-hint">Chạm để mở lời chúc ↻</span>
          </div>
          <div class="wish-face wish-back">
            <span class="wish-tag"></span>
            <span class="wish-body"></span>
          </div>
        </div>
      `;
      card.querySelector(".wish-front .wish-tag").textContent = w.tag;
      card.querySelector(".wish-front .wish-title").textContent = w.title;
      card.querySelector(".wish-back .wish-tag").textContent = w.title;
      card.querySelector(".wish-back .wish-body").textContent = w.body;
      const flip = () => card.classList.toggle("flipped");
      card.addEventListener("click", flip);
      card.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          flip();
        }
      });
      wishesGrid.appendChild(card);
    });

    // 4.4 Giải thuật tri ân (14 cột)
    const rawChars = String(MAIN.sortMessage || "CẢM ƠN THẦY PHONG").replace(/\s+/g, "").split("");
    const barsEl = $("algo-bars");
    const cmpEl = $("algo-cmp");
    const swpEl = $("algo-swp");
    const bigOEl = $("algo-bigo");
    const resEl = $("algo-result");

    let curAlgo = "quick";
    let items = [];
    let runToken = 0;
    let algoStarted = false;

    const ALGO_DELAY = { quick: 420, bubble: 170, insertion: 240 };
    const ALGO_BIGO = { quick: "O(n log n)", bubble: "O(n²)", insertion: "O(n²)" };

    function makeShuffledItems() {
      const arr = rawChars.map((ch, idx) => ({ ch, rank: idx + 1 }));
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      // Bảo đảm không trùng thứ tự đã sắp xếp sẵn
      if (arr.every((it, idx) => it.rank === idx + 1) && arr.length > 1) {
        [arr[0], arr[1]] = [arr[1], arr[0]];
      }
      return arr;
    }

    function drawBars(hl = {}) {
      barsEl.innerHTML = "";
      const n = items.length || 14;
      items.forEach((it, idx) => {
        const bar = document.createElement("div");
        bar.className = "algo-bar";
        if (hl.sorted) bar.classList.add("sorted");
        else if (hl.swp && hl.swp.includes(idx)) bar.classList.add("swp");
        else if (hl.cmp && hl.cmp.includes(idx)) bar.classList.add("cmp");
        bar.style.height = `${Math.round(22 + (it.rank / n) * 76)}%`;
        bar.textContent = it.ch;
        barsEl.appendChild(bar);
      });
    }

    async function runSort() {
      const myToken = ++runToken;
      items = makeShuffledItems();
      let cmps = 0, swps = 0;
      cmpEl.textContent = "0";
      swpEl.textContent = "0";
      bigOEl.textContent = ALGO_BIGO[curAlgo];
      resEl.textContent = "Đang chạy thuật toán...";
      drawBars();

      const delay = ALGO_DELAY[curAlgo];
      const alive = () => myToken === runToken;

      const touch = async (i, j, isSwap) => {
        if (!alive()) return false;
        if (isSwap) {
          swps++;
          swpEl.textContent = String(swps);
          [items[i], items[j]] = [items[j], items[i]];
          drawBars({ swp: [i, j] });
          music.note(items[j].rank, items.length);
        } else {
          cmps++;
          cmpEl.textContent = String(cmps);
          drawBars({ cmp: [i, j] });
          music.note(items[i].rank, items.length);
        }
        await sleep(delay);
        return alive();
      };

      if (curAlgo === "bubble") {
        for (let i = 0; i < items.length; i++) {
          for (let j = 0; j < items.length - i - 1; j++) {
            if (!(await touch(j, j + 1, false))) return;
            if (items[j].rank > items[j + 1].rank) {
              if (!(await touch(j, j + 1, true))) return;
            }
          }
        }
      } else if (curAlgo === "insertion") {
        for (let i = 1; i < items.length; i++) {
          let j = i;
          while (j > 0) {
            if (!(await touch(j - 1, j, false))) return;
            if (items[j - 1].rank > items[j].rank) {
              if (!(await touch(j - 1, j, true))) return;
              j--;
            } else {
              break;
            }
          }
        }
      } else {
        async function qs(lo, hi) {
          if (!alive() || lo >= hi) return;
          const pivot = items[hi].rank;
          let i = lo;
          for (let j = lo; j < hi; j++) {
            if (!(await touch(j, hi, false))) return;
            if (items[j].rank < pivot) {
              if (i !== j && !(await touch(i, j, true))) return;
              i++;
            }
          }
          if (i !== hi && !(await touch(i, hi, true))) return;
          await qs(lo, i - 1);
          await qs(i + 1, hi);
        }
        await qs(0, items.length - 1);
      }

      if (!alive()) return;
      drawBars({ sorted: true });
      resEl.textContent = `✨ ${MAIN.sortMessage || "CẢM ƠN THẦY PHONG"} ✨`;
      burstConfetti(1);
    }

    items = makeShuffledItems();
    drawBars();

    document.querySelectorAll(".algo-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".algo-tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        curAlgo = tab.dataset.alg;
        algoStarted = true;
        runSort();
      });
    });
    $("algo-replay").addEventListener("click", () => {
      algoStarted = true;
      runSort();
    });

    const algoObs = new IntersectionObserver(
      (entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting && !algoStarted) {
            algoStarted = true;
            runSort();
            algoObs.disconnect();
          }
        });
      },
      { threshold: 0.3 }
    );
    algoObs.observe($("algo"));

    // 4.5 Hộp bí mật – CTF Senior
    const ctf = MAIN.ctfChallenge || {};
    $("ctf-title").textContent = ctf.title || "CTF · SENIOR WEB SECURITY";
    $("ctf-prompt").textContent = ctf.prompt || "";
    $("ctf-raw").textContent = ctf.rawRequest || "";
    $("ctf-question").textContent = ctf.question || "";
    if (ctf.placeholder) $("ctf-input").placeholder = ctf.placeholder;
    console.info(
      "%c[CTF SENIOR HINT] Kiểm tra sự bất đồng bộ giữa header độ dài gói tin ở tầng Front-end Proxy và header phân mảnh ở tầng Back-end Server.",
      "color:#f6d878;font-weight:bold;font-size:12px;"
    );

    $("ctf-hint-btn").addEventListener("click", () => {
      const box = $("ctf-hint-box");
      box.textContent = MAIN.ctfHint || "";
      box.classList.toggle("hidden");
    });

    $("ctf-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const val = normCommon($("ctf-input").value);
      const st = $("ctf-status");
      if (sha256(`ctf|${val}`) === MAIN.ctfHash) {
        const secret = dec(MAIN.secretEnc, `ctf|${val}`);
        st.textContent = `✓ Flag chính xác! ${secret}`;
        st.className = "status-box ok";
        burstConfetti(1.1);
      } else {
        st.textContent = "✕ Flag chưa đúng. Xem kỹ thứ tự xử lý Content-Length và Transfer-Encoding (hoặc mở Console F12 để xem gợi ý).";
        st.className = "status-box err";
      }
    });

    // 4.6 Phong thư tay
    const letter = MAIN.letter || {};
    $("letter-salutation").textContent = letter.salutation || "";
    const lBody = $("letter-body");
    lBody.innerHTML = "";
    (letter.paragraphs || []).forEach((p) => {
      const el = document.createElement("p");
      el.textContent = p;
      lBody.appendChild(el);
    });
    $("letter-closing").textContent = letter.closing || "";
    $("letter-signature").textContent = letter.signature || MAIN.from || "";

    const dlg = $("letter-dialog");
    $("open-letter-btn").addEventListener("click", () => {
      if (typeof dlg.showModal === "function") dlg.showModal();
      else dlg.setAttribute("open", "");
    });
    $("close-letter-btn").addEventListener("click", () => {
      if (typeof dlg.close === "function") dlg.close();
      else dlg.removeAttribute("open");
    });
    dlg.addEventListener("click", (e) => {
      if (e.target === dlg) {
        if (typeof dlg.close === "function") dlg.close();
        else dlg.removeAttribute("open");
      }
    });

    // 4.7 Thông điệp nhị phân (38 byte, nút "🔓 Giải mã" ẩn lúc đầu, hiện sau 3 lần sai)
    const binBits = MAIN.binaryBits || [];
    const binGrid = $("bin-grid");
    const binStatus = $("bin-status");
    const binRevealBtn = $("bin-reveal-btn");
    let binWrong = 0;

    binGrid.innerHTML = "";
    binBits.forEach((bits) => {
      const cell = document.createElement("div");
      cell.className = "bin-cell";
      cell.innerHTML = `<span class="bin-bits">${bits}</span><span class="bin-char"></span>`;
      binGrid.appendChild(cell);
    });

    function decodeBinaryString() {
      return binBits.map((b) => String.fromCharCode(parseInt(b, 2))).join("");
    }

    function revealAllBinaryCells() {
      const cells = binGrid.querySelectorAll(".bin-cell");
      binBits.forEach((bits, i) => {
        const ch = String.fromCharCode(parseInt(bits, 2));
        const c = cells[i];
        if (!c) return;
        c.querySelector(".bin-char").textContent = ch === " " ? "\u00A0" : ch;
        c.classList.add("decoded");
      });
    }

    $("bin-form").addEventListener("submit", (e) => {
      e.preventDefault();
      const userNorm = normCommon($("bin-input").value);
      if (userNorm && sha256(`bin|${userNorm}`) === MAIN.binaryHash) {
        revealAllBinaryCells();
        binStatus.textContent = `✓ Chính xác tuyệt đối! Thông điệp: "${decodeBinaryString()}"`;
        binStatus.className = "status-box ok";
        burstConfetti(1.2);
      } else {
        binWrong++;
        binStatus.textContent = `✕ Bản dịch chưa khớp (lần thử sai: ${binWrong}).`;
        binStatus.className = "status-box err";
        if (binWrong >= 3) {
          binRevealBtn.classList.remove("hidden");
        }
      }
    });

    binRevealBtn.addEventListener("click", () => {
      revealAllBinaryCells();
      binStatus.textContent = `🔓 Đã giải mã toàn bộ ${binBits.length} byte: "${decodeBinaryString()}"`;
      binStatus.className = "status-box ok";
    });

    // 4.8 Phòng xử lý sự cố (3 tình huống tự do) & Thiệp 3D
    const cases = MAIN.cases || [];
    const casesList = $("cases-list");
    const casesCount = $("cases-count");
    const solvedSet = new Set();

    function updateCasesProgress() {
      casesCount.textContent = `${solvedSet.size}/${cases.length} sự cố đã xử lý`;
      if (solvedSet.size === cases.length && cases.length > 0) {
        $("greet-lock").classList.add("hidden");
        $("greet-stage").classList.remove("hidden");
        burstConfetti(1.3);
      }
    }

    casesList.innerHTML = "";
    cases.forEach((c, idx) => {
      const card = document.createElement("article");
      card.className = "case-card";
      card.innerHTML = `
        <span class="card-badge"></span>
        <h3 class="card-title"></h3>
        <p class="card-desc"></p>
        <pre class="case-code"></pre>
        <p class="card-q"></p>
        <form class="case-form">
          <textarea class="case-textarea" placeholder="Nhập hướng xử lý 1 câu rồi nhấn Enter..."></textarea>
          <div class="case-actions">
            <span class="case-fb" aria-live="polite"></span>
            <button type="submit" class="btn-gold">Gửi phương án</button>
          </div>
        </form>
      `;
      card.querySelector(".card-badge").textContent = c.badge;
      card.querySelector(".card-title").textContent = c.title;
      card.querySelector(".card-desc").textContent = c.desc;
      card.querySelector(".case-code").textContent = c.code;
      card.querySelector(".card-q").textContent = c.question;

      const form = card.querySelector(".case-form");
      const ta = card.querySelector(".case-textarea");
      const fb = card.querySelector(".case-fb");
      const btn = card.querySelector("button[type=submit]");
      let wrong = 0;

      const submitCase = () => {
        if (solvedSet.has(idx)) return;
        const txt = normPhrase(ta.value);
        if (!txt) {
          fb.textContent = "Vui lòng nhập phương án xử lý trước khi gửi.";
          fb.className = "case-fb err";
          return;
        }
        const matched = (c.keys || []).some((k) => txt.includes(normPhrase(k)));
        if (matched) {
          solvedSet.add(idx);
          card.classList.add("solved");
          ta.disabled = true;
          btn.disabled = true;
          fb.textContent = `✓ Chuẩn xác! ${c.sample}`;
          fb.className = "case-fb ok";
          updateCasesProgress();
        } else {
          wrong++;
          if (wrong < 3) {
            fb.textContent = `✕ ${c.hint} (Còn ${3 - wrong} lần thử)`;
            fb.className = "case-fb err";
          } else {
            solvedSet.add(idx);
            card.classList.add("solved");
            ta.disabled = true;
            btn.disabled = true;
            fb.textContent = `→ Đáp án mẫu: ${c.sample} (Đã thông qua)`;
            fb.className = "case-fb ok";
            updateCasesProgress();
          }
        }
      };

      form.addEventListener("submit", (e) => {
        e.preventDefault();
        submitCase();
      });
      ta.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          submitCase();
        }
      });

      casesList.appendChild(card);
    });

    // Thiệp 3D (#greet)
    const gr = MAIN.greeting || {};
    $("greet-badge").textContent = gr.badge || "";
    $("greet-title").textContent = gr.title || "";
    $("greet-body").textContent = gr.body || "";
    $("greet-quote").textContent = gr.quote || "";
    $("greet-sig").textContent = `— ${gr.signature || MAIN.from || ""}`;

    const greetCard = $("greet-card");
    const toggleGreet = () => {
      greetCard.classList.toggle("opened");
      if (greetCard.classList.contains("opened")) burstConfetti(0.9);
    };
    greetCard.addEventListener("click", toggleGreet);
    greetCard.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleGreet();
      }
    });

    // 4.9 Kết & Máy bay kéo băng rôn & Tia sao vàng
    $("end-credits").textContent = `Ý tưởng & thực hiện: ${MAIN.author || MAIN.from || "Nguyễn Phú Đạt"}`;
    $("end-signature").textContent = MAIN.from || "Nguyễn Phú Đạt";
    $("end-date").textContent = `Ngày Nhà giáo Việt Nam · ${MAIN.date || "20/11/2026"}`;

    let planeBusy = false;
    function flyPlane() {
      if (planeBusy) return;
      planeBusy = true;
      const pb = $("plane-banner");
      pb.classList.remove("flying");
      void pb.offsetWidth;
      pb.classList.add("flying");
      setTimeout(() => {
        planeBusy = false;
        pb.classList.remove("flying");
      }, 11200);
    }

    let endFlown = false;
    const endObs = new IntersectionObserver(
      (entries) => {
        entries.forEach((en) => {
          if (en.isIntersecting && !endFlown) {
            endFlown = true;
            flyPlane();
          }
        });
      },
      { threshold: 0.35 }
    );
    endObs.observe($("end"));

    // Bí mật: gõ "phong" hoặc chạm 3 lần huy hiệu VAA
    let keyBuf = "";
    window.addEventListener("keydown", (e) => {
      if ($("main").classList.contains("hidden")) return;
      const tag = (e.target && e.target.tagName) || "";
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (e.key.length === 1) {
        keyBuf = (keyBuf + e.key.toLowerCase()).slice(-5);
        if (keyBuf === "phong") {
          keyBuf = "";
          flyPlane();
          burstConfetti(1.1);
        }
      }
    });

    let badgeTaps = 0;
    let badgeTimer = null;
    $("vaa-badge").addEventListener("click", () => {
      badgeTaps++;
      clearTimeout(badgeTimer);
      badgeTimer = setTimeout(() => (badgeTaps = 0), 1500);
      if (badgeTaps >= 3) {
        badgeTaps = 0;
        flyPlane();
        burstConfetti(1.1);
      }
    });

    $("btn-fireworks").addEventListener("click", () => burstConfetti(1.5));
    $("btn-replay").addEventListener("click", () => {
      heroStarted = false;
      $("main").classList.add("hidden");
      onReplay();
    });
    $("music-toggle").addEventListener("click", music.toggle);

    // Tia sao vàng khi chạm nền trang chính
    const starCv = $("star-cv");
    const sctx = starCv.getContext("2d");
    const stars = [];
    const resizeStar = () => {
      starCv.width = window.innerWidth;
      starCv.height = window.innerHeight;
    };
    resizeStar();
    window.addEventListener("resize", resizeStar);

    $("main").addEventListener("pointerdown", (e) => {
      if (e.target.closest("button, a, input, textarea, .wish-card, .greet-card, dialog")) return;
      for (let i = 0; i < 12; i++) {
        const ang = (Math.PI * 2 * i) / 12 + Math.random() * 0.3;
        const spd = 1.4 + Math.random() * 2.8;
        stars.push({
          x: e.clientX,
          y: e.clientY,
          vx: Math.cos(ang) * spd,
          vy: Math.sin(ang) * spd,
          life: 1,
          r: 1.8 + Math.random() * 2.2,
        });
      }
    });

    function animStars() {
      sctx.clearRect(0, 0, starCv.width, starCv.height);
      for (let i = stars.length - 1; i >= 0; i--) {
        const s = stars[i];
        s.x += s.vx;
        s.y += s.vy;
        s.vy += 0.05;
        s.life -= 0.028;
        if (s.life <= 0) {
          stars.splice(i, 1);
          continue;
        }
        sctx.fillStyle = `rgba(246, 216, 120, ${s.life})`;
        sctx.beginPath();
        sctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
        sctx.fill();
      }
      requestAnimationFrame(animStars);
    }
    requestAnimationFrame(animStars);

    return () => {
      window.scrollTo({ top: 0, behavior: "instant" });
      playHero();
    };
  }

  /* ------------------------------------------------------------------------
     5. KHỞI CHẠY
     ------------------------------------------------------------------------ */
  gate.boot();
})();
