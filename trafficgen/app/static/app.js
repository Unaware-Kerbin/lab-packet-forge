/* Lab Packet Forge UI */
const state = {
  templates: {},
  protocols: [],
  categoryFilter: null,
  selected: null,
  fieldValues: {},
  craftStack: [],
  craftSelectedIdx: -1,
  lastTemplate: null,
  mode: "templates",
  safety: null,
  lastStoppedReason: null,
};

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: opts.body instanceof FormData ? undefined : { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.message || res.statusText);
  return data;
}

function defaultsFrom(proto) {
  const out = {};
  for (const f of proto.fields || []) {
    out[f.name] = f.default ?? "";
  }
  return out;
}

function renderFields(container, proto, values, { advanced = false } = {}) {
  container.innerHTML = "";
  const fields = (proto.fields || []).filter((f) => !!f.advanced === advanced);
  for (const f of fields) {
    const lab = document.createElement("label");
    lab.innerHTML = `<span>${f.label}${f.required ? ' <span class="req">*</span>' : ""}</span>`;
    let input;
    if (f.type === "select") {
      input = document.createElement("select");
      for (const opt of f.options || []) {
        const o = document.createElement("option");
        o.value = opt.value;
        o.textContent = opt.label;
        if (String(values[f.name]) === String(opt.value)) o.selected = true;
        input.appendChild(o);
      }
    } else if (f.type === "bool") {
      input = document.createElement("select");
      input.innerHTML = `<option value="true">true</option><option value="false">false</option>`;
      input.value = String(values[f.name] ?? f.default ?? true);
    } else {
      input = document.createElement("input");
      input.type = f.type === "int" || f.type === "float" ? "number" : "text";
      if (f.min != null) input.min = f.min;
      if (f.max != null) input.max = f.max;
      if (f.type === "float") input.step = "any";
      input.value = values[f.name] ?? "";
      if (f.hint) input.placeholder = f.hint;
    }
    input.dataset.field = f.name;
    input.addEventListener("input", () => {
      values[f.name] = coerce(f, input.value);
    });
    input.addEventListener("change", () => {
      values[f.name] = coerce(f, input.value);
    });
    lab.appendChild(input);
    container.appendChild(lab);
  }
}

function coerce(f, v) {
  if (f.type === "int") return v === "" ? f.default : Number(v);
  if (f.type === "float") return v === "" ? f.default : Number(v);
  if (f.type === "bool") return String(v) === "true";
  return v;
}

function collectForm(proto, root) {
  const values = { ...defaultsFrom(proto) };
  root.querySelectorAll("[data-field]").forEach((el) => {
    const f = proto.fields.find((x) => x.name === el.dataset.field);
    if (f) values[f.name] = coerce(f, el.value);
  });
  return values;
}

function renderGallery(filterQ = "") {
  const gallery = $("#gallery");
  gallery.innerHTML = "";
  const q = filterQ.toLowerCase();
  const cats = Object.keys(state.templates);
  const pills = $("#cat-pills");
  pills.innerHTML = "";
  const allBtn = document.createElement("button");
  allBtn.textContent = "All";
  allBtn.className = state.categoryFilter ? "" : "on";
  allBtn.onclick = () => {
    state.categoryFilter = null;
    renderGallery($("#search").value);
  };
  pills.appendChild(allBtn);

  for (const cat of cats) {
    const b = document.createElement("button");
    b.textContent = cat;
    if (state.categoryFilter === cat) b.className = "on";
    b.onclick = () => {
      state.categoryFilter = cat;
      renderGallery($("#search").value);
    };
    pills.appendChild(b);
  }

  for (const cat of cats) {
    if (state.categoryFilter && state.categoryFilter !== cat) continue;
    let items = state.templates[cat] || [];
    if (q) {
      items = items.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          p.id.toLowerCase().includes(q) ||
          (p.template?.blurb || "").toLowerCase().includes(q) ||
          cat.toLowerCase().includes(q)
      );
    }
    if (!items.length) continue;
    const block = document.createElement("div");
    block.className = "cat-block";
    block.innerHTML = `<h3>${cat}</h3>`;
    const cards = document.createElement("div");
    cards.className = "cards";
    for (const p of items) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "card";
      btn.innerHTML = `<h4>${p.name}</h4><p>${p.template?.blurb || ""}</p><div class="id">${p.id}</div>`;
      btn.onclick = () => openProtoDialog(p);
      cards.appendChild(btn);
    }
    block.appendChild(cards);
    gallery.appendChild(block);
  }
}

function softCap(proto) {
  return proto?.template?.soft_pps_cap ?? null;
}

function hardCap(proto) {
  return proto?.template?.hard_pps_cap ?? null;
}

function updateRateBanner(proto, pps) {
  const banner = $("#rate-banner");
  if (!banner) return;
  const rate = Number(pps);
  const soft = softCap(proto);
  const hard = hardCap(proto);
  const risky = !!proto?.template?.control_plane_risk;
  const warnAt = state.safety?.dangerous_rate_warn_pps ?? 50;
  let text = "";
  let cls = "rate-banner";
  if (hard != null && rate > hard) {
    text = `⚠ ${proto.id} hard cap ${hard} pps — enable “allow dangerous rate” or lower pps (requested ${rate}).`;
    cls += " danger";
  } else if (soft != null && rate > soft) {
    text = `⚠ ${proto.id} above soft cap ${soft} pps — control-plane / broadcast floods can DoS switches.`;
    cls += " danger";
  } else if (risky && rate >= warnAt) {
    text = `⚠ Dangerous rate for L2/control-plane template ${proto.id} (${rate} pps). Prefer ≤${soft ?? warnAt} pps.`;
    cls += " danger";
  } else if (risky) {
    text = `Control-plane template ${proto.id}: default ≤${soft ?? 10} pps, hard cap ${hard ?? "—"}.`;
  }
  if (!text) {
    banner.className = "rate-banner hidden";
    banner.textContent = "";
    return;
  }
  banner.className = cls;
  banner.textContent = text;
}

function confirmDangerousStart(proto, pps) {
  const rate = Number(pps);
  const soft = softCap(proto);
  const hard = hardCap(proto);
  const risky = !!proto?.template?.control_plane_risk;
  const allow = $("#allow-dangerous")?.checked;
  if (hard != null && rate > hard && !allow) {
    alert(`${proto?.id || "stream"} hard cap is ${hard} pps. Lower pps or check “allow dangerous rate”.`);
    return false;
  }
  if ((risky && soft != null && rate > soft) || (risky && rate >= 50) || rate >= 500) {
    const msg =
      `Start TX at ${rate} pps` +
      (proto?.id ? ` for ${proto.id}` : "") +
      `?\n\nHigh rates of ARP/STP/IGMP/BUM/etc. can lock up switch CPUs and flood CAM tables.\n` +
      (hard != null && rate > hard ? "You enabled the hard-cap override.\n" : "") +
      "Gateway killswitch will auto-stop TX if the probe target is unreachable for the configured timeout.";
    return confirm(msg);
  }
  return true;
}

async function applyKillswitchConfig() {
  const input = $("#ks-target");
  if (!input) return;
  const raw = (input.value || "").trim();
  const body = { target: raw || "auto" };
  try {
    const res = await api("/api/safety/killswitch", { method: "POST", body: JSON.stringify(body) });
    const ks = res.killswitch || {};
    if (state.safety) state.safety.killswitch = ks;
    updateKillswitchBanner(ks, null);
  } catch (e) {
    alert(e.message || String(e));
  }
}

function openProtoDialog(proto) {
  state.selected = proto;
  state.fieldValues = defaultsFrom(proto);
  $("#dlg-title").textContent = proto.name;
  $("#dlg-blurb").textContent = `${proto.template?.blurb || ""} — ${proto.template?.when_to_use || ""}`;
  renderFields($("#dlg-fields"), proto, state.fieldValues, { advanced: false });
  renderFields($("#dlg-advanced"), proto, state.fieldValues, { advanced: true });
  const pps = proto.template?.default_pps;
  if (pps) $("#pps").value = pps;
  updateRateBanner(proto, $("#pps").value);
  $("#proto-dialog").showModal();
}

async function applyTemplateStream(start = false) {
  const proto = state.selected;
  if (!proto) return;
  const config = collectForm(proto, $("#proto-form"));
  state.fieldValues = config;
  const stream = {
    mode: "template",
    protocol: proto.id,
    config,
    pps: Number($("#pps").value) || 10,
    loop: true,
    iface: $("#iface").value,
    allow_dangerous_rate: !!$("#allow-dangerous")?.checked,
  };
  state.lastTemplate = { protocol: proto.id, config, proto };
  updateRateBanner(proto, stream.pps);
  const res = await api("/api/stream", { method: "POST", body: JSON.stringify(stream) });
  if (res.pps_policy?.warning) {
    const b = $("#rate-banner");
    b.className = "rate-banner" + (res.pps_policy.dangerous ? " danger" : "");
    b.textContent = res.pps_policy.warning;
  }
  $("#proto-dialog").close();
  $("#st-proto").textContent = proto.id;
  if (start) await doStart();
}

function setMode(mode) {
  state.mode = mode;
  $$(".mode").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  $("#view-templates").classList.toggle("hidden", mode !== "templates");
  $("#view-craft").classList.toggle("hidden", mode !== "craft");
}

function renderCraftList(q = "") {
  const box = $("#craft-list");
  box.innerHTML = "";
  const ql = q.toLowerCase();
  for (const p of state.protocols) {
    if (ql && !p.name.toLowerCase().includes(ql) && !p.id.toLowerCase().includes(ql)) continue;
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = `${p.name} (${p.id})`;
    b.onclick = () => {
      state.craftStack.push({ protocol: p.id, config: defaultsFrom(p) });
      state.craftSelectedIdx = state.craftStack.length - 1;
      renderStack();
      renderCraftFields();
    };
    box.appendChild(b);
  }
}

function renderStack() {
  const stack = $("#stack");
  stack.innerHTML = "";
  state.craftStack.forEach((layer, idx) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.innerHTML = `<button type="button" title="select" style="color:inherit;border:0;background:0;cursor:pointer">${layer.protocol}</button>`;
    chip.querySelector("button").onclick = () => {
      state.craftSelectedIdx = idx;
      renderCraftFields();
    };
    const rm = document.createElement("button");
    rm.type = "button";
    rm.textContent = "×";
    rm.onclick = () => {
      state.craftStack.splice(idx, 1);
      if (state.craftSelectedIdx >= state.craftStack.length) state.craftSelectedIdx = state.craftStack.length - 1;
      renderStack();
      renderCraftFields();
    };
    chip.appendChild(rm);
    stack.appendChild(chip);
  });
}

function renderCraftFields() {
  const box = $("#craft-fields");
  box.innerHTML = "";
  const idx = state.craftSelectedIdx;
  if (idx < 0 || !state.craftStack[idx]) return;
  const layer = state.craftStack[idx];
  const proto = state.protocols.find((p) => p.id === layer.protocol);
  if (!proto) return;
  const h = document.createElement("h3");
  h.textContent = `Fields: ${proto.name}`;
  box.appendChild(h);
  const wrap = document.createElement("div");
  wrap.className = "fields";
  wrap.id = "craft-field-root";
  box.appendChild(wrap);
  renderFields(wrap, proto, layer.config, { advanced: false });
  const adv = document.createElement("details");
  adv.innerHTML = "<summary>Advanced</summary>";
  const advBox = document.createElement("div");
  advBox.className = "fields";
  adv.appendChild(advBox);
  box.appendChild(adv);
  renderFields(advBox, proto, layer.config, { advanced: true });
  // keep config live
  box.querySelectorAll("[data-field]").forEach((el) => {
    el.addEventListener("input", () => syncCraftConfig());
    el.addEventListener("change", () => syncCraftConfig());
  });
}

function syncCraftConfig() {
  const idx = state.craftSelectedIdx;
  if (idx < 0) return;
  const layer = state.craftStack[idx];
  const proto = state.protocols.find((p) => p.id === layer.protocol);
  if (!proto) return;
  layer.config = collectForm(proto, $("#craft-fields"));
}

async function applyCraft() {
  syncCraftConfig();
  const stream = {
    mode: "craft",
    layers: state.craftStack,
    protocol: state.craftStack.length ? state.craftStack[state.craftStack.length - 1].protocol : null,
    pps: Number($("#pps").value) || 10,
    loop: true,
    iface: $("#iface").value,
    allow_dangerous_rate: !!$("#allow-dangerous")?.checked,
  };
  const proto = state.protocols.find((p) => p.id === stream.protocol);
  updateRateBanner(proto, stream.pps);
  const res = await api("/api/stream", { method: "POST", body: JSON.stringify(stream) });
  const warns = [...(res.warnings || [])];
  if (res.pps_policy?.warning) warns.push(res.pps_policy.warning);
  $("#craft-warnings").textContent = warns.join("; ");
  $("#st-proto").textContent = stream.protocol || "craft";
}

async function doStart() {
  const pps = Number($("#pps").value) || 10;
  const proto =
    state.selected ||
    state.protocols.find((p) => p.id === ($("#st-proto").textContent || state.lastTemplate?.protocol));
  if (!confirmDangerousStart(proto, pps)) return;
  await api("/api/start", {
    method: "POST",
    body: JSON.stringify({
      iface: $("#iface").value,
      pps,
      allow_dangerous_rate: !!$("#allow-dangerous")?.checked,
    }),
  });
  state.lastStoppedReason = null;
  $("#btn-start").disabled = true;
  $("#btn-stop").disabled = false;
}

async function doStop() {
  await api("/api/stop", { method: "POST", body: "{}" });
  $("#btn-start").disabled = false;
  $("#btn-stop").disabled = true;
}

function updateKillswitchBanner(ks, stoppedReason) {
  const el = $("#ks-banner");
  if (!el) return;
  const targets = (ks.targets && ks.targets.length ? ks.targets : null) || (ks.gateway ? [ks.gateway] : []);
  const targetLabel = targets.length ? targets.join(", ") : ks.target_spec || "auto";
  const timeout = Math.round(ks.timeout_s || 120);

  if (stoppedReason === "gateway_unreachable") {
    el.className = "ks-banner stopped";
    el.textContent = `Killswitch stopped TX — probe ${targetLabel} unreachable for ${timeout}s.`;
    return;
  }
  if (!ks.enabled) {
    el.className = "ks-banner";
    el.textContent = "Killswitch off";
    return;
  }
  if (ks.armed) {
    if (ks.reachable === false) {
      const left = Math.max(0, Math.ceil(ks.seconds_until_stop ?? timeout - (ks.fail_seconds || 0)));
      el.className = "ks-banner failing";
      el.textContent = `Killswitch armed · probing ${targetLabel} · FAIL ${Math.floor(ks.fail_seconds || 0)}s · stop in ${left}s`;
    } else {
      el.className = "ks-banner armed";
      el.textContent = `Killswitch armed · probing ${targetLabel} · OK · auto-stop after ${timeout}s continuous fail`;
    }
    return;
  }
  el.className = "ks-banner";
  el.textContent = `Killswitch ready · target ${targetLabel} · ${timeout}s fail window (arms when TX starts)`;
}

async function pollStats() {
  try {
    const s = await api("/api/stats");
    $("#st-sent").textContent = s.sent ?? 0;
    $("#st-pps").textContent = (s.pps_actual ?? 0).toFixed?.(1) ?? s.pps_actual;
    $("#st-err").textContent = s.errors ?? 0;
    $("#st-proto").textContent = s.protocol || "—";
    $("#st-last").textContent = s.last_error || "";
    const reason = s.stopped_reason || "—";
    $("#st-reason").textContent = reason;
    const ks = s.killswitch || {};
    const gwBits = [];
    if (ks.armed) gwBits.push("armed");
    else if (ks.enabled === false) gwBits.push("off");
    else gwBits.push("idle");
    const tgt = (ks.targets && ks.targets[0]) || ks.gateway || ks.target_spec || "auto";
    gwBits.push(tgt);
    if (ks.armed) {
      if (ks.reachable === false) {
        const left = Math.max(0, Math.ceil(ks.seconds_until_stop ?? 0));
        gwBits.push(`FAIL ${Math.floor(ks.fail_seconds || 0)}s`);
        gwBits.push(`stop@${left}s`);
      } else if (ks.reachable === true) {
        gwBits.push("ok");
      }
    }
    $("#st-gw").textContent = gwBits.join(" · ") || "—";
    updateKillswitchBanner(ks, s.stopped_reason);
    if (s.stopped_reason === "gateway_unreachable" && state.lastStoppedReason !== s.stopped_reason) {
      state.lastStoppedReason = s.stopped_reason;
      const b = $("#rate-banner");
      b.className = "rate-banner kill";
      const tgtLabel = (ks.targets && ks.targets.length ? ks.targets.join(", ") : null) || ks.gateway || "probe target";
      b.textContent = `TX auto-stopped: ${tgtLabel} unreachable for ${ks.timeout_s || 120}s (killswitch).`;
    }
    $("#btn-start").disabled = !!s.running;
    $("#btn-stop").disabled = !s.running;
  } catch (_) {}
}

async function init() {
  const [tpl, protos, ifaces, safety] = await Promise.all([
    api("/api/templates"),
    api("/api/protocols"),
    api("/api/ifaces"),
    api("/api/safety").catch(() => null),
  ]);
  state.templates = tpl.categories || {};
  state.protocols = protos.protocols || [];
  state.safety = safety;
  const sel = $("#iface");
  sel.innerHTML = "";
  for (const name of ifaces.ifaces || ["eth1"]) {
    const o = document.createElement("option");
    o.value = name;
    o.textContent = name;
    if (name === (ifaces.default || "eth1")) o.selected = true;
    sel.appendChild(o);
  }
  const ksInput = $("#ks-target");
  if (ksInput) {
    const ks = safety?.killswitch || safety?.gateway_kill || {};
    const spec = ks.target_spec ?? safety?.gateway_kill?.target_default ?? "auto";
    ksInput.value = !spec || spec === "auto" ? "" : spec;
    ksInput.addEventListener("change", () => applyKillswitchConfig());
    ksInput.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        applyKillswitchConfig();
      }
    });
    updateKillswitchBanner(safety?.killswitch || {}, null);
  }
  renderGallery();
  renderCraftList();

  $$(".mode").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  $("#search").addEventListener("input", (e) => renderGallery(e.target.value));
  $("#craft-search").addEventListener("input", (e) => renderCraftList(e.target.value));
  $("#pps").addEventListener("input", () => {
    const proto =
      state.selected ||
      state.protocols.find((p) => p.id === ($("#st-proto").textContent || state.lastTemplate?.protocol));
    updateRateBanner(proto, $("#pps").value);
  });
  $("#dlg-apply").addEventListener("click", () => applyTemplateStream(false).catch(alert));
  $("#dlg-craft").addEventListener("click", () => {
    const proto = state.selected;
    if (!proto) return;
    const config = collectForm(proto, $("#proto-form"));
    state.craftStack = [{ protocol: proto.id, config }];
    state.craftSelectedIdx = 0;
    $("#proto-dialog").close();
    setMode("craft");
    renderStack();
    renderCraftFields();
  });
  $("#btn-apply-craft").addEventListener("click", () => applyCraft().catch(alert));
  $("#btn-load-template").addEventListener("click", () => {
    if (!state.lastTemplate) return alert("No template applied yet");
    state.craftStack = [{ protocol: state.lastTemplate.protocol, config: { ...state.lastTemplate.config } }];
    state.craftSelectedIdx = 0;
    renderStack();
    renderCraftFields();
  });
  $("#btn-save-preset").addEventListener("click", () => {
    syncCraftConfig();
    const blob = new Blob([JSON.stringify({ layers: state.craftStack }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "forge-preset.json";
    a.click();
  });
  $("#btn-start").addEventListener("click", () => doStart().catch(alert));
  $("#btn-stop").addEventListener("click", () => doStop().catch(alert));
  $("#btn-upload").addEventListener("click", async () => {
    const file = $("#pcap-file").files?.[0];
    if (!file) return alert("Choose a pcap");
    const fd = new FormData();
    fd.append("file", file);
    const qs = new URLSearchParams({
      iface: $("#iface").value,
      pps: String($("#pps").value || 10),
      loop: "true",
      allow_dangerous_rate: String(!!$("#allow-dangerous")?.checked),
    });
    const res = await fetch(`/api/replay?${qs}`, { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) return alert(data.detail || "upload failed");
    $("#st-proto").textContent = "pcap_replay";
    alert(`Armed replay: ${data.pcap_path}`);
  });

  setInterval(pollStats, 1000);
}

init().catch((e) => {
  console.error(e);
  $("#st-last").textContent = String(e);
});
