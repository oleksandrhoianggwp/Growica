(function () {
  "use strict";

  const STATUS_LABELS = { pending: "Pending", processing: "Processing", submitted: "Submitted", failed: "Failed" };
  const PLACEHOLDERS = {
    domain: "example.com\nsub.example.org",
    ip: "192.0.2.10\n2001:db8::1",
    url: "https://example.com/login\nhttps://example.org/path?x=1",
  };
  const $ = (sel) => document.querySelector(sel);
  const state = { batchId: null, options: null, pollTimer: null };

  try { state.batchId = Number(localStorage.getItem("currentBatch")) || null; } catch (e) { state.batchId = null; }

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function toast(message) {
    const el = $("#toast");
    el.textContent = message;
    el.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { el.hidden = true; }, 5000);
  }

  async function api(path, options) {
    let response;
    try {
      response = await fetch(path, options);
    } catch (e) {
      throw { message: "Cannot reach the server.", errors: [] };
    }
    let body = null;
    try { body = await response.json(); } catch (e) { body = null; }
    if (!response.ok) {
      let detail = body && body.detail;
      let errors = (body && body.errors) || [];
      if (detail && typeof detail === "object") { errors = detail.errors || errors; detail = detail.detail; }
      throw { message: detail || `Request failed (HTTP ${response.status})`, errors, status: response.status };
    }
    return body;
  }

  function badge(row) {
    return `<span class="badge ${esc(row.status)}">${esc(STATUS_LABELS[row.status] || row.status)}</span>`;
  }

  function details(row) {
    const parts = [];
    if (row.status === "processing" || row.status === "pending") parts.push(esc(row.progress || ""));
    if (row.error) parts.push(`<span class="${row.status === "failed" ? "err" : ""}">${esc(row.error)}</span>`);
    if (row.outcome_uncertain) parts.push('<span class="uncertain">Outcome unknown — may already be on the site</span>');
    if (row.attempts > 1) parts.push(`<span class="muted">${row.attempts} attempts</span>`);
    return parts.join("<br>");
  }

  function retryButton(row) {
    if (row.status !== "failed") return "";
    return `<button type="button" class="link" data-retry="${row.id}" data-uncertain="${row.outcome_uncertain ? 1 : 0}">Retry</button>`;
  }

  function renderBatch(batch) {
    const rows = batch.submissions;
    const counts = { pending: 0, processing: 0, submitted: 0, failed: 0 };
    rows.forEach((r) => { counts[r.status] = (counts[r.status] || 0) + 1; });
    $("#batch-title").textContent = `Batch #${batch.id}`;
    $("#batch-summary").innerHTML =
      `<span>${esc(batch.submission_type.toUpperCase())} · ${esc(batch.threat_type)}${batch.attachment_name ? " · " + esc(batch.attachment_name) : ""}</span>` +
      Object.keys(counts).map((k) => `<span>${STATUS_LABELS[k]}: <b>${counts[k]}</b></span>`).join("");
    $("#retry-batch").hidden = counts.failed === 0;
    $("#batch-rows").innerHTML = rows.length ? rows.map((r) => `
      <tr>
        <td>${r.line_no}</td>
        <td class="target">${esc(r.target)}</td>
        <td>${badge(r)}</td>
        <td class="code">${r.confirmation_code ? esc(r.confirmation_code) : "—"}</td>
        <td class="details">${details(r)}</td>
        <td>${retryButton(r)}</td>
      </tr>`).join("") : '<tr class="empty"><td colspan="6">Every target in this batch was a duplicate.</td></tr>';
    return counts.pending + counts.processing > 0;
  }

  function renderHistory(rows) {
    $("#history-rows").innerHTML = rows.length ? rows.map((r) => `
      <tr>
        <td>${r.id}</td>
        <td><button type="button" class="link" data-batch="${r.batch_id}">#${r.batch_id}</button></td>
        <td>${esc(r.submission_type)}</td>
        <td class="target">${esc(r.target)}</td>
        <td>${esc(r.threat_type)}</td>
        <td>${badge(r)}${r.outcome_uncertain ? '<span class="uncertain">Outcome unknown</span>' : ""}</td>
        <td class="code">${r.confirmation_code ? esc(r.confirmation_code) : "—"}</td>
        <td class="muted">${esc((r.updated_at || "").replace("T", " ").replace("+00:00", " UTC"))}</td>
        <td>${retryButton(r)}</td>
      </tr>`).join("") : '<tr class="empty"><td colspan="9">No submissions yet.</td></tr>';
  }

  async function refresh() {
    let active = false;
    try {
      if (state.batchId) {
        try {
          active = renderBatch(await api(`/api/batches/${state.batchId}`));
        } catch (e) {
          if (e.status === 404) { state.batchId = null; } else { throw e; }
        }
      }
      const filter = $("#history-filter").value;
      renderHistory(await api(`/api/submissions?limit=200${filter ? "&status=" + filter : ""}`));
      await refreshHealth();
    } catch (e) {
      $("#health").textContent = e.message || "Server unavailable";
      $("#health").className = "health bad";
    }
    clearTimeout(state.pollTimer);
    state.pollTimer = setTimeout(refresh, active ? 2000 : 8000);
  }

  async function refreshHealth() {
    const h = await api("/api/health");
    const el = $("#health");
    if (h.config_problem && !h.dry_run) {
      el.textContent = h.config_problem;
      el.className = "health bad";
    } else if (h.dry_run) {
      el.textContent = "DRY RUN — forms are filled but never submitted";
      el.className = "health warn";
    } else {
      const queue = h.queue_length ? ` · ${h.queue_length} queued` : "";
      el.textContent = `CAPTCHA: ${h.captcha_provider} · ≥${h.min_submit_interval}s between submissions${queue}`;
      el.className = "health";
    }
  }

  function showFormErrors(message, errors) {
    const box = $("#form-errors");
    if (!message) { box.hidden = true; box.innerHTML = ""; return; }
    box.innerHTML = esc(message) + (errors && errors.length ? "<ul>" + errors.map((e) => `<li>${esc(e)}</li>`).join("") + "</ul>" : "");
    box.hidden = false;
  }

  function selectedType() {
    const checked = document.querySelector('input[name="submission_type"]:checked');
    return checked ? checked.value : "domain";
  }

  function updateTypeHints() {
    const type = selectedType();
    $("#targets").placeholder = PLACEHOLDERS[type] || "";
    const limit = state.options ? state.options.max_targets_per_batch : 100;
    $("#targets-hint").textContent = `Each line is submitted separately, one after another (max ${limit}).`;
  }

  function clientValidate(form) {
    const errors = [];
    if (!form.targets.value.trim()) errors.push("Enter at least one target.");
    if (!form.threat_type.value) errors.push("Select a threat type.");
    if (!form.reason.value.trim()) errors.push("Enter a reason.");
    const file = form.attachment.files[0];
    if (file) {
      const ext = file.name.toLowerCase().slice(file.name.lastIndexOf("."));
      if (![".jpg", ".jpeg", ".png", ".pdf"].includes(ext)) errors.push("Attachment must be JPG, JPEG, PNG or PDF.");
      if (file.size > 2 * 1024 * 1024) errors.push("Attachment must be 2 MB or smaller.");
    }
    return errors;
  }

  async function onSubmit(event) {
    event.preventDefault();
    const form = event.target;
    const errors = clientValidate(form);
    if (errors.length) { showFormErrors("Please fix these problems:", errors); return; }
    showFormErrors(null);
    const data = new FormData(form);
    data.set("submission_type", selectedType());
    data.set("allow_resubmit", form.allow_resubmit.checked ? "true" : "false");
    if (!form.attachment.files.length) data.delete("attachment");
    const button = $("#submit-btn");
    button.disabled = true;
    button.textContent = "Queuing…";
    try {
      const result = await api("/api/batches", { method: "POST", body: data });
      state.batchId = result.batch_id;
      try { localStorage.setItem("currentBatch", String(result.batch_id)); } catch (e) { /* storage unavailable */ }
      const skipped = result.skipped_duplicates || [];
      const box = $("#skipped");
      if (skipped.length) {
        box.innerHTML = `<b>${skipped.length} duplicate target(s) skipped:</b><ul>` + skipped.map((s) =>
          `<li>${esc(s.target)} — already ${esc(s.existing_status)} as #${s.existing_id}${s.confirmation_code ? " (" + esc(s.confirmation_code) + ")" : ""}</li>`).join("") +
          "</ul>Tick “Re-send targets…” to submit them again.";
        box.hidden = false;
      } else {
        box.hidden = true;
      }
      form.targets.value = "";
      toast(`${result.queued} submission(s) queued.`);
      refresh();
    } catch (e) {
      showFormErrors(e.message, e.errors);
    } finally {
      button.disabled = false;
      button.textContent = "Queue submissions";
    }
  }

  async function retry(id, uncertain) {
    let confirmFlag = false;
    if (uncertain) {
      confirmFlag = window.confirm("The previous attempt may already have reached the site. Retrying could create a duplicate report. Retry anyway?");
      if (!confirmFlag) return;
    }
    try {
      await api(`/api/submissions/${id}/retry${confirmFlag ? "?confirm_uncertain=true" : ""}`, { method: "POST" });
      toast(`Submission #${id} queued again.`);
    } catch (e) {
      toast(e.message);
    }
    refresh();
  }

  async function retryBatch() {
    if (!state.batchId) return;
    try {
      const result = await api(`/api/batches/${state.batchId}/retry-failed`, { method: "POST" });
      let message = `${result.retried.length} submission(s) queued again.`;
      if (result.not_retried.length) message += ` ${result.not_retried.length} not retried: ` + result.not_retried.map((n) => `#${n.id} ${n.reason}`).join("; ");
      toast(message);
    } catch (e) {
      toast(e.message);
    }
    refresh();
  }

  async function init() {
    try {
      state.options = await api("/api/options");
    } catch (e) {
      showFormErrors(e.message, e.errors);
      return;
    }
    $("#type-group").innerHTML = state.options.submission_types.map((t, i) =>
      `<label><input type="radio" name="submission_type" value="${esc(t.value)}" ${i === 0 ? "checked" : ""}>${esc(t.label)}</label>`).join("");
    const threat = $("#threat_type");
    state.options.threat_types.forEach((t) => {
      const opt = document.createElement("option");
      opt.value = t; opt.textContent = t; threat.appendChild(opt);
    });
    document.querySelectorAll('input[name="submission_type"]').forEach((el) => el.addEventListener("change", updateTypeHints));
    updateTypeHints();
    $("#reason").addEventListener("input", (e) => { $("#reason-count").textContent = e.target.value.length; });
    $("#batch-form").addEventListener("submit", onSubmit);
    $("#retry-batch").addEventListener("click", retryBatch);
    $("#history-filter").addEventListener("change", refresh);
    document.addEventListener("click", (e) => {
      const r = e.target.closest("[data-retry]");
      if (r) { retry(Number(r.dataset.retry), r.dataset.uncertain === "1"); return; }
      const b = e.target.closest("[data-batch]");
      if (b) {
        state.batchId = Number(b.dataset.batch);
        try { localStorage.setItem("currentBatch", String(state.batchId)); } catch (err) { /* storage unavailable */ }
        $("#skipped").hidden = true;
        refresh();
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    });
    refresh();
  }

  init();
})();
