(function () {
  "use strict";

  // --- State ---
  const state = {
    projects: [],
    filter: "all",
    search: "",
    expandedLogs: {},
    expandedConfigs: {},
    logData: {},
    activeLogTab: {},
    configData: {},
    logFilter: {},
    connected: false,
  };

  let rpcId = 0;
  let pollTimer = null;
  let searchDebounce = null;
  let lastRenderKey = "";
  let isFirstRender = true;
  let eventSource = null;
  let sseRetryTimer = null;

  // --- RPC ---
  async function rpc(method, params) {
    const res = await fetch("/api", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: ++rpcId, method, params: params || {} }),
    });
    const json = await res.json();
    if (!json.ok) throw new Error(json.error || "RPC failed");
    return json.result;
  }

  // --- DOM helpers ---
  function h(tag, attrs, children) {
    const el = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === "textContent") el.textContent = v;
      else if (k === "innerHTML") el.innerHTML = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    if (children) for (const c of children) {
      if (typeof c === "string") el.appendChild(document.createTextNode(c));
      else if (c) el.appendChild(c);
    }
    return el;
  }

  function actionButton(label, fn, cls) {
    return h("button", { textContent: label, onclick: fn, class: "btn " + (cls || "btn-secondary btn-sm") });
  }

  // --- Button loading state ---
  async function doActionWithButton(btn, method, params, successMsg) {
    var origText = btn.textContent;
    btn.textContent = origText + "...";
    btn.disabled = true;
    btn.classList.add("btn-loading");
    try {
      await rpc(method, params);
      if (successMsg) showToast(successMsg, "success");
      lastRenderKey = "";
      await refresh();
    } catch (e) {
      showToast(e.message, "error");
    } finally {
      btn.textContent = origText;
      btn.disabled = false;
      btn.classList.remove("btn-loading");
    }
  }

  // --- Toast system ---
  function showToast(message, type, duration) {
    type = type || "info";
    duration = duration || 3000;
    const container = document.getElementById("toast-container");
    const toast = h("div", { class: "toast toast-" + type, textContent: message });
    container.appendChild(toast);
    setTimeout(function () {
      toast.classList.add("toast-dismiss");
      setTimeout(function () { toast.remove(); }, 200);
    }, duration);
  }

  // --- Modal system ---
  function openModal(renderFn) {
    const backdrop = document.getElementById("modal-backdrop");
    const container = document.getElementById("modal-container");
    backdrop.hidden = false;
    container.hidden = false;
    container.innerHTML = "";
    var modal = h("div", { class: "modal" });
    renderFn(modal);
    container.appendChild(modal);

    backdrop.onclick = closeModal;
    container.onclick = function (e) {
      if (e.target === container) closeModal();
    };
  }

  function closeModal() {
    var backdrop = document.getElementById("modal-backdrop");
    var container = document.getElementById("modal-container");
    backdrop.hidden = true;
    container.hidden = true;
    container.innerHTML = "";
  }

  function openConfirmModal(title, message, onConfirm) {
    openModal(function (modal) {
      modal.appendChild(h("h2", {}, [title]));
      modal.appendChild(h("p", {}, [message]));
      var actions = h("div", { class: "modal-actions" });
      actions.appendChild(actionButton("Cancel", closeModal, "btn-secondary"));
      actions.appendChild(actionButton("Confirm", function () {
        closeModal();
        onConfirm();
      }, "btn-danger"));
      modal.appendChild(actions);
    });
  }

  // --- Connection status ---
  function setConnected(ok) {
    state.connected = ok;
    var el = document.getElementById("connection-status");
    if (ok) {
      el.className = "status-dot connected";
      el.title = "Connected";
    } else {
      el.className = "status-dot disconnected";
      el.title = "Disconnected";
    }
  }

  // --- Header stats ---
  function updateHeaderStats() {
    var el = document.getElementById("header-stats");
    if (!el) return;
    if (state.projects.length === 0) {
      el.textContent = "";
      return;
    }
    var running = 0, stopped = 0;
    for (var i = 0; i < state.projects.length; i++) {
      if (state.projects[i].state === "stopped") stopped++;
      else running++;
    }
    var parts = [];
    if (running > 0) parts.push(running + " running");
    if (stopped > 0) parts.push(stopped + " stopped");
    el.textContent = parts.join(", ");
  }

  // --- ANSI to HTML ---
  function ansiToHtml(text) {
    var COLORS = [
      "ansi-black", "ansi-red", "ansi-green", "ansi-yellow",
      "ansi-blue", "ansi-magenta", "ansi-cyan", "ansi-white",
    ];
    var BRIGHT_COLORS = [
      "ansi-bright-black", "ansi-bright-red", "ansi-bright-green", "ansi-bright-yellow",
      "ansi-bright-blue", "ansi-bright-magenta", "ansi-bright-cyan", "ansi-bright-white",
    ];

    var result = "";
    var openSpans = 0;
    var i = 0;
    while (i < text.length) {
      if (text.charCodeAt(i) === 27 && text.charAt(i + 1) === "[") {
        var end = text.indexOf("m", i + 2);
        if (end === -1) { result += escapeHtml(text.charAt(i)); i++; continue; }
        var codes = text.substring(i + 2, end).split(";").map(Number);
        i = end + 1;

        var classes = [];
        for (var j = 0; j < codes.length; j++) {
          var c = codes[j];
          if (c === 0) {
            // Reset: close all open spans
            while (openSpans > 0) { result += "</span>"; openSpans--; }
            continue;
          }
          if (c === 1) classes.push("ansi-bold");
          else if (c === 2) classes.push("ansi-dim");
          else if (c === 3) classes.push("ansi-italic");
          else if (c === 4) classes.push("ansi-underline");
          else if (c >= 30 && c <= 37) classes.push(COLORS[c - 30]);
          else if (c >= 90 && c <= 97) classes.push(BRIGHT_COLORS[c - 90]);
        }
        if (classes.length > 0) {
          result += '<span class="' + classes.join(" ") + '">';
          openSpans++;
        }
      } else {
        result += escapeHtml(text.charAt(i));
        i++;
      }
    }
    while (openSpans > 0) { result += "</span>"; openSpans--; }
    return result;
  }

  function escapeHtml(ch) {
    if (ch === "&") return "&amp;";
    if (ch === "<") return "&lt;";
    if (ch === ">") return "&gt;";
    return ch;
  }

  // --- Badge helpers ---
  function badgeClass(s) {
    if (s === "active") return "badge-active";
    if (s === "backgrounded") return "badge-backgrounded";
    if (s === "suspended") return "badge-suspended";
    if (s === "stopped") return "badge-stopped";
    return "";
  }

  function cardClass(s) {
    if (s === "active") return "card-active";
    if (s === "backgrounded") return "card-backgrounded";
    if (s === "suspended") return "card-suspended";
    if (s === "stopped") return "card-stopped";
    return "";
  }

  // --- Filtering ---
  function getFilteredProjects() {
    var list = state.projects;
    if (state.filter === "running") {
      list = list.filter(function (p) { return p.state !== "stopped"; });
    } else if (state.filter === "stopped") {
      list = list.filter(function (p) { return p.state === "stopped"; });
    }
    if (state.search) {
      var q = state.search.toLowerCase();
      list = list.filter(function (p) {
        return p.project.name.toLowerCase().includes(q) || p.project.path.toLowerCase().includes(q);
      });
    }
    return list;
  }

  // --- Actions ---
  async function doAction(method, params, successMsg) {
    try {
      await rpc(method, params);
      if (successMsg) showToast(successMsg, "success");
      lastRenderKey = "";
      await refresh();
    } catch (e) {
      showToast(e.message, "error");
    }
  }

  async function loadLogs(name) {
    try {
      var result = await rpc("logs", { name: name });
      state.logData[name] = result.logs || [];
      if (!state.activeLogTab[name] && state.logData[name].length > 0) {
        state.activeLogTab[name] = state.logData[name][0].process;
      }
    } catch (e) {
      state.logData[name] = [];
    }
  }

  async function loadConfig(name) {
    try {
      var result = await rpc("read_config", { name: name });
      state.configData[name] = { content: result.content, path: result.path, status: "" };
    } catch (e) {
      state.configData[name] = { content: "", path: "", status: e.message, error: true };
    }
  }

  async function saveConfig(name) {
    var data = state.configData[name];
    if (!data) return;
    var textarea = document.querySelector("#config-" + CSS.escape(name) + " textarea");
    if (textarea) data.content = textarea.value;
    try {
      await rpc("write_config", { name: name, content: data.content });
      data.status = "Saved";
      data.error = false;
      showToast("Config saved for " + name, "success");
    } catch (e) {
      data.status = e.message;
      data.error = true;
      showToast("Failed to save config: " + e.message, "error");
    }
    render();
  }

  // --- Log section ---
  function renderLogSection(name) {
    var logs = state.logData[name] || [];
    if (logs.length === 0) {
      return h("div", { class: "log-viewer" }, ["No logs available"]);
    }

    var tabs = h("div", { class: "log-tabs" });
    for (var i = 0; i < logs.length; i++) {
      (function (log) {
        var isActive = state.activeLogTab[name] === log.process;
        var tabBtn = h("button", {
          class: "log-tab" + (isActive ? " active" : ""),
          onclick: function () { state.activeLogTab[name] = log.process; render(); },
        });
        tabBtn.appendChild(document.createTextNode(log.process));
        if (log.content && log.content.length > 0) {
          tabBtn.appendChild(h("span", { class: "log-tab-dot" }));
        }
        tabs.appendChild(tabBtn);
      })(logs[i]);
    }

    var current = logs.find(function (l) { return l.process === state.activeLogTab[name]; }) || logs[0];
    var content = current.content || "(empty)";
    var filterText = state.logFilter[name] || "";

    var container = h("div", {});
    container.appendChild(tabs);

    // Log filter input
    var filterInput = h("input", {
      type: "text",
      class: "log-filter-input",
      placeholder: "Filter logs...",
      value: filterText,
      oninput: function (e) {
        state.logFilter[name] = e.target.value;
        renderLogContent(name, viewerEl);
      },
    });
    filterInput.value = filterText;
    container.appendChild(filterInput);

    var viewerEl = h("div", { class: "log-viewer" });
    renderLogContent(name, viewerEl);
    container.appendChild(viewerEl);
    return container;
  }

  function renderLogContent(name, viewerEl) {
    var logs = state.logData[name] || [];
    var current = logs.find(function (l) { return l.process === state.activeLogTab[name]; }) || logs[0];
    if (!current) { viewerEl.textContent = "No logs available"; return; }
    var content = current.content || "(empty)";
    var filterText = state.logFilter[name] || "";

    if (filterText) {
      var lines = content.split("\n");
      var q = filterText.toLowerCase();
      lines = lines.filter(function (line) { return line.toLowerCase().includes(q); });
      content = lines.join("\n") || "(no matching lines)";
    }

    viewerEl.innerHTML = ansiToHtml(content);
    // Auto-scroll to bottom
    viewerEl.scrollTop = viewerEl.scrollHeight;
  }

  // --- Config section ---
  function renderConfigSection(name) {
    var data = state.configData[name];
    if (!data) return h("div", {}, ["Loading..."]);

    var textarea = h("textarea", {});
    textarea.value = data.content;

    var statusEl = h("span", {
      class: "config-status" + (data.error ? " error" : data.status === "Saved" ? " success" : ""),
      textContent: data.status || "",
    });

    var saveBtn = actionButton("Save", function () { saveConfig(name); }, "btn-primary btn-sm");

    var container = h("div", { class: "config-editor", id: "config-" + name });
    if (data.path) {
      container.appendChild(h("div", { class: "config-path" }, [data.path]));
    }
    container.appendChild(textarea);
    container.appendChild(h("div", { class: "config-actions" }, [saveBtn, statusEl]));
    return container;
  }

  // --- Project card ---
  function renderProject(proj) {
    var p = proj.project;
    var s = proj.state;
    var name = p.name;
    var isStopped = s === "stopped";

    var headerChildren = [
      h("h3", { title: name }, [name]),
      h("span", { class: "badge " + badgeClass(s) }, [s]),
    ];
    var header = h("div", { class: "card-header" }, headerChildren);

    var meta = h("div", { class: "card-meta" });
    meta.appendChild(h("span", { class: "path", title: p.path }, [p.path]));
    if (!isStopped) {
      meta.appendChild(h("span", {}, ["workspace: " + p.workspace]));
      if (p.port > 0) {
        var routerUrl = "http://" + name.toLowerCase().replace(/[^a-z0-9-]/g, "-") + ".localhost:48080";
        meta.appendChild(h("a", { href: routerUrl, target: "_blank" }, [routerUrl]));
      }
    }

    var actions = h("div", { class: "card-actions" });

    if (isStopped) {
      actions.appendChild(actionButton("Start", function (e) {
        var btn = e.target.closest ? e.target.closest(".btn") : e.target;
        doActionWithButton(btn, "up", { path: p.path }, "Started " + name);
      }, "btn-primary btn-sm"));
      actions.appendChild(actionButton("Start\u2026", function () {
        openStartWithWorkspaceModal(p.path, name);
      }, "btn-secondary btn-sm"));
      actions.appendChild(actionButton("Remove", function () {
        openConfirmModal(
          "Remove " + name + "?",
          "This will unregister the project. You can add it back later.",
          function () { doAction("unregister", { name: name }, "Removed " + name); }
        );
      }, "btn-danger btn-sm"));
    } else {
      if (s !== "suspended") {
        actions.appendChild(actionButton("Focus", function (e) {
          var btn = e.target.closest ? e.target.closest(".btn") : e.target;
          doActionWithButton(btn, "focus", { name: name });
        }, "btn-secondary btn-sm"));
      }
      if (s === "suspended") {
        actions.appendChild(actionButton("Resume", function (e) {
          var btn = e.target.closest ? e.target.closest(".btn") : e.target;
          doActionWithButton(btn, "resume", { name: name }, "Resumed " + name);
        }, "btn-primary btn-sm"));
      } else {
        actions.appendChild(actionButton("Suspend", function (e) {
          var btn = e.target.closest ? e.target.closest(".btn") : e.target;
          doActionWithButton(btn, "suspend", { name: name });
        }, "btn-secondary btn-sm"));
      }
      actions.appendChild(h("span", { class: "separator" }));
      actions.appendChild(actionButton("Stop", function () {
        openConfirmModal(
          "Stop " + name + "?",
          "This will stop all processes. The project will remain registered.",
          function () { doAction("down", { name: name }, "Stopped " + name); }
        );
      }, "btn-danger btn-sm"));
    }

    // Toggle buttons for logs/config
    if (!isStopped) {
      actions.appendChild(h("span", { class: "separator" }));
      actions.appendChild(actionButton(
        state.expandedLogs[name] ? "Hide Logs" : "Logs",
        async function () {
          state.expandedLogs[name] = !state.expandedLogs[name];
          if (state.expandedLogs[name]) await loadLogs(name);
          render();
        },
        "btn-ghost btn-sm"
      ));
    }
    actions.appendChild(actionButton(
      state.expandedConfigs[name] ? "Hide Config" : "Config",
      async function () {
        state.expandedConfigs[name] = !state.expandedConfigs[name];
        if (state.expandedConfigs[name]) await loadConfig(name);
        render();
      },
      "btn-ghost btn-sm"
    ));

    var card = h("div", { class: "card " + cardClass(s) }, [header, meta, actions]);

    if (state.expandedLogs[name]) {
      card.appendChild(h("div", { class: "expandable" }, [renderLogSection(name)]));
    }
    if (state.expandedConfigs[name]) {
      card.appendChild(h("div", { class: "expandable" }, [renderConfigSection(name)]));
    }

    return card;
  }

  // --- Welcome view ---
  function renderWelcome() {
    var welcome = h("div", { class: "welcome-state" });
    welcome.appendChild(h("h2", {}, ["Welcome to projd"]));
    welcome.appendChild(h("p", { class: "welcome-subtitle" }, ["Manage your development projects from one dashboard."]));

    var steps = h("div", { class: "welcome-steps" });

    var step1 = h("div", { class: "welcome-step" });
    step1.appendChild(h("span", { class: "welcome-step-num" }, ["1"]));
    var s1text = h("div", { class: "welcome-step-text" });
    s1text.appendChild(h("strong", {}, ["Add a project directory"]));
    s1text.appendChild(h("span", {}, ["Browse to a directory with a .project.toml config"]));
    step1.appendChild(s1text);
    steps.appendChild(step1);

    var step2 = h("div", { class: "welcome-step" });
    step2.appendChild(h("span", { class: "welcome-step-num" }, ["2"]));
    var s2text = h("div", { class: "welcome-step-text" });
    s2text.appendChild(h("strong", {}, ["Configure and register"]));
    s2text.appendChild(h("span", {}, ["Review the config and choose to start or just register"]));
    step2.appendChild(s2text);
    steps.appendChild(step2);

    var step3 = h("div", { class: "welcome-step" });
    step3.appendChild(h("span", { class: "welcome-step-num" }, ["3"]));
    var s3text = h("div", { class: "welcome-step-text" });
    s3text.appendChild(h("strong", {}, ["Manage from here"]));
    s3text.appendChild(h("span", {}, ["Start, stop, focus, and view logs from this dashboard"]));
    step3.appendChild(s3text);
    steps.appendChild(step3);

    welcome.appendChild(steps);

    var cta = h("div", { class: "welcome-cta" });
    cta.appendChild(actionButton("Add Your First Project", openAddProjectModal, "btn-primary btn-lg"));
    welcome.appendChild(cta);

    var hint = h("div", { class: "welcome-hint" });
    hint.appendChild(document.createTextNode("Or press "));
    hint.appendChild(h("span", { class: "kbd" }, ["n"]));
    hint.appendChild(document.createTextNode(" to add a project, "));
    hint.appendChild(h("span", { class: "kbd" }, ["/"]));
    hint.appendChild(document.createTextNode(" to search"));
    welcome.appendChild(hint);

    return welcome;
  }

  // --- Render ---
  function renderKey() {
    var parts = [state.filter, state.search];
    for (var i = 0; i < state.projects.length; i++) {
      var p = state.projects[i];
      parts.push(p.project.name, p.state, p.focused ? "f" : "");
    }
    for (var name in state.expandedLogs) parts.push("L" + name + (state.expandedLogs[name] ? "1" : "0"));
    for (var name in state.expandedConfigs) parts.push("C" + name + (state.expandedConfigs[name] ? "1" : "0"));
    for (var name in state.logData) {
      if (state.expandedLogs[name] && state.logData[name]) {
        for (var j = 0; j < state.logData[name].length; j++) {
          var log = state.logData[name][j];
          parts.push(log.process + ":" + (log.content ? log.content.length : 0));
        }
      }
    }
    for (var name in state.activeLogTab) parts.push("T" + name + state.activeLogTab[name]);
    for (var name in state.configData) {
      if (state.expandedConfigs[name] && state.configData[name]) {
        parts.push("CS" + name + (state.configData[name].status || ""));
      }
    }
    return parts.join("|");
  }

  function render(force) {
    var key = renderKey();
    if (!force && key === lastRenderKey) return;
    lastRenderKey = key;

    updateHeaderStats();

    var container = document.getElementById("projects");
    container.innerHTML = "";
    var filtered = getFilteredProjects();
    if (filtered.length === 0) {
      if (state.projects.length === 0) {
        container.appendChild(renderWelcome());
      } else {
        var empty = h("div", { class: "empty-state" });
        empty.appendChild(h("p", {}, ["No projects match the current filter"]));
        container.appendChild(empty);
      }
      isFirstRender = false;
      return;
    }
    var animate = isFirstRender;
    for (var i = 0; i < filtered.length; i++) {
      var card = renderProject(filtered[i]);
      if (!animate) card.style.animation = "none";
      container.appendChild(card);
    }
    isFirstRender = false;
  }

  // --- Refresh / Polling ---
  async function refresh() {
    try {
      var result = await rpc("status");
      state.projects = result.projects || [];
      setConnected(true);
    } catch (e) {
      setConnected(false);
    }
    var logNames = Object.keys(state.expandedLogs).filter(function (n) { return state.expandedLogs[n]; });
    await Promise.all(logNames.map(function (n) { return loadLogs(n); }));
    render();
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(function () {
      if (!document.hidden) refresh();
    }, 2000);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  // --- SSE ---
  function connectSSE() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    try {
      eventSource = new EventSource("/events");
    } catch (e) {
      startPolling();
      return;
    }

    eventSource.onopen = function () {
      setConnected(true);
      stopPolling();
      if (sseRetryTimer) { clearTimeout(sseRetryTimer); sseRetryTimer = null; }
      refresh();
    };

    eventSource.onmessage = function (e) {
      try {
        var data = JSON.parse(e.data);
        if (data.type === "StatusChanged" && data.projects) {
          state.projects = data.projects;
          updateHeaderStats();
          render();
        } else if (data.type === "LogsAppended" && data.project && data.process) {
          var logs = state.logData[data.project];
          if (logs) {
            var logEntry = logs.find(function (l) { return l.process === data.process; });
            if (logEntry) {
              logEntry.content = (logEntry.content || "") + data.content;
              // Update DOM directly if this log tab is visible
              if (state.expandedLogs[data.project] &&
                  state.activeLogTab[data.project] === data.process) {
                var viewerEl = document.querySelector("#projects .log-viewer");
                if (viewerEl) {
                  renderLogContent(data.project, viewerEl);
                }
              }
            }
          }
        }
      } catch (err) {
        // ignore parse errors
      }
    };

    eventSource.onerror = function () {
      setConnected(false);
      if (eventSource) { eventSource.close(); eventSource = null; }
      startPolling();
      if (sseRetryTimer) clearTimeout(sseRetryTimer);
      sseRetryTimer = setTimeout(function () {
        sseRetryTimer = null;
        connectSSE();
      }, 3000);
    };
  }

  // --- Add Project modal (two-step wizard) ---
  function openAddProjectModal() {
    var wizardState = { step: 1, selectedPath: null, configContent: "", configPath: "", parsedConfig: null };

    function renderStepIndicator(modal) {
      var bar = h("div", { class: "wizard-steps" });
      var s1cls = "wizard-step" + (wizardState.step === 1 ? " wizard-step-active" : wizardState.step > 1 ? " wizard-step-done" : "");
      var s2cls = "wizard-step" + (wizardState.step === 2 ? " wizard-step-active" : "");
      bar.appendChild(h("span", { class: s1cls }, ["1. Select Directory"]));
      bar.appendChild(h("span", { class: "wizard-step-separator" }, ["\u2192"]));
      bar.appendChild(h("span", { class: s2cls }, ["2. Configure"]));
      modal.appendChild(bar);
    }

    function renderBreadcrumbs(modal, fullPath, onNavigate) {
      var bar = h("div", { class: "breadcrumb-bar" });
      var parts = fullPath.split("/").filter(Boolean);
      for (var i = 0; i < parts.length; i++) {
        if (i > 0) bar.appendChild(h("span", { class: "breadcrumb-sep" }, ["/"]));
        (function (idx) {
          var segPath = "/" + parts.slice(0, idx + 1).join("/");
          var link = h("span", {
            class: "breadcrumb-segment",
            textContent: parts[idx],
            onclick: function () { onNavigate(segPath); },
          });
          bar.appendChild(link);
        })(i);
      }
      modal.appendChild(bar);
    }

    function goToStep2(modal, selectedPath) {
      wizardState.selectedPath = selectedPath;
      wizardState.step = 2;
      renderStep2(modal);
    }

    function renderStep1(modal, browsePath) {
      modal.innerHTML = "";
      modal.appendChild(h("h2", {}, ["Add Project"]));
      renderStepIndicator(modal);

      var loading = h("div", { class: "browse-status", textContent: "Loading..." });
      modal.appendChild(loading);

      Promise.all([
        rpc("browse", { path: browsePath }),
        rpc("status"),
      ]).then(function (results) {
        var result = results[0];
        var statusResult = results[1];
        loading.remove();

        var registeredPaths = {};
        if (statusResult && statusResult.projects) {
          for (var ri = 0; ri < statusResult.projects.length; ri++) {
            registeredPaths[statusResult.projects[ri].project.path] = true;
          }
        }

        renderBreadcrumbs(modal, result.path, function (path) {
          renderStep1(modal, path);
        });

        var list = h("div", { class: "browse-list" });

        if (result.parent) {
          list.appendChild(h("div", {
            class: "browse-entry browse-parent",
            textContent: "..",
            onclick: function () { renderStep1(modal, result.parent); },
          }));
        }

        for (var i = 0; i < result.entries.length; i++) {
          (function (entry) {
            var isRegistered = registeredPaths[entry.path];
            var entryEl = h("div", {
              class: "browse-entry" + (entry.has_project_toml ? " browse-has-config" : ""),
            });
            var icon = h("span", {
              class: "browse-entry-icon",
              textContent: entry.has_project_toml ? "\u{1F4E6}" : "\u{1F4C1}",
            });
            entryEl.appendChild(icon);
            var nameSpan = h("span", {
              class: "browse-entry-name",
              textContent: entry.name,
              onclick: function (e) { e.stopPropagation(); renderStep1(modal, entry.path); },
            });
            entryEl.appendChild(nameSpan);
            if (isRegistered) {
              entryEl.appendChild(h("span", { class: "browse-registered-badge", textContent: "registered" }));
            } else if (entry.has_project_toml) {
              entryEl.appendChild(h("span", { class: "browse-entry-badge", textContent: ".project.toml" }));
            }
            if (!isRegistered) {
              var selectBtn = h("button", {
                class: "btn btn-primary btn-xs",
                textContent: "Select",
                onclick: function (e) { e.stopPropagation(); goToStep2(modal, entry.path); },
              });
              entryEl.appendChild(selectBtn);
            }
            list.appendChild(entryEl);
          })(result.entries[i]);
        }

        if (result.entries.length === 0) {
          list.appendChild(h("div", { class: "browse-empty", textContent: "No subdirectories" }));
        }

        modal.appendChild(list);
        wizardState.selectedPath = result.path;

        var actions = h("div", { class: "modal-actions" });
        actions.appendChild(actionButton("Cancel", closeModal, "btn-secondary"));
        actions.appendChild(actionButton("Use This Directory \u2192", function () {
          goToStep2(modal, result.path);
        }, "btn-primary"));
        modal.appendChild(actions);
      }).catch(function (e) {
        loading.textContent = "Error: " + e.message;
      });
    }

    // --- Helpers to parse/serialize simple TOML for the form ---
    function parseSimpleToml(text) {
      // Minimal parser: extract top-level keys and known sections
      var cfg = { name: "", workspace: "", server_command: "", server_port_env: "", server_ready_pattern: "",
                  terminals: [], editor_command: "", browser_command: "", browser_urls: "", browser_isolate: true, raw: text };
      try {
        var lines = text.split("\n");
        var section = "";
        var termIdx = -1;
        for (var i = 0; i < lines.length; i++) {
          var line = lines[i].trim();
          if (!line || line.startsWith("#")) continue;
          var secMatch = line.match(/^\[{1,2}([a-z_.]+)\]{1,2}$/);
          if (secMatch) {
            section = secMatch[1];
            if (section === "terminals") { cfg.terminals.push({ name: "", command: "" }); termIdx++; }
            continue;
          }
          var kvMatch = line.match(/^(\w+)\s*=\s*(.+)$/);
          if (!kvMatch) continue;
          var key = kvMatch[1];
          var val = kvMatch[2].trim();
          // Strip quotes
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          // Strip array brackets for single-value arrays
          if (val.startsWith("[") && val.endsWith("]")) {
            var inner = val.slice(1, -1).trim();
            // Keep as-is for form display
            val = inner.replace(/^"(.*)"$/, "$1");
          }
          if (section === "") {
            if (key === "name") cfg.name = val;
            else if (key === "workspace") cfg.workspace = val;
          } else if (section === "server") {
            if (key === "command") cfg.server_command = val;
            else if (key === "port_env") cfg.server_port_env = val;
            else if (key === "ready_pattern") cfg.server_ready_pattern = val;
          } else if (section === "terminals" && termIdx >= 0) {
            if (key === "name") cfg.terminals[termIdx].name = val;
            else if (key === "command") cfg.terminals[termIdx].command = val;
          } else if (section === "editor") {
            if (key === "command") cfg.editor_command = val;
          } else if (section === "browser") {
            if (key === "command") cfg.browser_command = val;
            else if (key === "urls") cfg.browser_urls = val;
            else if (key === "isolate_profile") cfg.browser_isolate = (val === "true");
          }
        }
      } catch (e) { /* fall back to raw */ }
      return cfg;
    }

    function serializeToToml(cfg) {
      var lines = [];
      lines.push('name = "' + (cfg.name || "project") + '"');
      if (cfg.workspace) lines.push('workspace = "' + cfg.workspace + '"');
      lines.push("");
      if (cfg.server_command) {
        lines.push("[server]");
        lines.push('command = "' + cfg.server_command + '"');
        if (cfg.server_port_env) lines.push('port_env = "' + cfg.server_port_env + '"');
        if (cfg.server_ready_pattern) lines.push('ready_pattern = "' + cfg.server_ready_pattern + '"');
        lines.push("");
      }
      for (var i = 0; i < cfg.terminals.length; i++) {
        var t = cfg.terminals[i];
        if (!t.name && !t.command) continue;
        lines.push("[[terminals]]");
        lines.push('name = "' + (t.name || "terminal") + '"');
        if (t.command) lines.push('command = "' + t.command + '"');
        lines.push("");
      }
      if (cfg.editor_command) {
        lines.push("[editor]");
        lines.push('command = "' + cfg.editor_command + '"');
        lines.push("");
      }
      if (cfg.browser_command || cfg.browser_urls) {
        lines.push("[browser]");
        if (cfg.browser_command) lines.push('command = "' + cfg.browser_command + '"');
        if (cfg.browser_urls) lines.push('urls = ["' + cfg.browser_urls + '"]');
        if (cfg.browser_isolate) lines.push("isolate_profile = true");
        lines.push("");
      }
      return lines.join("\n") + "\n";
    }

    function formField(label, value, placeholder, onChange) {
      var row = h("div", { class: "wizard-field" });
      row.appendChild(h("label", { class: "wizard-field-label" }, [label]));
      var input = h("input", { type: "text", class: "wizard-field-input", placeholder: placeholder || "" });
      input.value = value || "";
      input.addEventListener("input", function () { onChange(input.value); });
      row.appendChild(input);
      return row;
    }

    function optionalSection(form, label, desc, hasContent, buildFields, onDisable) {
      var title = h("div", { class: "wizard-section-title wizard-section-toggle" });
      var enableLabel = h("label", { class: "wizard-toggle-label" });
      var check = h("input", { type: "checkbox" });
      check.checked = hasContent;
      enableLabel.appendChild(check);
      enableLabel.appendChild(document.createTextNode(" " + label));
      title.appendChild(enableLabel);
      title.appendChild(h("span", { class: "wizard-optional-tag" }, [desc]));
      form.appendChild(title);

      var fields = h("div", { class: "wizard-optional-fields" });
      if (!hasContent) fields.hidden = true;
      buildFields(fields);
      form.appendChild(fields);

      check.addEventListener("change", function () {
        fields.hidden = !check.checked;
        if (!check.checked && onDisable) onDisable();
        if (check.checked) {
          fields.innerHTML = "";
          buildFields(fields);
        }
      });
    }

    function renderStep2(modal) {
      modal.innerHTML = "";
      modal.appendChild(h("h2", {}, ["Add Project"]));
      renderStepIndicator(modal);

      var loading = h("div", { class: "browse-status", textContent: "Loading config..." });
      modal.appendChild(loading);

      rpc("init_config", { path: wizardState.selectedPath }).then(function (result) {
        loading.remove();
        wizardState.configPath = result.path;
        wizardState.configContent = result.content;
        var cfg = parseSimpleToml(result.content);
        wizardState.parsedConfig = cfg;

        var dirName = wizardState.selectedPath.split("/").filter(Boolean).pop() || "project";
        if (!cfg.name) cfg.name = dirName;

        modal.appendChild(h("div", { class: "config-path" }, [result.path]));

        var form = h("div", { class: "wizard-form" });

        // --- General (always visible) ---
        form.appendChild(h("div", { class: "wizard-section-title" }, ["General"]));
        form.appendChild(formField("Name", cfg.name, dirName, function (v) { cfg.name = v; }));
        form.appendChild(formField("Workspace", cfg.workspace, "auto-assigned (1, 2, 3...)", function (v) { cfg.workspace = v; }));

        // --- Server ---
        optionalSection(form, "Server", "dev server with HTTP proxy", !!cfg.server_command,
          function (f) {
            f.appendChild(formField("Command", cfg.server_command, "npm run dev", function (v) { cfg.server_command = v; }));
            f.appendChild(formField("Port env", cfg.server_port_env, "PORT", function (v) { cfg.server_port_env = v; }));
            f.appendChild(formField("Ready pattern", cfg.server_ready_pattern, "listening on, ready in", function (v) { cfg.server_ready_pattern = v; }));
          },
          function () { cfg.server_command = ""; cfg.server_port_env = ""; cfg.server_ready_pattern = ""; }
        );

        // --- Terminal ---
        var termHasContent = cfg.terminals.some(function (t) { return t.name || t.command; });
        optionalSection(form, "Terminal", "open terminal windows", termHasContent,
          function (f) {
            if (cfg.terminals.length === 0) cfg.terminals.push({ name: "", command: "" });
            for (var ti = 0; ti < cfg.terminals.length; ti++) {
              (function (idx) {
                f.appendChild(formField("Name", cfg.terminals[idx].name, "dev, logs, watch...", function (v) { cfg.terminals[idx].name = v; }));
                f.appendChild(formField("Command", cfg.terminals[idx].command, "ghostty, kitty, alacritty", function (v) { cfg.terminals[idx].command = v; }));
              })(ti);
            }
          },
          function () { cfg.terminals = []; }
        );

        // --- Editor ---
        optionalSection(form, "Editor", "open code editor", !!cfg.editor_command,
          function (f) {
            f.appendChild(formField("Command", cfg.editor_command, "code --new-window .", function (v) { cfg.editor_command = v; }));
          },
          function () { cfg.editor_command = ""; }
        );

        // --- Browser ---
        var browserHasContent = !!(cfg.browser_command || cfg.browser_urls);
        optionalSection(form, "Browser", "open browser tabs", browserHasContent,
          function (f) {
            f.appendChild(formField("Browser", cfg.browser_command, "helium, zen-browser, google-chrome", function (v) { cfg.browser_command = v; }));
            f.appendChild(formField("URLs", cfg.browser_urls, "${PROJ_ORIGIN}", function (v) { cfg.browser_urls = v; }));
            var isolateGroup = h("div", { class: "wizard-field" });
            var isolateLabel = h("label", { class: "wizard-check-label" });
            var isolateCheck = h("input", { type: "checkbox" });
            isolateCheck.checked = cfg.browser_isolate;
            isolateCheck.addEventListener("change", function () { cfg.browser_isolate = isolateCheck.checked; });
            isolateLabel.appendChild(isolateCheck);
            isolateLabel.appendChild(document.createTextNode(" Isolate browser profile"));
            isolateGroup.appendChild(isolateLabel);
            f.appendChild(isolateGroup);
          },
          function () { cfg.browser_command = ""; cfg.browser_urls = ""; cfg.browser_isolate = false; }
        );

        modal.appendChild(form);

        // --- Raw TOML toggle ---
        var rawSection = h("div", { class: "wizard-raw-section" });
        var rawToggle = h("button", {
          class: "btn btn-ghost btn-sm",
          textContent: "Show raw TOML",
          onclick: function () {
            if (rawTextarea.hidden) {
              rawTextarea.value = serializeToToml(cfg);
              rawTextarea.hidden = false;
              rawToggle.textContent = "Hide raw TOML";
            } else {
              rawTextarea.hidden = true;
              rawToggle.textContent = "Show raw TOML";
            }
          },
        });
        rawSection.appendChild(rawToggle);
        var rawTextarea = h("textarea", { class: "wizard-config-editor", hidden: "" });
        rawTextarea.value = result.content;
        rawSection.appendChild(rawTextarea);
        modal.appendChild(rawSection);

        // --- Mode selection ---
        var modeGroup = h("div", { class: "form-group", style: "margin-top: 12px" });
        var radioGroup = h("div", { class: "radio-group" });
        var radioStart = h("input", { type: "radio", name: "add-mode", value: "start", id: "mode-start", checked: "" });
        radioGroup.appendChild(h("label", { for: "mode-start" }, [radioStart, " Register and start"]));
        var radioRegister = h("input", { type: "radio", name: "add-mode", value: "register", id: "mode-register" });
        radioGroup.appendChild(h("label", { for: "mode-register" }, [radioRegister, " Register only"]));
        modeGroup.appendChild(radioGroup);
        modal.appendChild(modeGroup);

        var actions = h("div", { class: "modal-actions" });
        actions.appendChild(actionButton("\u2190 Back", function () {
          wizardState.step = 1;
          renderStep1(modal, wizardState.selectedPath);
        }, "btn-secondary"));
        actions.appendChild(actionButton("Add Project", async function (e) {
          var btn = e.target.closest ? e.target.closest(".btn") : e.target;
          var origText = btn.textContent;
          btn.textContent = "Adding...";
          btn.disabled = true;
          btn.classList.add("btn-loading");
          try {
            // Use raw TOML if visible, otherwise serialize from form
            var newContent;
            if (!rawTextarea.hidden) {
              newContent = rawTextarea.value;
            } else {
              newContent = serializeToToml(cfg);
            }
            if (newContent !== result.content) {
              await rpc("write_init_config", { path: wizardState.configPath, content: newContent });
            }
            var mode = document.querySelector('input[name="add-mode"]:checked').value;
            if (mode === "start") {
              var upParams = { path: wizardState.selectedPath };
              if (cfg.workspace) upParams.workspace = cfg.workspace;
              await rpc("up", upParams);
              showToast("Started project", "success");
            } else {
              await rpc("register", { path: wizardState.selectedPath });
              showToast("Registered project", "success");
            }
            closeModal();
            lastRenderKey = "";
            await refresh();
          } catch (err) {
            btn.textContent = origText;
            btn.disabled = false;
            btn.classList.remove("btn-loading");
            showToast(err.message, "error", 5000);
          }
        }, "btn-primary"));
        modal.appendChild(actions);
      }).catch(function (e) {
        loading.textContent = "Error: " + e.message;
      });
    }

    openModal(function (modal) {
      renderStep1(modal, null);
    });
  }

  // --- Workspace override modal for stopped projects ---
  function openStartWithWorkspaceModal(projectPath, projectName) {
    openModal(function (modal) {
      modal.appendChild(h("h2", {}, ["Start " + projectName]));
      var group = h("div", { class: "form-group" });
      group.appendChild(h("label", {}, ["Workspace (optional)"]));
      var wsInput = h("input", {
        type: "text",
        placeholder: "Leave blank for default",
        id: "start-workspace",
      });
      group.appendChild(wsInput);
      modal.appendChild(group);
      var actions = h("div", { class: "modal-actions" });
      actions.appendChild(actionButton("Cancel", closeModal, "btn-secondary"));
      actions.appendChild(actionButton("Start", async function (e) {
        var btn = e.target.closest ? e.target.closest(".btn") : e.target;
        var ws = document.getElementById("start-workspace").value.trim();
        closeModal();
        var params = { path: projectPath };
        if (ws) params.workspace = ws;
        doActionWithButton(btn, "up", params, "Started " + projectName);
      }, "btn-primary"));
      modal.appendChild(actions);
    });
  }

  // --- Filter tabs ---
  function initFilterTabs() {
    var tabs = document.querySelectorAll(".filter-tab");
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        tabs.forEach(function (t) { t.classList.remove("active"); });
        tab.classList.add("active");
        state.filter = tab.getAttribute("data-filter");
        render();
      });
    });
  }

  // --- Search ---
  function initSearch() {
    var input = document.getElementById("search");
    input.addEventListener("input", function () {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(function () {
        state.search = input.value.trim();
        render();
      }, 150);
    });
  }

  // --- Keyboard shortcuts ---
  function initKeyboard() {
    document.addEventListener("keydown", function (e) {
      if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
        if (e.key === "Escape") {
          e.target.blur();
          closeModal();
        }
        return;
      }

      if (e.key === "/") {
        e.preventDefault();
        document.getElementById("search").focus();
      } else if (e.key === "n") {
        e.preventDefault();
        openAddProjectModal();
      } else if (e.key === "Escape") {
        closeModal();
      }
    });
  }

  // --- Add project button ---
  function initAddButton() {
    document.getElementById("add-project-btn").addEventListener("click", openAddProjectModal);
  }

  // --- Init ---
  initFilterTabs();
  initSearch();
  initKeyboard();
  initAddButton();
  refresh();
  connectSSE();
})();
