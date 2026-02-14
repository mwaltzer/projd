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
    connected: false,
  };

  let rpcId = 0;
  let pollTimer = null;
  let searchDebounce = null;
  let lastRenderKey = "";
  let isFirstRender = true;

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
      lastRenderKey = ""; // force re-render after action
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
        tabs.appendChild(h("button", {
          class: "log-tab" + (isActive ? " active" : ""),
          textContent: log.process,
          onclick: function () { state.activeLogTab[name] = log.process; render(); },
        }));
      })(logs[i]);
    }

    var current = logs.find(function (l) { return l.process === state.activeLogTab[name]; }) || logs[0];
    var viewer = h("div", { class: "log-viewer" }, [current.content || "(empty)"]);
    return h("div", {}, [tabs, viewer]);
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

    var header = h("div", { class: "card-header" }, [
      h("h3", { title: name }, [name]),
      h("span", { class: "badge " + badgeClass(s) }, [s]),
    ]);

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
      actions.appendChild(actionButton("Start", function () {
        doAction("up", { path: p.path }, "Started " + name);
      }, "btn-primary btn-sm"));
      actions.appendChild(actionButton("Remove", function () {
        openConfirmModal(
          "Remove " + name + "?",
          "This will unregister the project. You can add it back later.",
          function () { doAction("unregister", { name: name }, "Removed " + name); }
        );
      }, "btn-danger btn-sm"));
    } else {
      if (s !== "suspended") {
        actions.appendChild(actionButton("Focus", function () {
          doAction("focus", { name: name });
        }, "btn-secondary btn-sm"));
      }
      if (s === "suspended") {
        actions.appendChild(actionButton("Resume", function () {
          doAction("resume", { name: name }, "Resumed " + name);
        }, "btn-primary btn-sm"));
      } else {
        actions.appendChild(actionButton("Suspend", function () {
          doAction("suspend", { name: name });
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

  // --- Render ---
  function renderKey() {
    // Build a key from data that affects rendering
    var parts = [state.filter, state.search];
    for (var i = 0; i < state.projects.length; i++) {
      var p = state.projects[i];
      parts.push(p.project.name, p.state, p.focused ? "f" : "");
    }
    // Include expanded sections
    for (var name in state.expandedLogs) parts.push("L" + name + (state.expandedLogs[name] ? "1" : "0"));
    for (var name in state.expandedConfigs) parts.push("C" + name + (state.expandedConfigs[name] ? "1" : "0"));
    // Include log data content for expanded logs
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

    var container = document.getElementById("projects");
    container.innerHTML = "";
    var filtered = getFilteredProjects();
    if (filtered.length === 0) {
      var msg = state.projects.length === 0
        ? "No projects registered"
        : "No projects match the current filter";
      var empty = h("div", { class: "empty-state" });
      empty.appendChild(h("p", {}, [msg]));
      if (state.projects.length === 0) {
        empty.appendChild(actionButton("Add Project", openAddProjectModal, "btn-primary"));
      }
      container.appendChild(empty);
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
    // Refresh expanded logs in parallel
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

  // --- Add Project modal (directory browser) ---
  function openAddProjectModal() {
    var selectedPath = null;

    function renderBrowser(modal, browsePath) {
      modal.innerHTML = "";
      modal.appendChild(h("h2", {}, ["Add Project"]));

      var loading = h("div", { class: "browse-status", textContent: "Loading..." });
      modal.appendChild(loading);

      rpc("browse", { path: browsePath }).then(function (result) {
        loading.remove();

        // Current path display
        var pathBar = h("div", { class: "browse-path" }, [result.path]);
        modal.appendChild(pathBar);

        // Directory listing
        var list = h("div", { class: "browse-list" });

        // Parent directory link
        if (result.parent) {
          list.appendChild(h("div", {
            class: "browse-entry browse-parent",
            textContent: "..",
            onclick: function () { renderBrowser(modal, result.parent); },
          }));
        }

        for (var i = 0; i < result.entries.length; i++) {
          (function (entry) {
            var entryEl = h("div", {
              class: "browse-entry" + (entry.has_project_toml ? " browse-has-config" : ""),
            });
            var nameSpan = h("span", { class: "browse-entry-name", textContent: entry.name });
            entryEl.appendChild(nameSpan);
            if (entry.has_project_toml) {
              entryEl.appendChild(h("span", { class: "browse-entry-badge", textContent: ".project.toml" }));
            }
            entryEl.addEventListener("click", function () {
              renderBrowser(modal, entry.path);
            });
            list.appendChild(entryEl);
          })(result.entries[i]);
        }

        if (result.entries.length === 0) {
          list.appendChild(h("div", { class: "browse-empty", textContent: "No subdirectories" }));
        }

        modal.appendChild(list);
        selectedPath = result.path;

        // Mode selection
        var modeGroup = h("div", { class: "form-group", style: "margin-top: 12px" });
        var radioGroup = h("div", { class: "radio-group" });
        var radioStart = h("input", { type: "radio", name: "add-mode", value: "start", id: "mode-start", checked: "" });
        radioGroup.appendChild(h("label", { for: "mode-start" }, [radioStart, " Register and start"]));
        var radioRegister = h("input", { type: "radio", name: "add-mode", value: "register", id: "mode-register" });
        radioGroup.appendChild(h("label", { for: "mode-register" }, [radioRegister, " Register only"]));
        modeGroup.appendChild(radioGroup);
        modal.appendChild(modeGroup);

        // Actions
        var actions = h("div", { class: "modal-actions" });
        actions.appendChild(actionButton("Cancel", closeModal, "btn-secondary"));
        actions.appendChild(actionButton("Select This Directory", async function () {
          if (!selectedPath) return;
          var mode = document.querySelector('input[name="add-mode"]:checked').value;
          closeModal();
          try {
            await rpc("init_config", { path: selectedPath });
            if (mode === "start") {
              await rpc("up", { path: selectedPath });
              showToast("Started project", "success");
            } else {
              await rpc("register", { path: selectedPath });
              showToast("Registered project", "success");
            }
            lastRenderKey = "";
            await refresh();
          } catch (e) {
            showToast(e.message, "error", 5000);
          }
        }, "btn-primary"));
        modal.appendChild(actions);
      }).catch(function (e) {
        loading.textContent = "Error: " + e.message;
      });
    }

    openModal(function (modal) {
      renderBrowser(modal, null);
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
      // Don't capture when typing in inputs
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
  startPolling();
})();
