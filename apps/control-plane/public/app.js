// Configuration
const CONFIG = {
  REFRESH_MS: 3000,
  DIR_LIMIT: 128,
  TOAST_DURATION: 5000,
  RECONNECT_DELAY: 1000,
  MAX_LOG_ENTRIES: 100,
  SNAPSHOT_TAIL: 100,
};

const STORAGE_KEYS = {
  SESSION_STATE: 'opencode_session_state_v1',
};

// State Management
const state = {
  devices: new Map(),
  selectedDeviceId: null,
  treeByDevice: new Map(),
  selectedFolderPath: null,
  sessionId: null,
  sessionUrl: null,
  isSessionActive: false,
  uiSocket: null,
  uiReady: false,
  reconnectTimer: null,
  contextMenuTarget: null,
  modalCallback: null,
  sidebarOpen: true,
  logEntries: [],
  // Git state
  gitStatus: null,
  hasGitRepo: false,
  snapshotHydratedForSession: null,
};

// DOM Elements
const elements = {};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  initializeElements();
  restoreSessionState();
  bindEventListeners();
  connectUiSocket();
  fetchDevices();
  setInterval(fetchDevices, CONFIG.REFRESH_MS);
  updateConnectionStatus('Connecting...', false);
});

function initializeElements() {
  const ids = [
    'connection-status', 'devices-list', 'devices-empty', 'refresh-devices',
    'online-count', 'total-count', 'header-device', 'toggle-sidebar',
    'sidebar', 'tree-root', 'selected-path', 'session-status',
    'start-session', 'start-session-text', 'stop-session',
    'open-in-browser', 'copy-url', 'context-menu', 'modal',
    'modal-title', 'modal-label', 'modal-input', 'modal-message',
    'modal-close', 'modal-cancel', 'modal-confirm', 'toast-container',
     'session-id-display', 'project-path-display', 'status-display',
     'activity-log', 'clear-log', 'port-exposure', 'port-links',
      // Git elements
     'git-status-badge', 'git-branch', 'git-added-count', 'git-modified-count', 'git-untracked-count',
     'git-init', 'git-clone', 'git-config', 'git-add', 'git-commit', 'git-pull', 'git-push', 'git-branch-btn', 'git-checkout', 'git-refresh',
  ];
  
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) elements[id] = el;
  });
  
  // Get nested elements
  elements.statusText = elements['connection-status']?.querySelector('.status-text');
  elements.statusDot = elements['connection-status']?.querySelector('.status-dot');
}

function bindEventListeners() {
  // Device list
  elements['refresh-devices']?.addEventListener('click', fetchDevices);
  
  // Sidebar toggle
  elements['toggle-sidebar']?.addEventListener('click', toggleSidebar);
  
  // Session controls
  elements['start-session']?.addEventListener('click', handleStartSession);
  elements['stop-session']?.addEventListener('click', handleStopSession);
  elements['open-in-browser']?.addEventListener('click', openInBrowser);
  elements['copy-url']?.addEventListener('click', copySessionUrl);
  
  // Context menu
  document.querySelectorAll('.context-menu-item').forEach(item => {
    item.addEventListener('click', handleContextMenuAction);
  });
  
  // Modal
  elements['modal-close']?.addEventListener('click', closeModal);
  elements['modal-cancel']?.addEventListener('click', closeModal);
  elements['modal-confirm']?.addEventListener('click', () => {
    const callback = state.modalCallback;
    const value = elements['modal-input']?.value.trim() || '';
    closeModal();
    if (callback) {
      void callback(value);
    }
  });
  
  // Close context menu on click outside
  document.addEventListener('click', (e) => {
    if (!elements['context-menu']?.contains(e.target)) {
      hideContextMenu();
    }
  });
  
  // Clear log button
  elements['clear-log']?.addEventListener('click', clearActivityLog);
  
  // Tool tabs switching
  document.querySelectorAll('.tool-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      const tool = e.target.dataset.tool;
      switchToolTab(tool);
    });
  });
  
  // Git event listeners
  elements['git-init']?.addEventListener('click', () => void handleGitInit());
  elements['git-clone']?.addEventListener('click', () => void handleGitClone());
  elements['git-config']?.addEventListener('click', () => void handleGitConfig());
  elements['git-add']?.addEventListener('click', () => void handleGitAdd());
  elements['git-commit']?.addEventListener('click', () => void handleGitCommit());
  elements['git-pull']?.addEventListener('click', () => void handleGitPull());
  elements['git-push']?.addEventListener('click', () => void handleGitPush());
  elements['git-branch-btn']?.addEventListener('click', () => void handleGitBranch());
  elements['git-checkout']?.addEventListener('click', () => void handleGitCheckout());
  elements['git-refresh']?.addEventListener('click', () => void refreshGitStatus());
  
  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      hideContextMenu();
      closeModal();
    }
  });
}

// Tool Tab Switching
function switchToolTab(tool) {
  // Update tab buttons
  document.querySelectorAll('.tool-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.tool === tool);
  });
  
  // Update tool content
  document.querySelectorAll('.tool-content').forEach(content => {
    content.classList.toggle('active', content.id === `${tool}-tool`);
  });
}

// Device Management
async function fetchDevices() {
  try {
    const payload = await apiJson('/devices');
    const now = Date.now();
    const onlineIds = new Set();
    
    for (const device of Array.isArray(payload.devices) ? payload.devices : []) {
      if (typeof device?.d !== 'string') continue;
      
      onlineIds.add(device.d);
      const previous = state.devices.get(device.d) || {};
      const previousPorts = Array.isArray(previous.pt) ? previous.pt.slice().sort((a, b) => a - b) : [];
      const nextPorts = Array.isArray(device.pt) ? device.pt.filter(p => Number.isInteger(p)).slice().sort((a, b) => a - b) : [];
      state.devices.set(device.d, {
        ...previous,
        ...device,
        online: true,
        seenAt: now,
      });

      if (state.selectedDeviceId === device.d) {
        const changed = previousPorts.length !== nextPorts.length || previousPorts.some((port, index) => port !== nextPorts[index]);
        if (changed && nextPorts.length > 0) {
          addLogEntry('info', `Detected exposed ports: ${nextPorts.map(port => `:${port}`).join(', ')}`);
        }
      }
    }
    
    // Mark offline devices
    for (const [deviceId, entry] of state.devices.entries()) {
      if (!onlineIds.has(deviceId)) {
        state.devices.set(deviceId, { ...entry, online: false, pt: [] });
      }
    }
    
    renderDevices();
    updateStats();
    updatePortLinks();
    updateConnectionStatus('Connected', true);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'device_fetch_failed';
    updateConnectionStatus('Connection error', false);
    console.error('Device fetch failed:', message);
  }
}

function renderDevices() {
  const list = elements['devices-list'];
  const empty = elements['devices-empty'];
  if (!list || !empty) return;
  
  const deviceEntries = Array.from(state.devices.values()).sort((a, b) => {
    const aOnline = a.online ? 1 : 0;
    const bOnline = b.online ? 1 : 0;
    if (aOnline !== bOnline) return bOnline - aOnline;
    
    const aName = String(a.hn || a.d || '');
    const bName = String(b.hn || b.d || '');
    return aName.localeCompare(bName);
  });
  
  list.innerHTML = '';
  
  if (deviceEntries.length === 0) {
    empty.style.display = 'flex';
    return;
  }
  
  empty.style.display = 'none';
  
  for (const device of deviceEntries) {
    const item = document.createElement('li');
    item.className = `device-item${state.selectedDeviceId === device.d ? ' active' : ''}`;
    item.addEventListener('click', () => selectDevice(device.d));
    
    item.innerHTML = `
      <div class="device-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
          <line x1="8" y1="21" x2="16" y2="21"/>
          <line x1="12" y1="17" x2="12" y2="21"/>
        </svg>
      </div>
      <div class="device-info">
        <div class="device-name">${escapeHtml(device.hn || device.d)}</div>
        <div class="device-meta">${escapeHtml([device.os, device.av].filter(Boolean).join(' • ') || 'No metadata')}</div>
      </div>
      <span class="device-status ${device.online ? 'online' : 'offline'}"></span>
    `;
    
    list.appendChild(item);
  }
}

function updateStats() {
  const devices = Array.from(state.devices.values());
  const online = devices.filter(d => d.online).length;
  
  if (elements['online-count']) elements['online-count'].textContent = online;
  if (elements['total-count']) elements['total-count'].textContent = devices.length;
}

function updateConnectionStatus(text, connected) {
  if (elements.statusText) elements.statusText.textContent = text;
  if (elements.statusDot) elements.statusDot.classList.toggle('online', connected);
}

function selectDevice(deviceId) {
  // Deselect if clicking same device
  if (state.selectedDeviceId === deviceId) return;
  
  state.selectedDeviceId = deviceId;
  state.selectedFolderPath = null;
  state.sessionId = null;
  state.sessionUrl = null;
  state.isSessionActive = false;
  state.snapshotHydratedForSession = null;
  clearSessionState();
  state.hasGitRepo = false;
  state.gitStatus = null;
  
  ensureRootNode(deviceId);
  
  const device = state.devices.get(deviceId);
  if (elements['header-device']) {
    elements['header-device'].textContent = device ? (device.hn || device.d) : 'Select a device';
  }
  
  addLogEntry('device', `Selected device: ${device ? (device.hn || device.d) : deviceId}`);
  
  renderDevices();
  renderTree();
  updateSessionUI();
  updateGitUI();
}

function toggleSidebar() {
  state.sidebarOpen = !state.sidebarOpen;
  elements['sidebar']?.classList.toggle('collapsed', !state.sidebarOpen);
}

// Tree Management
function ensureRootNode(deviceId) {
  if (state.treeByDevice.has(deviceId)) return;
  
  state.treeByDevice.set(deviceId, {
    name: 'project',
    path: '.',
    kind: 'd',
    expanded: true,
    loaded: false,
    loading: false,
    error: null,
    children: [],
  });
}

function renderTree() {
  const root = elements['tree-root'];
  const pathBadge = elements['selected-path'];
  if (!root) return;
  
  root.innerHTML = '';
  
  if (!state.selectedDeviceId) {
    if (pathBadge) pathBadge.textContent = '/';
    renderEmptyTreeState(root);
    return;
  }
  
  const treeRoot = state.treeByDevice.get(state.selectedDeviceId);
  if (!treeRoot) return;
  
  if (!treeRoot.loaded && !treeRoot.loading && !treeRoot.error) {
    loadNode(treeRoot);
  }
  
  const list = document.createElement('ul');
  list.className = 'tree';
  appendNode(list, treeRoot, true);
  root.appendChild(list);
  
  if (pathBadge) pathBadge.textContent = state.selectedFolderPath || '/';
}

function renderEmptyTreeState(container) {
  container.innerHTML = `
    <div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <path d="M9 15l2 2 4-4"/>
      </svg>
      <span>Select a device to browse files</span>
    </div>
  `;
}

function appendNode(parent, node, isRoot = false) {
  const item = document.createElement('li');
  item.className = 'tree-node';
  
  const row = document.createElement('div');
  row.className = 'tree-row';
  
  if (node.kind === 'd') {
    // Folder
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = `tree-toggle${node.expanded ? ' expanded' : ''}`;
    toggle.innerHTML = '▸';
    toggle.disabled = node.loading;
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      toggleNode(node);
    });
    
    const icon = document.createElement('span');
    icon.className = 'tree-icon folder';
    icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>`;
    
    const select = document.createElement('button');
    select.type = 'button';
    select.className = `tree-select${state.selectedFolderPath === node.path ? ' active' : ''}`;
    select.innerHTML = `<span class="tree-label">${isRoot ? '/project' : escapeHtml(node.name)}/</span>`;
    select.addEventListener('click', () => {
      const previousPath = state.selectedFolderPath;
      state.selectedFolderPath = node.path;
      // Reset session when folder changes
      state.sessionId = null;
      state.sessionUrl = null;
      state.isSessionActive = false;
      state.snapshotHydratedForSession = null;
      clearSessionState();
      renderTree();
      updateSessionUI();
      if (previousPath !== node.path) {
        addLogEntry('info', `Selected folder: ${node.path === '.' ? '/project' : node.path}`);
        // Refresh git status for the new folder
        void refreshGitStatus();
      }
    });
    
    // Context menu
    row.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showContextMenu(e, node);
    });
    
    row.append(toggle, icon, select);
    item.appendChild(row);
    
    if (node.expanded) {
      const childList = document.createElement('ul');
      childList.className = 'tree';
      
      if (node.loading) {
        childList.innerHTML = '<li class="tree-loading">Loading...</li>';
      } else if (node.error) {
        childList.innerHTML = `<li class="tree-error">Error: ${escapeHtml(node.error)}</li>`;
      } else if (node.children.length === 0) {
        childList.innerHTML = '<li class="tree-loading">(empty)</li>';
      } else {
        for (const child of node.children) {
          appendNode(childList, child, false);
        }
      }
      item.appendChild(childList);
    }
  } else {
    // File
    const icon = document.createElement('span');
    icon.className = 'tree-icon file';
    icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
    
    const file = document.createElement('span');
    file.className = 'tree-file';
    file.textContent = node.name;
    
    row.append(icon, file);
    item.appendChild(row);
  }
  
  parent.appendChild(item);
}

async function toggleNode(node) {
  if (node.kind !== 'd') return;
  
  node.expanded = !node.expanded;
  if (node.expanded && node.error) node.error = null;
  
  renderTree();
  
  if (node.expanded && !node.loaded && !node.loading) {
    await loadNode(node);
  }
}

async function loadNode(node) {
  if (!state.selectedDeviceId || node.kind !== 'd') return;
  
  node.error = null;
  node.loading = true;
  renderTree();
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/dir`, {
      method: 'POST',
      body: { root: 'cwd', path: node.path, limit: CONFIG.DIR_LIMIT },
    });
    
    if (payload?.error) throw new Error(payload.error);
    if (!Array.isArray(payload?.e)) throw new Error('invalid_directory_payload');
    
    const children = [];
    for (const entry of payload.e) {
      if (!Array.isArray(entry) || entry.length < 3) continue;
      
      const [kind, name] = entry;
      if ((kind !== 'd' && kind !== 'f') || typeof name !== 'string') continue;
      
      children.push({
        name,
        path: node.path === '.' ? name : `${node.path}/${name}`,
        kind,
        expanded: false,
        loaded: false,
        loading: false,
        error: null,
        children: [],
      });
    }
    
    children.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'd' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    
    node.children = children;
    node.loaded = true;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'dir_request_failed';
    node.error = message;
    node.loaded = false;
    showToast('error', 'Failed to load directory', message);
  } finally {
    node.loading = false;
    renderTree();
  }
}

// Context Menu
function showContextMenu(event, node) {
  state.contextMenuTarget = node;
  
  const menu = elements['context-menu'];
  if (!menu) return;
  
  // Position menu
  const x = Math.min(event.clientX, window.innerWidth - 180);
  const y = Math.min(event.clientY, window.innerHeight - 150);
  
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.classList.add('visible');
}

function hideContextMenu() {
  elements['context-menu']?.classList.remove('visible');
  state.contextMenuTarget = null;
}

async function handleContextMenuAction(event) {
  const action = event.currentTarget.dataset.action;
  const node = state.contextMenuTarget;
  
  hideContextMenu();
  
  if (!node || !state.selectedDeviceId) return;
  
  switch (action) {
    case 'new-folder':
      openModal({
        title: 'New Folder',
        label: 'Folder Name',
        placeholder: 'Enter folder name',
        confirmText: 'Create',
        callback: async (name) => {
          if (!name) return;
          const folderPath = node.path === '.' ? name : `${node.path}/${name}`;
          await createFolder(folderPath, node);
        },
      });
      break;
      
    case 'rename':
      openModal({
        title: 'Rename Folder',
        label: 'New Name',
        value: node.name,
        confirmText: 'Rename',
        callback: async (newName) => {
          if (!newName || newName === node.name) return;
          const parentPath = node.path.split('/').slice(0, -1).join('/');
          const destPath = parentPath === '.' || parentPath === '' ? newName : `${parentPath}/${newName}`;
          await renameFolder(node.path, destPath, node);
        },
      });
      break;
      
    case 'delete':
      if (node.path === '.') {
        showToast('error', 'Cannot delete root', 'You cannot delete the project root folder');
        return;
      }
      openModal({
        title: 'Delete Folder',
        label: 'Confirm by typing folder name',
        message: `Are you sure you want to delete "${node.name}"? This action cannot be undone.`,
        confirmText: 'Delete',
        confirmDanger: true,
        callback: async (confirmName) => {
          if (confirmName !== node.name) {
            showToast('error', 'Name mismatch', 'The name you entered does not match');
            return;
          }
          await deleteFolder(node.path, node);
        },
      });
      break;
  }
}

// Folder Operations
async function createFolder(folderPath, parentNode) {
  if (!state.selectedDeviceId) return;
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/mkdir`, {
      method: 'POST',
      body: { root: 'cwd', path: folderPath },
    });
    
    if (payload.o === 1) {
      addLogEntry('success', `Created folder: ${folderPath}`);
      showToast('success', 'Folder created', folderPath);
      // Refresh parent
      parentNode.loaded = false;
      parentNode.expanded = true;
      await loadNode(parentNode);
    } else {
      addLogEntry('error', `Failed to create folder: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Failed to create folder', payload.m || 'Unknown error');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'mkdir_request_failed';
    addLogEntry('error', `Failed to create folder: ${message}`);
    showToast('error', 'Failed to create folder', message);
  }
}

async function deleteFolder(folderPath, node) {
  if (!state.selectedDeviceId) return;
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/rmdir`, {
      method: 'POST',
      body: { root: 'cwd', path: folderPath },
    });
    
    if (payload.o === 1) {
      addLogEntry('success', `Deleted folder: ${folderPath}`);
      showToast('success', 'Folder deleted', folderPath);
      
      // Clear selection if deleted folder was selected
      if (state.selectedFolderPath === folderPath) {
        state.selectedFolderPath = null;
        state.sessionId = null;
        state.sessionUrl = null;
        state.isSessionActive = false;
        state.snapshotHydratedForSession = null;
        clearSessionState();
        updateSessionUI();
      }
      
      // Refresh parent
      const parentPath = folderPath.includes('/') ? folderPath.split('/').slice(0, -1).join('/') : '.';
      const root = state.treeByDevice.get(state.selectedDeviceId);
      const parentNode = findNodeByPath(root, parentPath);
      if (parentNode) {
        parentNode.loaded = false;
        parentNode.expanded = true;
        await loadNode(parentNode);
      }
    } else {
      addLogEntry('error', `Failed to delete folder: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Failed to delete folder', payload.m || 'Unknown error');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'rmdir_request_failed';
    addLogEntry('error', `Failed to delete folder: ${message}`);
    showToast('error', 'Failed to delete folder', message);
  }
}

async function renameFolder(sourcePath, destPath, node) {
  if (!state.selectedDeviceId) return;
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/rename`, {
      method: 'POST',
      body: { root: 'cwd', source: sourcePath, dest: destPath },
    });
    
    if (payload.o === 1) {
      addLogEntry('success', `Renamed: ${sourcePath} → ${destPath}`);
      showToast('success', 'Folder renamed', `${sourcePath} → ${destPath}`);
      
      // Update selection if renamed folder was selected
      if (state.selectedFolderPath === sourcePath) {
        state.selectedFolderPath = destPath;
      }
      
      // Refresh parent
      const parentPath = destPath.includes('/') ? destPath.split('/').slice(0, -1).join('/') : '.';
      const root = state.treeByDevice.get(state.selectedDeviceId);
      const parentNode = findNodeByPath(root, parentPath);
      if (parentNode) {
        parentNode.loaded = false;
        parentNode.expanded = true;
        await loadNode(parentNode);
      }
    } else {
      addLogEntry('error', `Failed to rename: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Failed to rename folder', payload.m || 'Unknown error');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'rename_request_failed';
    addLogEntry('error', `Failed to rename: ${message}`);
    showToast('error', 'Failed to rename folder', message);
  }
}

function findNodeByPath(rootNode, targetPath) {
  if (!rootNode) return null;
  if (rootNode.path === targetPath) return rootNode;
  
  for (const child of rootNode.children || []) {
    const found = findNodeByPath(child, targetPath);
    if (found) return found;
  }
  return null;
}

// Modal Dialog
function openModal(options) {
  const titleEl = elements['modal-title'];
  const labelEl = elements['modal-label'];
  const inputEl = elements['modal-input'];
  const messageEl = elements['modal-message'];
  const confirmBtn = elements['modal-confirm'];
  
  if (titleEl) titleEl.textContent = options.title;
  if (labelEl) labelEl.textContent = options.label || 'Name';
  if (inputEl) {
    inputEl.value = options.value || '';
    inputEl.placeholder = options.placeholder || '';
  }
  if (messageEl) {
    messageEl.textContent = options.message || '';
    messageEl.style.display = options.message ? 'block' : 'none';
  }
  if (confirmBtn) {
    confirmBtn.textContent = options.confirmText || 'Confirm';
    confirmBtn.className = `btn ${options.confirmDanger ? 'btn-danger' : 'btn-primary'}`;
  }
  
  state.modalCallback = options.callback;
  elements['modal']?.classList.add('visible');
  
  // Focus input after animation
  setTimeout(() => inputEl?.focus(), 50);
}

function closeModal() {
  elements['modal']?.classList.remove('visible');
  state.modalCallback = null;
  if (elements['modal-input']) elements['modal-input'].value = '';
}

function restoreSessionState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.SESSION_STATE);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return;

    const deviceId = typeof parsed.deviceId === 'string' ? parsed.deviceId : null;
    const folderPath = typeof parsed.folderPath === 'string' ? parsed.folderPath : null;
    const sessionId = typeof parsed.sessionId === 'string' ? parsed.sessionId : null;
    const sessionUrl = typeof parsed.sessionUrl === 'string' ? parsed.sessionUrl : null;

    if (deviceId) state.selectedDeviceId = deviceId;
    if (folderPath) state.selectedFolderPath = folderPath;
    if (sessionId) state.sessionId = sessionId;
    if (sessionUrl) state.sessionUrl = sessionUrl;
    if (sessionId || sessionUrl) state.isSessionActive = true;

    if (state.selectedDeviceId) {
      ensureRootNode(state.selectedDeviceId);
      renderTree();
      updateSessionUI();
    }
  } catch {
    // ignore persisted state errors
  }
}

function persistSessionState() {
  const payload = {
    deviceId: state.selectedDeviceId,
    folderPath: state.selectedFolderPath,
    sessionId: state.sessionId,
    sessionUrl: state.sessionUrl,
    savedAt: Date.now(),
  };
  localStorage.setItem(STORAGE_KEYS.SESSION_STATE, JSON.stringify(payload));
}

function clearSessionState() {
  localStorage.removeItem(STORAGE_KEYS.SESSION_STATE);
}

// Session Management
function updateSessionUI() {
  const hasDevice = Boolean(state.selectedDeviceId);
  const hasFolder = Boolean(state.selectedFolderPath);
  const hasSession = Boolean(state.sessionUrl);
  
  const startBtn = elements['start-session'];
  const stopBtn = elements['stop-session'];
  const openBtn = elements['open-in-browser'];
  const copyBtn = elements['copy-url'];
  const statusBadge = elements['session-status'];
  const startText = elements['start-session-text'];
  
  // Update info display
  if (elements['session-id-display']) {
    elements['session-id-display'].textContent = state.sessionId || (hasSession ? 'Active' : '—');
  }
  if (elements['project-path-display']) {
    elements['project-path-display'].textContent = state.selectedFolderPath || '—';
  }
  
  // Update buttons
  if (startBtn) {
    startBtn.disabled = !hasDevice || !hasFolder;
    if (startText) startText.textContent = hasSession ? 'Open in Browser' : 'Launch OpenCode';
  }
  if (stopBtn) stopBtn.disabled = !hasDevice || !hasFolder || !state.isSessionActive;
  if (openBtn) openBtn.disabled = !hasSession;
  if (copyBtn) copyBtn.disabled = !hasSession;
  
  // Update status badge
  if (statusBadge) {
    if (state.isSessionActive) {
      statusBadge.textContent = 'Running';
      statusBadge.className = 'status-badge primary-badge running';
    } else if (hasFolder) {
      statusBadge.textContent = 'Ready';
      statusBadge.className = 'status-badge primary-badge';
    } else {
      statusBadge.textContent = 'Select folder';
      statusBadge.className = 'status-badge';
    }
  }
  
  // Also update git UI if folder changes
  updateGitUI();
  updatePortLinks();

  if (state.sessionId) {
    void hydrateSnapshotForActiveSession();
  }
}

function updatePortLinks() {
  const container = elements['port-links'];
  if (!container) return;

  container.innerHTML = '';

  const device = state.selectedDeviceId ? state.devices.get(state.selectedDeviceId) : null;
  const ports = Array.isArray(device?.pt) ? device.pt.filter(p => Number.isInteger(p) && p >= 1 && p <= 65535) : [];

  if (!state.selectedDeviceId) {
    const empty = document.createElement('span');
    empty.className = 'port-empty';
    empty.textContent = 'Select a device';
    container.appendChild(empty);
    return;
  }

  if (ports.length === 0) {
    const empty = document.createElement('span');
    empty.className = 'port-empty';
    empty.textContent = 'No detected ports yet';
    container.appendChild(empty);
    return;
  }

  const sortedPorts = Array.from(new Set(ports)).sort((a, b) => a - b);
  for (const port of sortedPorts) {
    const link = document.createElement('a');
    link.className = 'port-link';
    link.href = `/device/${encodeURIComponent(state.selectedDeviceId)}/port/${port}/`;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = `:${port}`;
    container.appendChild(link);
  }
}

async function hydrateSnapshotForActiveSession() {
  if (!state.sessionId) return;
  if (state.snapshotHydratedForSession === state.sessionId) return;

  try {
    const payload = await apiJson(`/session/${encodeURIComponent(state.sessionId)}/snapshot?tail=${CONFIG.SNAPSHOT_TAIL}`);
    if (!payload || payload.o !== 1 || !Array.isArray(payload.e)) {
      return;
    }

    const hydratedEntries = [];
    for (const entry of payload.e) {
      if (!entry || typeof entry !== 'object') continue;
      const source = typeof entry.src === 'string' ? entry.src : 'session';
      const message = typeof entry.m === 'string'
        ? entry.m
        : (entry.k === 'meta' ? `metadata snapshot captured (${state.sessionId})` : 'snapshot event');
      hydratedEntries.push({
        type: source === 'git' ? 'info' : (source === 'session' ? 'device' : 'info'),
        time: formatSnapshotTime(entry.ts),
        message: `[snapshot] ${message}`,
        timestamp: new Date(),
      });
    }

    if (hydratedEntries.length > 0) {
      state.logEntries = hydratedEntries.slice(-CONFIG.MAX_LOG_ENTRIES);
      renderActivityLog();
    }
    state.snapshotHydratedForSession = state.sessionId;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'snapshot_hydration_failed';
    console.warn('Snapshot hydration skipped:', message);
  }
}

function formatSnapshotTime(value) {
  if (typeof value !== 'string') {
    return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
  return date.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

async function handleStartSession() {
  if (state.sessionUrl) {
    // Open existing session
    addLogEntry('info', `Opening session: ${state.sessionUrl}`);
    openInBrowser();
    return;
  }
  
  if (!state.selectedDeviceId || !state.selectedFolderPath) {
    addLogEntry('warning', 'Cannot start: no device or folder selected');
    showToast('error', 'Missing selection', 'Select a device and folder first');
    return;
  }
  
  const device = state.devices.get(state.selectedDeviceId);
  if (!device || !device.online) {
    addLogEntry('error', 'Cannot start: device is offline');
    showToast('error', 'Device offline', 'The selected device is offline');
    return;
  }
  
  addLogEntry('info', `Starting OpenCode for: ${state.selectedFolderPath}`);
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/session/start`, {
      method: 'POST',
      body: { path: state.selectedFolderPath },
    });
    
    if (payload.o === 1 && payload.u) {
      state.sessionId = typeof payload.s === 'string' ? payload.s : state.sessionId;
      state.sessionUrl = payload.u;
      state.isSessionActive = true;
      state.snapshotHydratedForSession = null;
      persistSessionState();
      addLogEntry('success', `OpenCode started: ${payload.u}`);
      showToast('success', 'OpenCode started', `Session opened at ${payload.u}`);
      
      // Auto-open in browser
      setTimeout(() => openInBrowser(), 500);
    } else {
      addLogEntry('error', `Failed to start: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Failed to start', payload.m || 'Unknown error');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'session_start_failed';
    addLogEntry('error', `Failed to start OpenCode: ${message}`);
    showToast('error', 'Failed to start OpenCode', message);
  }
  
  updateSessionUI();
}

async function handleStopSession() {
  if (!state.selectedDeviceId) return;
  
  addLogEntry('info', 'Stopping OpenCode session...');
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/session/terminate`, {
      method: 'POST',
      body: state.sessionId ? { sessionId: state.sessionId } : {},
    });
    
    if (payload.o === 1) {
      state.sessionId = null;
      state.sessionUrl = null;
      state.isSessionActive = false;
      state.snapshotHydratedForSession = null;
      clearSessionState();
      addLogEntry('success', 'OpenCode session stopped');
      showToast('success', 'OpenCode stopped', 'Session terminated');
    } else {
      addLogEntry('error', `Failed to stop: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Failed to stop', payload.m || 'Unknown error');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'session_stop_failed';
    addLogEntry('error', `Failed to stop OpenCode: ${message}`);
    showToast('error', 'Failed to stop OpenCode', message);
  }
  
  updateSessionUI();
}

function openInBrowser() {
  if (!state.sessionUrl) {
    showToast('error', 'No session', 'Start a session first');
    return;
  }
  
  const popup = window.open(state.sessionUrl, '_blank', 'noopener,noreferrer');
  if (!popup) {
    showToast('info', 'Popup blocked', 'Please allow popups or copy the URL manually');
  }
}

async function copySessionUrl() {
  if (!state.sessionUrl) {
    showToast('error', 'No session', 'Start a session first');
    return;
  }
  
  try {
    await navigator.clipboard.writeText(state.sessionUrl);
    showToast('success', 'URL copied', 'Session URL copied to clipboard');
  } catch {
    showToast('error', 'Copy failed', 'Could not copy to clipboard');
  }
}

// WebSocket
function connectUiSocket() {
  if (state.uiSocket && (state.uiSocket.readyState === WebSocket.OPEN || state.uiSocket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${window.location.host}/ws-ui`);
  state.uiSocket = ws;
  
  ws.addEventListener('open', () => {
    state.uiReady = true;
    updateConnectionStatus('Connected', true);
    if (state.sessionId) {
      void hydrateSnapshotForActiveSession();
    }
  });
  
  ws.addEventListener('message', (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.t === 'chunk') {
        // Handle streaming output if needed
      } else if (payload.t === 'gitlog') {
        if (!payload.d || payload.d === state.selectedDeviceId) {
          const level = payload.s === 'err' ? 'error' : 'info';
          const text = typeof payload.m === 'string' ? payload.m : '';
          if (text) {
            addLogEntry(level, `Git: ${text}`);
          }
        }
      } else if (payload.t === 'err') {
        console.error('WebSocket error:', payload);
      }
    } catch {
      // Ignore invalid messages
    }
  });
  
  ws.addEventListener('close', () => {
    state.uiReady = false;
    updateConnectionStatus('Disconnected', false);
    scheduleReconnect();
  });
  
  ws.addEventListener('error', () => {
    state.uiReady = false;
    updateConnectionStatus('Connection error', false);
  });
}

function scheduleReconnect() {
  if (state.reconnectTimer) return;
  
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    connectUiSocket();
  }, CONFIG.RECONNECT_DELAY);
}

// Toast Notifications
function showToast(type, title, message) {
  const container = elements['toast-container'];
  if (!container) return;
  
  const toast = document.createElement('div');
  toast.className = 'toast';
  
  const icons = {
    success: '<svg class="toast-icon success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error: '<svg class="toast-icon error" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    info: '<svg class="toast-icon info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  };
  
  toast.innerHTML = `
    ${icons[type] || icons.info}
    <div class="toast-content">
      <div class="toast-title">${escapeHtml(title)}</div>
      ${message ? `<div class="toast-message">${escapeHtml(message)}</div>` : ''}
    </div>
  `;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 150);
  }, CONFIG.TOAST_DURATION);
}

// API Helper
async function apiJson(url, options = {}) {
  const gitAction = options.logGit ? getGitActionLabel(url) : null;
  if (gitAction) {
    addLogEntry('info', `Git ${gitAction}: request sent`);
  }

  const requestInit = {
    method: options.method || 'GET',
    headers: { 'content-type': 'application/json' },
    body: options.body ? JSON.stringify(options.body) : undefined,
  };

  if ((requestInit.method || 'GET').toUpperCase() !== 'GET') {
    const csrf = getCookieValue('cp_csrf');
    if (csrf) {
      requestInit.headers['x-csrf-token'] = csrf;
    }
  }

  let response;
  try {
    response = await fetch(url, requestInit);
  } catch (error) {
    if (gitAction) {
      const message = error instanceof Error ? error.message : 'request_failed';
      addLogEntry('error', `Git ${gitAction} failed: ${message}`);
    }
    throw error;
  }

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401) {
      window.location.assign('/login');
      throw new Error('auth_required');
    }
    const reason = payload.error || `http_${response.status}`;
    if (gitAction) {
      addLogEntry('error', `Git ${gitAction} failed: ${reason}`);
    }
    throw new Error(reason);
  }

  if (gitAction) {
    const operationOk = payload && typeof payload === 'object' && payload.o === 1;
    if (operationOk) {
      addLogEntry('success', `Git ${gitAction}: completed`);
    } else if (payload && typeof payload === 'object' && payload.o === 0) {
      const failure = payload.m || payload.e || 'operation_failed';
      addLogEntry('error', `Git ${gitAction} failed: ${failure}`);
    }

    const detail = getGitDetailMessage(payload);
    if (detail) {
      addLogEntry('info', `Git ${gitAction}: ${detail}`);
    }
  }
  
  return payload;
}

function getCookieValue(name) {
  if (!document.cookie) return '';
  const target = `${name}=`;
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith(target)) {
      return trimmed.slice(target.length);
    }
  }
  return '';
}

function getGitActionLabel(url) {
  if (typeof url !== 'string') return 'operation';
  const match = /\/git\/([a-z]+)/i.exec(url);
  return match ? match[1].toLowerCase() : 'operation';
}

function getGitDetailMessage(payload) {
  if (!payload || typeof payload !== 'object' || typeof payload.m !== 'string') {
    return '';
  }
  const trimmed = payload.m.trim();
  if (!trimmed) return '';
  const firstLine = trimmed.split(/\r?\n/, 1)[0] || trimmed;
  return firstLine;
}

// Activity Log
function addLogEntry(type, message) {
  const timestamp = new Date();
  const timeStr = timestamp.toLocaleTimeString('en-US', { 
    hour12: false, 
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit' 
  });
  
  const entry = {
    type,
    time: timeStr,
    message,
    timestamp,
  };
  
  state.logEntries.push(entry);
  
  // Keep only last N entries
  if (state.logEntries.length > CONFIG.MAX_LOG_ENTRIES) {
    state.logEntries = state.logEntries.slice(-CONFIG.MAX_LOG_ENTRIES);
  }
  
  renderActivityLog();
}

function renderActivityLog() {
  const logContainer = elements['activity-log'];
  if (!logContainer) return;
  
  logContainer.innerHTML = '';
  
  for (const entry of state.logEntries) {
    const div = document.createElement('div');
    div.className = `log-entry ${entry.type}`;
    div.innerHTML = `
      <span class="log-time">${escapeHtml(entry.time)}</span>
      <span class="log-message">${escapeHtml(entry.message)}</span>
    `;
    logContainer.appendChild(div);
  }
  
  // Auto-scroll to bottom
  logContainer.scrollTop = logContainer.scrollHeight;
}

function clearActivityLog() {
  state.logEntries = [];
  addLogEntry('info', 'Activity log cleared');
}

// Git Operations
function logGitCommandOutput(payload) {
  if (!payload || typeof payload.m !== 'string') return;
  const trimmed = payload.m.trim();
  if (!trimmed) return;
  const firstLine = trimmed.split(/\r?\n/, 1)[0] || trimmed;
  addLogEntry('info', `Git: ${firstLine}`);
}

async function refreshGitStatus() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) {
    updateGitUI();
    return;
  }
  
  try {
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/status`, {
      method: 'POST',
      logGit: true,
      body: { root: 'cwd', path: state.selectedFolderPath },
    });
    
    if (payload.o === 1) {
      state.gitStatus = payload;
      state.hasGitRepo = true;
      
      // Update UI
      const infoRow = document.getElementById('git-info-row');
      if (infoRow) infoRow.style.display = 'flex';
      
      if (elements['git-branch']) {
        elements['git-branch'].textContent = payload.b || 'unknown';
      }
      if (elements['git-added-count']) {
        elements['git-added-count'].textContent = (payload.a || []).length;
      }
      if (elements['git-modified-count']) {
        elements['git-modified-count'].textContent = (payload.m || []).length;
      }
      if (elements['git-untracked-count']) {
        elements['git-untracked-count'].textContent = (payload.u || []).length;
      }
      
      // Update badge
      const badge = elements['git-status-badge'];
      if (badge) {
        badge.textContent = payload.b || 'Git repo';
        badge.className = 'tool-status-value has-repo';
      }
      
      // Enable git buttons
      updateGitButtonStates(true);
    } else {
      state.hasGitRepo = false;
      state.gitStatus = null;
      
      // Hide info row
      const infoRow = document.getElementById('git-info-row');
      if (infoRow) infoRow.style.display = 'none';
      
      // Update badge
      const badge = elements['git-status-badge'];
      if (badge) {
        badge.textContent = 'No repo';
        badge.className = 'tool-status-value';
      }
      
      // Disable most git buttons, enable init/clone
      updateGitButtonStates(false);
    }
  } catch (error) {
    state.hasGitRepo = false;
    state.gitStatus = null;
    
    // Hide info row
    const infoRow = document.getElementById('git-info-row');
    if (infoRow) infoRow.style.display = 'none';
    
    // Update badge
    const badge = elements['git-status-badge'];
    if (badge) {
      badge.textContent = 'No repo';
      badge.className = 'tool-status-value';
    }
    
    updateGitButtonStates(false);
    addLogEntry('error', `Git status failed: ${error.message}`);
  }
}

function updateGitUI() {
  const hasRepo = state.hasGitRepo;
  
  // Show/hide info row
  const infoRow = document.getElementById('git-info-row');
  if (infoRow) infoRow.style.display = hasRepo ? 'flex' : 'none';
  
  // Update badge
  const badge = elements['git-status-badge'];
  if (badge) {
    badge.textContent = hasRepo ? (state.gitStatus?.b || 'Git repo') : 'No repo';
    badge.className = hasRepo ? 'tool-status-value has-repo' : 'tool-status-value';
  }
  
  // Update branch display
  if (elements['git-branch']) {
    elements['git-branch'].textContent = hasRepo ? (state.gitStatus?.b || 'unknown') : '—';
  }
  
  // Update counters
  if (elements['git-added-count']) {
    elements['git-added-count'].textContent = hasRepo ? (state.gitStatus?.a || []).length : '0';
  }
  if (elements['git-modified-count']) {
    elements['git-modified-count'].textContent = hasRepo ? (state.gitStatus?.m || []).length : '0';
  }
  if (elements['git-untracked-count']) {
    elements['git-untracked-count'].textContent = hasRepo ? (state.gitStatus?.u || []).length : '0';
  }
  
  updateGitButtonStates(hasRepo);
}

function updateGitButtonStates(hasRepo) {
  const hasDeviceAndFolder = state.selectedDeviceId && state.selectedFolderPath;
  
  // Always enable init and clone if we have device and folder
  if (elements['git-init']) elements['git-init'].disabled = !hasDeviceAndFolder;
  if (elements['git-clone']) elements['git-clone'].disabled = !hasDeviceAndFolder;
  if (elements['git-config']) elements['git-config'].disabled = !hasDeviceAndFolder;
  if (elements['git-refresh']) elements['git-refresh'].disabled = !hasDeviceAndFolder;
  
  // Other buttons require a git repo
  const repoButtons = ['git-add', 'git-commit', 'git-pull', 'git-push', 'git-branch-btn', 'git-checkout'];
  for (const btnId of repoButtons) {
    if (elements[btnId]) {
      elements[btnId].disabled = !hasDeviceAndFolder || !hasRepo;
    }
  }
}

async function handleGitInit() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) {
    showToast('error', 'Missing selection', 'Select a device and folder first');
    return;
  }
  
  try {
    addLogEntry('info', 'Initializing git repository...');
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/init`, {
      method: 'POST',
      logGit: true,
      body: { root: 'cwd', path: state.selectedFolderPath },
    });
    
    if (payload.o === 1) {
      addLogEntry('success', 'Git repository initialized');
      logGitCommandOutput(payload);
      showToast('success', 'Git initialized', 'Repository created successfully');
      await refreshGitStatus();
    } else {
      addLogEntry('error', `Git init failed: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Git init failed', payload.m || 'Unknown error');
    }
  } catch (error) {
    addLogEntry('error', `Git init failed: ${error.message}`);
    showToast('error', 'Git init failed', error.message);
  }
}

async function handleGitClone() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) {
    showToast('error', 'Missing selection', 'Select a device and folder first');
    return;
  }
  
  openModal({
    title: 'Clone Repository',
    label: 'Repository URL',
    placeholder: 'https://github.com/user/repo.git',
    confirmText: 'Clone',
    callback: async (url) => {
      if (!url) return;
      
      openModal({
        title: 'Branch (optional)',
        label: 'Branch name (leave empty for default)',
        placeholder: 'main',
        confirmText: 'Clone',
        callback: async (branch) => {
          try {
            addLogEntry('info', `Cloning repository: ${url}`);
            const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/clone`, {
              method: 'POST',
              logGit: true,
              body: { 
                root: 'cwd', 
                path: state.selectedFolderPath,
                url,
                branch: branch || undefined,
              },
            });
            
            if (payload.o === 1) {
              addLogEntry('success', 'Repository cloned successfully');
              logGitCommandOutput(payload);
              showToast('success', 'Clone complete', 'Repository cloned successfully');
              // Reload tree to show cloned files
              const root = state.treeByDevice.get(state.selectedDeviceId);
              if (root) {
                root.loaded = false;
                root.expanded = true;
                await loadNode(root);
              }
              await refreshGitStatus();
            } else {
              addLogEntry('error', `Clone failed: ${payload.m || 'Unknown error'}`);
              showToast('error', 'Clone failed', payload.m || 'Unknown error');
            }
          } catch (error) {
            addLogEntry('error', `Clone failed: ${error.message}`);
            showToast('error', 'Clone failed', error.message);
          }
        },
      });
    },
  });
}

async function handleGitConfig() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) {
    showToast('error', 'Missing selection', 'Select a device and folder first');
    return;
  }

  let currentName = '';
  let currentEmail = '';
  let authReady = 0;

  try {
    const current = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/config`, {
      method: 'POST',
      logGit: true,
      body: {
        root: 'cwd',
        path: state.selectedFolderPath,
        action: 'get',
      },
    });
    currentName = typeof current.n === 'string' ? current.n : '';
    currentEmail = typeof current.e === 'string' ? current.e : '';
    authReady = current.a === 1 ? 1 : 0;
  } catch (error) {
    addLogEntry('warning', `Could not read existing git config: ${error instanceof Error ? error.message : 'unknown_error'}`);
  }

  openModal({
    title: 'Git Config: Name',
    label: 'Git user.name',
    placeholder: 'Jane Developer',
    value: currentName,
    confirmText: 'Next',
    callback: async (name) => {
      const trimmedName = name.trim();
      if (!trimmedName) {
        showToast('error', 'Missing name', 'Git user name is required');
        return;
      }

      openModal({
        title: 'Git Config: Email',
        label: 'Git user.email',
        placeholder: 'jane@example.com',
        value: currentEmail,
        confirmText: 'Save',
        callback: async (email) => {
          const trimmedEmail = email.trim();
          if (!trimmedEmail) {
            showToast('error', 'Missing email', 'Git email is required');
            return;
          }

          const enableCredentialManager = authReady !== 1;
          try {
            const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/config`, {
              method: 'POST',
              logGit: true,
              body: {
                root: 'cwd',
                path: state.selectedFolderPath,
                action: 'set',
                name: trimmedName,
                email: trimmedEmail,
                global: 1,
                credentialManager: enableCredentialManager ? 1 : 0,
              },
            });

            if (payload.o === 1) {
              addLogEntry('success', 'Git identity updated');
              if (payload.h) {
                addLogEntry('info', `Git credential helper: ${payload.h}`);
              }
              if (payload.a === 1) {
                showToast('success', 'Git configured', 'Identity and sign-in helper are configured');
              } else {
                showToast('success', 'Git configured', 'Identity saved (credential helper not confirmed)');
              }
            } else {
              const message = payload.m || 'git_config_failed';
              addLogEntry('error', `Git config failed: ${message}`);
              showToast('error', 'Git config failed', message);
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : 'git_config_failed';
            addLogEntry('error', `Git config failed: ${message}`);
            showToast('error', 'Git config failed', message);
          }
        },
      });
    },
  });
}

async function handleGitAdd() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) return;
  
  openModal({
    title: 'Add Files',
    label: 'File pattern (leave empty to add all)',
    placeholder: '*.js or src/',
    confirmText: 'Add',
    callback: async (pattern) => {
      try {
        const all = !pattern;
        addLogEntry('info', all ? 'Adding all files...' : `Adding files: ${pattern}`);
        
        const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/add`, {
          method: 'POST',
          logGit: true,
          body: { 
            root: 'cwd', 
            path: state.selectedFolderPath,
            files: pattern || undefined,
            all: all ? 1 : 0,
          },
        });
        
        if (payload.o === 1) {
          addLogEntry('success', 'Files added to staging');
          logGitCommandOutput(payload);
          showToast('success', 'Files added', 'Changes staged successfully');
          await refreshGitStatus();
        } else {
          addLogEntry('error', `Add failed: ${payload.m || 'Unknown error'}`);
          showToast('error', 'Add failed', payload.m || 'Unknown error');
        }
      } catch (error) {
        addLogEntry('error', `Add failed: ${error.message}`);
        showToast('error', 'Add failed', error.message);
      }
    },
  });
}

async function handleGitCommit() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) return;
  
  openModal({
    title: 'Commit Changes',
    label: 'Commit message',
    placeholder: 'Enter commit message...',
    confirmText: 'Commit',
    callback: async (message) => {
      if (!message) {
        showToast('error', 'Missing message', 'Commit message is required');
        return;
      }
      
      try {
        addLogEntry('info', 'Committing changes...');
        const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/commit`, {
          method: 'POST',
          logGit: true,
          body: { 
            root: 'cwd', 
            path: state.selectedFolderPath,
            message,
          },
        });
        
        if (payload.o === 1) {
          addLogEntry('success', `Committed: ${payload.h ? payload.h.substring(0, 7) : 'success'}`);
          logGitCommandOutput(payload);
          showToast('success', 'Changes committed', payload.h || 'Commit successful');
          await refreshGitStatus();
        } else {
          addLogEntry('error', `Commit failed: ${payload.m || 'Unknown error'}`);
          showToast('error', 'Commit failed', payload.m || 'Unknown error');
        }
      } catch (error) {
        addLogEntry('error', `Commit failed: ${error.message}`);
        showToast('error', 'Commit failed', error.message);
      }
    },
  });
}

async function handleGitPull() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) return;
  
  try {
    addLogEntry('info', 'Pulling changes...');
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/pull`, {
      method: 'POST',
      logGit: true,
      body: { 
        root: 'cwd', 
        path: state.selectedFolderPath,
      },
    });
    
    if (payload.o === 1) {
      addLogEntry('success', 'Pull complete');
      logGitCommandOutput(payload);
      showToast('success', 'Pull complete', 'Changes pulled successfully');
      await refreshGitStatus();
    } else {
      addLogEntry('error', `Pull failed: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Pull failed', payload.m || 'Unknown error');
    }
  } catch (error) {
    addLogEntry('error', `Pull failed: ${error.message}`);
    showToast('error', 'Pull failed', error.message);
  }
}

async function handleGitPush() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) return;
  
  try {
    addLogEntry('info', 'Pushing changes...');
    const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/push`, {
      method: 'POST',
      logGit: true,
      body: { 
        root: 'cwd', 
        path: state.selectedFolderPath,
      },
    });
    
    if (payload.o === 1) {
      addLogEntry('success', 'Push complete');
      logGitCommandOutput(payload);
      showToast('success', 'Push complete', 'Changes pushed successfully');
    } else {
      addLogEntry('error', `Push failed: ${payload.m || 'Unknown error'}`);
      showToast('error', 'Push failed', payload.m || 'Unknown error');
    }
  } catch (error) {
    addLogEntry('error', `Push failed: ${error.message}`);
    showToast('error', 'Push failed', error.message);
  }
}

async function handleGitBranch() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) return;
  
  openModal({
    title: 'Branch Actions',
    label: 'Branch name (for create/delete) or leave empty to list',
    placeholder: 'feature/new-branch',
    confirmText: 'List Branches',
    callback: async (branchName) => {
      const action = branchName ? 'create' : 'list';
      
      try {
        addLogEntry('info', action === 'list' ? 'Listing branches...' : `Creating branch: ${branchName}`);
        const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/branch`, {
          method: 'POST',
          logGit: true,
          body: { 
            root: 'cwd', 
            path: state.selectedFolderPath,
            action,
            branch: branchName || undefined,
          },
        });
        
        if (payload.o === 1) {
          if (action === 'list' && payload.b) {
            const branches = payload.b.join(', ');
            addLogEntry('info', `Branches: ${branches}`);
            logGitCommandOutput(payload);
            showToast('info', 'Branches', payload.b.join(', '));
          } else {
            addLogEntry('success', `Branch created: ${branchName}`);
            logGitCommandOutput(payload);
            showToast('success', 'Branch created', branchName || 'Success');
            await refreshGitStatus();
          }
        } else {
          addLogEntry('error', `Branch operation failed: ${payload.m || 'Unknown error'}`);
          showToast('error', 'Branch operation failed', payload.m || 'Unknown error');
        }
      } catch (error) {
        addLogEntry('error', `Branch operation failed: ${error.message}`);
        showToast('error', 'Branch operation failed', error.message);
      }
    },
  });
}

async function handleGitCheckout() {
  if (!state.selectedDeviceId || !state.selectedFolderPath) return;
  
  openModal({
    title: 'Checkout Branch',
    label: 'Branch name',
    placeholder: 'main',
    confirmText: 'Checkout',
    callback: async (branch) => {
      if (!branch) {
        showToast('error', 'Missing branch', 'Branch name is required');
        return;
      }
      
      try {
        addLogEntry('info', `Checking out: ${branch}`);
        const payload = await apiJson(`/devices/${encodeURIComponent(state.selectedDeviceId)}/git/checkout`, {
          method: 'POST',
          logGit: true,
          body: { 
            root: 'cwd', 
            path: state.selectedFolderPath,
            branch,
          },
        });
        
        if (payload.o === 1) {
          addLogEntry('success', `Checked out: ${branch}`);
          logGitCommandOutput(payload);
          showToast('success', 'Checkout complete', `Now on branch: ${branch}`);
          await refreshGitStatus();
        } else {
          addLogEntry('error', `Checkout failed: ${payload.m || 'Unknown error'}`);
          showToast('error', 'Checkout failed', payload.m || 'Unknown error');
        }
      } catch (error) {
        addLogEntry('error', `Checkout failed: ${error.message}`);
        showToast('error', 'Checkout failed', error.message);
      }
    },
  });
}

// Utility Functions
function escapeHtml(text) {
  if (typeof text !== 'string') return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
