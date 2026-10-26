/* GoChat browser client: REST auth + user management, WebSocket rooms
 * and presence, and end-to-end encrypted direct messages.
 *
 * E2E: each user generates a tweetnacl box keypair (X25519 + XSalsa20-
 * Poly1305) on first login and uploads the public key to the server.
 * DM bodies are sealed with nacl.box and the server only relays opaque
 * ciphertext; the plaintext never leaves the browser.
 */
"use strict";

const API = ""; // same origin

const state = {
  token: null,
  me: null,
  key: null,            // {publicKey, privateKey}
  ws: null,
  connStatus: "disconnected",
  activeRoom: null,     // room name or "@userid" for DM threads
  activeUser: null,
  rooms: [],            // [{name, topic, createdAt}]
  roomMembers: {},      // name -> [User]
  roomHistory: {},      // name -> [Message]
  currentMembers: [],
  users: [],
  typing: {},           // "room:user" -> timestamp
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.style.display = "block";
  clearTimeout(t._h);
  t._h = setTimeout(() => (t.style.display = "none"), 3000);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (state.token) headers.Authorization = "Bearer " + state.token;
  const res = await fetch(API + path, { ...opts, headers });
  if (!res.ok) {
    let msg = res.status + " " + res.statusText;
    try { msg = (await res.json()).message || msg; } catch (_) { /* ignore */ }
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  return res.json();
}

/* ---------- auth ---------- */

async function login(username, password) {
  const out = await api("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  state.token = out.token;
  state.me = out.user;
  await ensureKey();
  await uiEnterApp();
}

async function register(username, displayName, password) {
  await api("/api/v1/users", {
    method: "POST",
    body: JSON.stringify({ username, password, displayName }),
  });
  await login(username, password);
}

/* ---------- E2E keys ---------- */

function loadKeyFromStorage() {
  const raw = localStorage.getItem("gochat_key_" + state.me.id);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function ensureKey() {
  state.key = loadKeyFromStorage();
  if (!state.key) {
    const kp = nacl.box.keyPair();
    state.key = {
      publicKey: base64Encode(kp.publicKey),
      privateKey: base64Encode(kp.secretKey),
    };
    localStorage.setItem("gochat_key_" + state.me.id, JSON.stringify(state.key));
  }
  try {
    await api("/api/v1/users/me/public-key", {
      method: "PUT",
      body: JSON.stringify({ publicKey: state.key.publicKey }),
    });
  } catch (err) {
    console.warn("public key upload failed", err);
  }
}

function base64Encode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64Decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* box encryption helpers: nonce(24) || ct — same layout as the Go client */
function e2eEncrypt(recipientB64Pub, plaintext) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const boxed = nacl.box(
    new TextEncoder().encode(plaintext),
    nonce,
    base64Decode(recipientB64Pub),
    base64Decode(state.key.privateKey),
  );
  const out = new Uint8Array(nonce.length + boxed.length);
  out.set(nonce, 0);
  out.set(boxed, nonce.length);
  return base64Encode(out);
}

function e2eDecrypt(senderB64Pub, sealedB64) {
  const raw = base64Decode(sealedB64);
  const nonce = raw.subarray(0, nacl.box.nonceLength);
  const ct = raw.subarray(nacl.box.nonceLength);
  const opened = nacl.box.open(ct, nonce, base64Decode(senderB64Pub), base64Decode(state.key.privateKey));
  if (!opened) return null;
  return new TextDecoder().decode(opened);
}

/* ---------- UI ---------- */

function setStatus(s, ok) {
  state.connStatus = s;
  const el = $("conn-status");
  el.textContent = s;
  el.className = "status" + (ok ? " ok" : "");
}

async function uiEnterApp() {
  $("login").style.display = "none";
  $("register").style.display = "none";
  $("app").style.display = "block";
  $("logout").style.display = "";
  $("e2e-status").textContent = "E2E key: " + state.key.publicKey.slice(0, 12) + "…";
  await connectWS();
  await refreshRooms();
  await refreshUsers();
}

function bindActions() {
  $("login-btn").onclick = async () => {
    try { await login($("login-user").value.trim(), $("login-pass").value); }
    catch (e) { toast("login failed: " + e.message); }
  };
  $("show-register").onclick = (e) => { e.preventDefault(); $("login").style.display = "none"; $("register").style.display = "block"; };
  $("show-login").onclick = (e) => { e.preventDefault(); $("register").style.display = "none"; $("login").style.display = "block"; };
  $("reg-btn").onclick = async () => {
    try { await register($("reg-user").value.trim(), $("reg-display").value.trim(), $("reg-pass").value); }
    catch (e) { toast("registration failed: " + e.message); }
  };
  $("logout").onclick = () => {
    state.ws && state.ws.close();
    state.token = null;
    state.me = null;
    $("app").style.display = "none";
    $("login").style.display = "block";
    $("logout").style.display = "none";
    setStatus("disconnected", false);
  };
  $("create-room").onclick = async () => {
    const name = $("new-room").value.trim();
    if (!name) return;
    try {
      sendFrame("create_room", { name });
      $("new-room").value = "";
    } catch (e) { toast(e.message); }
  };
  $("leave-room").onclick = () => {
    if (!state.activeRoom) return;
    sendFrame("leave", { room: state.activeRoom });
    setActiveRoom(null);
  };
  $("send-btn").onclick = sendMessage;
  $("msg-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
    else if (state.activeRoom && !state.activeRoom.startsWith("@")) {
      sendFrame("typing", { room: state.activeRoom, active: true });
    }
  });
  document.querySelectorAll(".tab-bar button").forEach((b) => {
    b.onclick = () => {
      document.querySelectorAll(".tab-bar button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      $("tab-rooms").style.display = b.dataset.tab === "rooms" ? "" : "none";
      $("tab-users").style.display = b.dataset.tab === "users" ? "" : "none";
      if (b.dataset.tab === "users" && state.users.length === 0) refreshUsers();
    };
  });
}

/* ---------- websocket ---------- */

function connectWS() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(proto + "//" + location.host + "/ws");
  state.ws = ws;
  setStatus("connecting…", false);
  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", data: { token: state.token } }));
  };
  ws.onmessage = (ev) => {
    let frame;
    try { frame = JSON.parse(ev.data); } catch (_) { return; }
    handleFrame(frame);
  };
  ws.onclose = () => {
    setStatus("disconnected", false);
    setTimeout(() => { if (state.token && !state.ws) {} }, 0);
  };
  return ws;
}

function sendFrame(type, data) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) throw new Error("not connected");
  state.ws.send(JSON.stringify({ type, data }));
}

function handleFrame(f) {
  const d = f.data || {};
  switch (f.type) {
    case "welcome":
      setStatus("connected (" + (d.node || "?") + ")", true);
      refreshRooms();
      break;
    case "joined": {
      state.roomMembers[d.room] = d.members || [];
      state.roomHistory[d.room] = d.history || [];
      renderRooms();
      renderMembers();
      renderMessages();
      break;
    }
    case "left":
      delete state.roomMembers[d.room];
      renderRooms();
      renderMembers();
      break;
    case "rooms":
      state.rooms = d.rooms || [];
      renderRooms();
      break;
    case "message": {
      const room = d.room;
      // The server echoes messages back to the sender, so every device
      // shows what the user sent.
      if (!state.roomHistory[room]) state.roomHistory[room] = [];
      state.roomHistory[room].push(d);
      if (state.roomHistory[room].length > 200) state.roomHistory[room].shift();
      if (state.activeRoom === room) renderMessages();
      break;
    }
    case "dm": {
      const thread = "@" + d.sender;
      if (!state.roomHistory[thread]) state.roomHistory[thread] = [];
      // The server echoes DMs back to the sender; drop the local
      // placeholder once the real one lands.
      if (d.sender === state.me.id) {
        state.roomHistory[thread] = state.roomHistory[thread]
          .filter((m) => !(m.id && m.id.startsWith("local-") && m.body === d.body));
      }
      state.roomHistory[thread].push(d);
      if (state.roomHistory[thread].length > 200) state.roomHistory[thread].shift();
      if (state.activeRoom === thread) renderMessages();
      break;
    }
    case "presence": {
      if (!d.room) break;
      const list = state.roomMembers[d.room] || [];
      const idx = list.findIndex((u) => u.id === d.user.id);
      if (d.type === "join" && idx < 0) list.push(d.user);
      if (d.type === "leave" && idx >= 0) list.splice(idx, 1);
      state.roomMembers[d.room] = list;
      if (state.activeRoom === d.room) { renderMembers(); renderMessages(); }
      renderRooms();
      break;
    }
    case "typing": {
      if (!d.room) break;
      state.typing[d.room + ":" + d.user.id] = Date.now();
      setTimeout(() => {
        const key = d.room + ":" + d.user.id;
        if (state.typing[key] && Date.now() - state.typing[key] > 2500) delete state.typing[key];
        renderTyping();
      }, 2600);
      renderTyping();
      break;
    }
    case "room_created": {
      state.rooms.push({ name: d.name || f.type, topic: "", createdAt: "" });
      renderRooms();
      break;
    }
    case "room_deleted": {
      state.rooms = state.rooms.filter((r) => r.name !== d.name);
      state.roomMembers = {};
      if (state.activeRoom === d.name) setActiveRoom(null);
      renderRooms();
      break;
    }
    case "error":
      toast("server: " + (d.message || "error"));
      break;
    case "offline": {
      const msgs = d.messages || [];
      msgs.forEach((m) => {
        const thread = "@" + m.sender;
        if (!state.roomHistory[thread]) state.roomHistory[thread] = [];
        state.roomHistory[thread].push(m);
      });
      if (msgs.length) toast(msgs.length + " offline DM(s) delivered");
      break;
    }
    default:
      break;
  }
}

/* ---------- rooms / users ---------- */

async function refreshRooms() {
  try {
    sendFrame("room_list", {});
  } catch (_) { /* will retry on welcome */ }
}

async function refreshUsers() {
  try {
    state.users = await api("/api/v1/users?limit=200");
    renderUsers();
  } catch (e) { console.warn(e); }
}

function renderRooms() {
  const el = $("room-list");
  el.innerHTML = "";
  state.rooms.forEach((r) => {
    const row = document.createElement("div");
    row.className = "room" + (state.activeRoom === r.name ? " active" : "");
    row.innerHTML = '<span>' + esc(r.name) + '</span><span class="count">' +
      (state.roomMembers[r.name] ? state.roomMembers[r.name].length : 0) + "</span>";
    row.onclick = () => openRoom(r.name);
    el.appendChild(row);
  });
}

function renderUsers() {
  const el = $("user-list");
  el.innerHTML = "";
  state.users.forEach((u) => {
    if (u.id === state.me.id) return;
    const row = document.createElement("div");
    row.className = "member";
    row.innerHTML = '<span>' + esc(u.displayName || u.username) +
      (u.publicKey ? "" : ' <span class="sending">(no key)</span>') + "</span>";
    row.onclick = () => {
      if (!u.publicKey) { toast(u.username + " has not uploaded an E2E key yet"); return; }
      openDM(u);
    };
    el.appendChild(row);
  });
}

/* ---------- chat pane ---------- */

function openRoom(name) {
  if (state.activeRoom === name) return;
  state.activeUser = null;
  setActiveRoom(name);
  sendFrame("join", { room: name });
}

function openDM(u) {
  state.activeUser = u;
  setActiveRoom("@" + u.id);
  $("chat-sub").textContent = "end-to-end encrypted with " + (u.displayName || u.username) +
    " (public key " + u.publicKey.slice(0, 12) + "…)";
  $("leave-room").style.display = "none";
  $("msg-input").placeholder = "Encrypted DM to " + (u.displayName || u.username) + " (only you two can read)";
  renderMessages();
}

function setActiveRoom(name) {
  state.activeRoom = name;
  $("chat-title").textContent = name ? (name.startsWith("@") ? "DM" : name) : "Select a room";
  if (!name) {
    $("chat-sub").textContent = "";
    $("leave-room").style.display = "none";
    $("msg-input").disabled = true;
    $("send-btn").disabled = true;
    return;
  }
  if (!name.startsWith("@")) {
    const r = state.rooms.find((x) => x.name === name);
    $("chat-sub").textContent = r && r.topic ? r.topic : (state.roomMembers[state.activeRoom] || []).length + " members";
    $("leave-room").style.display = "";
    $("msg-input").placeholder = "Message " + name;
  }
  $("msg-input").disabled = false;
  $("send-btn").disabled = false;
  renderMessages();
  renderMembers();
  renderTyping();
}

function sendMessage() {
  const input = $("msg-input");
  const text = input.value.trim();
  if (!text || !state.activeRoom) return;
  input.value = "";
  try {
    if (state.activeRoom.startsWith("@")) {
      const user = state.activeUser;
      if (!user || !user.publicKey) { toast("recipient has no E2E key"); return; }
      const sealed = e2eEncrypt(user.publicKey, text);
      // The server echoes DMs to the sender; stash plaintext locally so
      // we can render it until the echo (or as the permanent record)
      // arrives. No plaintext is ever sent to the server.
      if (!state._lastOutgoing) state._lastOutgoing = {};
      const tempId = "local-" + Date.now();
      state._lastOutgoing[tempId] = text;
      sendFrame("message", { recipient: user.id, body: sealed });
      const m = {
        id: tempId, kind: "dm", sender: state.me.id, senderName: state.me.displayName,
        recipient: user.id, body: sealed, createdAt: new Date().toISOString(),
      };
      const thread = "@" + user.id;
      if (!state.roomHistory[thread]) state.roomHistory[thread] = [];
      state.roomHistory[thread].push(m);
      if (state.activeRoom === thread) renderMessages();
      setTimeout(() => { delete state._lastOutgoing[tempId]; }, 120000);
    } else {
      sendFrame("message", { room: state.activeRoom, body: text });
    }
  } catch (e) { toast(e.message); }
}

function renderMembers() {
  const el = $("member-list");
  el.innerHTML = "";
  const members = state.activeRoom ? state.roomMembers[state.activeRoom] || [] : [];
  members.forEach((u) => {
    const d = document.createElement("div");
    d.className = "member";
    d.innerHTML = '<span>' + esc(u.displayName || u.username) + "</span>";
    el.appendChild(d);
  });
}

function renderTyping() {
  const names = Object.keys(state.typing)
    .filter((k) => k.startsWith((state.activeRoom || "") + ":"))
    .map((k) => {
      const id = k.split(":")[1];
      const m = (state.roomMembers[state.activeRoom] || []).find((u) => u.id === id);
      return m ? (m.displayName || m.username) : null;
    })
    .filter(Boolean);
  $("typing").textContent = names.length ? names.join(", ") + " typing…" : "";
}

function renderMessages() {
  const el = $("messages");
  const room = state.activeRoom;
  const msgs = room ? state.roomHistory[room] || [] : [];
  el.innerHTML = "";
  msgs.forEach((m) => renderMessage(el, m));
  el.scrollTop = el.scrollHeight;
}

function renderMessage(el, m) {
  const div = document.createElement('div');
  div.className = 'msg' + (m.kind === 'dm' ? ' dm' : '');
  const time = new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const senderName = m.senderName || m.sender;
  const mine = m.sender === state.me.id;
  let body = '';
  let locked = '';
  if (m.kind === 'dm') {
    const peerId = mine ? m.recipient : m.sender;
    const peer = state.users.find((u) => u.id === peerId) ||
      (mine ? { publicKey: state.key.publicKey } : { publicKey: null });
    if (mine) {
      const local = state._lastOutgoing && state._lastOutgoing[m.id];
      if (local) {
        body = esc(local);
        if (m.id.startsWith('local-')) {
          state._lastOutgoing[m.id] = local;
          state._echoSeen = state._echoSeen || {};
          state._echoSeen[m.body] = local;
        } else {
          body = esc(state._echoSeen && state._echoSeen[m.body] ? state._echoSeen[m.body] : local);
        }
      } else {
        const echoed = state._echoSeen && state._echoSeen[m.body];
        body = echoed ? esc(echoed) : esc('sent (' + m.body.slice(0, 16) + ')');
      }
      locked = 'E2E';
    } else if (peer && peer.publicKey) {
      const plain = e2eDecrypt(peer.publicKey, m.body);
      body = plain !== null ? esc(plain) : esc('could not decrypt');
      locked = 'E2E';
    } else {
      body = esc('encrypted message');
      locked = 'E2E';
    }
  } else {
    body = esc(m.body);
  }
  const header = mine ? 'you' : senderName;
  div.innerHTML = '<div class="meta"><span class="name">' + esc(header) + '</span><span>' + time +
    (locked ? '</span><span class="locked">' + locked + '</span></div>' : '</div>') +
    '<div class="body">' + body + '</div>';
  el.appendChild(div);
}

/* ---------- boot ---------- */

bindActions();