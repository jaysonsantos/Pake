// Bridge browser WebAuthn calls to the native tauri-plugin-webauthn plugin.
// The plugin exposes Tauri commands, but normal websites call navigator.credentials.
// This polyfill translates between the browser API shape (ArrayBuffers) and the
// SimpleWebAuthn JSON shape used by the plugin.
(function () {
  if (window.__PAKE_WEBAUTHN_BRIDGE_INSTALLED__) return;
  window.__PAKE_WEBAUTHN_BRIDGE_INSTALLED__ = true;

  const base64UrlChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  function isArrayBufferLike(value) {
    return value instanceof ArrayBuffer || ArrayBuffer.isView(value);
  }

  function toUint8Array(value) {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    return null;
  }

  function bufferToBase64Url(value) {
    const bytes = toUint8Array(value);
    if (!bytes) return value;

    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBuffer(value) {
    if (typeof value !== "string") return value;
    if (!value || ![...value].every((char) => base64UrlChars.includes(char))) {
      return value;
    }

    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    try {
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    } catch (_) {
      return value;
    }
  }

  function jsonCloneWithBuffersAsBase64Url(value) {
    if (isArrayBufferLike(value)) return bufferToBase64Url(value);
    if (Array.isArray(value)) return value.map(jsonCloneWithBuffersAsBase64Url);
    if (value && typeof value === "object") {
      const out = {};
      for (const [key, child] of Object.entries(value)) {
        out[key] = jsonCloneWithBuffersAsBase64Url(child);
      }
      return out;
    }
    return value;
  }

  function credentialResponseToBuffers(response) {
    if (!response || typeof response !== "object") return response;
    const out = {};
    for (const [key, value] of Object.entries(response)) {
      out[key] = typeof value === "string" ? base64UrlToBuffer(value) : value;
    }
    return out;
  }

  function makePublicKeyCredential(json) {
    const rawId = base64UrlToBuffer(json.rawId || json.id);
    const response = credentialResponseToBuffers(json.response);
    const clientExtensionResults = json.clientExtensionResults || {};

    return {
      id: json.id,
      rawId,
      response,
      type: json.type || "public-key",
      authenticatorAttachment: json.authenticatorAttachment || null,
      getClientExtensionResults: () => clientExtensionResults,
      toJSON: () => json,
    };
  }

  function getInvoke() {
    return window.__TAURI__?.core?.invoke;
  }

  function shouldUseNative(options) {
    return options && typeof options === "object" && options.publicKey;
  }

  const originalCredentials = navigator.credentials;
  if (!originalCredentials) return;

  const originalCreate = originalCredentials.create?.bind(originalCredentials);
  const originalGet = originalCredentials.get?.bind(originalCredentials);

  async function nativeCreate(options) {
    const invoke = getInvoke();
    if (!invoke || !shouldUseNative(options)) return originalCreate(options);

    const response = await invoke("plugin:webauthn|register", {
      origin: window.location.origin,
      options: jsonCloneWithBuffersAsBase64Url(options.publicKey),
    });
    return makePublicKeyCredential(response);
  }

  async function nativeGet(options) {
    const invoke = getInvoke();
    if (!invoke || !shouldUseNative(options)) return originalGet(options);

    const response = await invoke("plugin:webauthn|authenticate", {
      origin: window.location.origin,
      options: jsonCloneWithBuffersAsBase64Url(options.publicKey),
    });
    return makePublicKeyCredential(response);
  }

  try {
    Object.defineProperty(originalCredentials, "create", {
      configurable: true,
      writable: true,
      value: nativeCreate,
    });
    Object.defineProperty(originalCredentials, "get", {
      configurable: true,
      writable: true,
      value: nativeGet,
    });
  } catch (_) {
    // Some WebViews may expose a less configurable CredentialsContainer.
    // In that case keep the native behavior instead of breaking login entirely.
  }
})();
