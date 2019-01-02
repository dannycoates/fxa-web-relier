import { arrayToB64, b64ToArray, concat, concatKdf } from "./utils";

export interface RelierOptions {
  clientId: string;
  storage: Storage;
  scopes: string[];
  openidConfigUrl: string;
}

interface OAuthRequestParams extends Record<string, any> {
  client_id: string;
  state: string;
  response_type: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  email?: string;
  keys_jwk?: string;
}

const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

export interface SavedState {
  pkceVerifier: string;
  oauthState: string;
  scopedBundlePrivateKey?: string;
}

export interface LoginInfo extends SavedState {
  requestParams: OAuthRequestParams;
}

export async function getLoginInfo(
  clientId: string,
  scopes: string[],
  email?: string
) {
  const verifier = arrayToB64(crypto.getRandomValues(new Uint8Array(64)));
  const challenge = await crypto.subtle.digest(
    "SHA-256",
    ENCODER.encode(verifier)
  );
  const requestParams = {
    client_id: clientId,
    scope: scopes.join(" "),
    state: arrayToB64(crypto.getRandomValues(new Uint8Array(16))),
    response_type: "code",
    code_challenge_method: "S256",
    code_challenge: arrayToB64(new Uint8Array(challenge))
  } as OAuthRequestParams;
  if (email) {
    requestParams.email = email;
  }
  const result = {
    pkceVerifier: verifier,
    oauthState: requestParams.state,
    requestParams
  } as LoginInfo;
  // TODO find scoped keys better
  if (scopes.some(scope => scope.startsWith("http"))) {
    const keys = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256"
      },
      true,
      ["deriveBits"]
    );
    const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
    const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    requestParams.keys_jwk = arrayToB64(
      ENCODER.encode(JSON.stringify(publicJwk))
    );
    result.scopedBundlePrivateKey = JSON.stringify(privateJwk);
  }
  return result;
}

export async function exchangeCodeForToken(
  clientId: string,
  queryString: string,
  pkceVerifier: string,
  oauthState: string,
  tokenUrl: string
) {
  const params = new URLSearchParams(queryString);
  const code = params.get("code");
  const state = params.get("state");
  if (oauthState !== state) {
    throw new Error("oauth state mismatch");
  }
  const tokenResponse = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code,
      client_id: clientId,
      code_verifier: pkceVerifier
    })
  });
  const auth = await tokenResponse.json();
  return auth;
}

export async function getUserInfo(userInfoUrl: string, accessToken: string) {
  const infoResponse = await fetch(userInfoUrl, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`
    }
  });
  const userInfo = await infoResponse.json();
  return userInfo;
}

export async function decryptScopedKeysBundle(key: string, bundle: string) {
  const privateJwk = JSON.parse(key);
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    false,
    ["deriveBits"]
  );
  const jweParts = bundle.split(".");
  if (jweParts.length !== 5) {
    throw new Error("invalid jwe");
  }
  const header = JSON.parse(DECODER.decode(b64ToArray(jweParts[0])));
  if (header.alg !== "ECDH-ES" || header.enc !== "A256GCM") {
    throw new Error("unsupported jwe type");
  }

  const additionalData = ENCODER.encode(jweParts[0]);
  const iv = b64ToArray(jweParts[2]);
  const ciphertext = b64ToArray(jweParts[3]);
  const tag = b64ToArray(jweParts[4]);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    header.epk,
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    false,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey
    },
    privateKey,
    256
  );
  const rawSharedKey = await concatKdf(new Uint8Array(sharedBits), header.enc);
  const sharedKey = await crypto.subtle.importKey(
    "raw",
    rawSharedKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
      additionalData: additionalData,
      tagLength: tag.length * 8
    },
    sharedKey,
    concat(ciphertext, tag)
  );

  return JSON.parse(DECODER.decode(plaintext));
}

export async function getOpenIdConfig(url: string) {
  const response = await fetch(url);
  return response.json();
}

export class Relier {
  clientId: string;
  scopes: string[];
  storage: Storage;
  configUrl: string;

  constructor(options: RelierOptions) {
    this.clientId = options.clientId;
    this.storage = options.storage;
    this.scopes = options.scopes;
    this.configUrl = options.openidConfigUrl;
  }

  async beginLogin(email?: string) {
    const info = await getLoginInfo(this.clientId, this.scopes, email);
    this.storage.setItem("pkceVerifier", info.pkceVerifier);
    this.storage.setItem("oauthState", info.oauthState);
    if (info.scopedBundlePrivateKey) {
      this.storage.setItem(
        "scopedBundlePrivateKey",
        info.scopedBundlePrivateKey
      );
    }
    const config = await getOpenIdConfig(this.configUrl);
    const queryString = new URLSearchParams(info.requestParams).toString();
    location.assign(`${config.authorization_endpoint}?${queryString}`);
  }

  async finishLogin(queryString: string) {
    const pkceVerifier = this.storage.getItem("pkceVerifier");
    const oauthState = this.storage.getItem("oauthState");
    const scopedBundlePrivateKey = this.storage.getItem(
      "scopedBundlePrivateKey"
    );
    if (!pkceVerifier) {
      throw new Error("no PKCE verifier in storage");
    }
    if (!oauthState) {
      throw new Error("no oauth state in storage");
    }
    const config = await getOpenIdConfig(this.configUrl);
    const authInfo = await exchangeCodeForToken(
      this.clientId,
      queryString,
      pkceVerifier,
      oauthState,
      config.token_endpoint
    );
    const result = {
      authInfo
    } as Record<string, any>; //TODO
    if (this.scopes.includes("profile")) {
      result.userInfo = await getUserInfo(
        config.userinfo_endpoint,
        authInfo.access_token
      );
    }
    if (scopedBundlePrivateKey && authInfo.keys_jwe) {
      result.jwks = await decryptScopedKeysBundle(
        scopedBundlePrivateKey,
        authInfo.keys_jwe
      );
    }
    return result;
  }
}
