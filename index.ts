/**
 * An implementation of rfc6749#section-4.1 and rfc7636.
 */

import murmurhash from 'murmurhash'

export interface Configuration {
  authorizationUrl: URL
  clientId: string
  explicitlyExposedTokens?: string[]
  redirectUrl: URL
  requestedScopes: string[]
  tokenUrl: URL
  extraAuthorizationParams?: ObjStringDict
  extraRefreshParams?: ObjStringDict
  onAccessTokenExpiry: (refreshAccessToken: () => Promise<AccessContext>) => Promise<AccessContext>
  onInvalidGrant: (refreshAuthCodeOrRefreshToken: () => Promise<void>) => void
}

export interface PKCECodes {
  codeChallenge: string
  codeVerifier: string
}

export interface State {
  isHTTPDecoratorActive?: boolean
  accessToken?: AccessToken
  authorizationCode?: string
  codeChallenge?: string
  codeVerifier?: string
  explicitlyExposedTokens?: ObjStringDict
  hasAuthCodeBeenExchangedForAccessToken?: boolean
  refreshToken?: RefreshToken
  stateQueryParam?: string
  grantedScopes?: string[]
}

export interface RefreshToken {
  value: string
}

export interface AccessToken {
  value: string
  expiry: string
}

export type Scopes = string[]

export interface AccessContext {
  token?: AccessToken
  explicitlyExposedTokens?: ObjStringDict
  grantedScopes?: Scopes
  refreshToken?: RefreshToken
}

export type ObjStringDict = { [_: string]: string }
export type HttpClient = (...args: any[]) => Promise<any>
export type URL = string

/**
 * A list of OAuth2AuthCodePKCE errors.
 */
// To "namespace" all errors.
Error.toString
export class ErrorOAuth2 extends Error {
  toString(): string {
    return 'ErrorOAuth2'
  }
}

export class ErrorLocalStorageUndefined extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorLocalStorageUndefined'
  }
}

// For really unknown errors.
export class ErrorUnknown extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorUnknown'
  }
}

// Some generic, internal errors that can happen.
export class ErrorNoAuthCode extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorNoAuthCode'
  }
}
export class ErrorInvalidReturnedStateParam extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorInvalidReturnedStateParam'
  }
}
export class ErrorInvalidJson extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorInvalidJson'
  }
}

// Errors that occur across many endpoints
export class ErrorInvalidScope extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorInvalidScope'
  }
}
export class ErrorInvalidRequest extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorInvalidRequest'
  }
}
export class ErrorInvalidToken extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorInvalidToken'
  }
}

/**
 * Possible authorization grant errors given by the redirection from the
 * authorization server.
 */
export class ErrorAuthenticationGrant extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorAuthenticationGrant'
  }
}
export class ErrorUnauthorizedClient extends ErrorAuthenticationGrant {
  toString(): string {
    return 'ErrorUnauthorizedClient'
  }
}
export class ErrorAccessDenied extends ErrorAuthenticationGrant {
  toString(): string {
    return 'ErrorAccessDenied'
  }
}
export class ErrorUnsupportedResponseType extends ErrorAuthenticationGrant {
  toString(): string {
    return 'ErrorUnsupportedResponseType'
  }
}
export class ErrorServerError extends ErrorAuthenticationGrant {
  toString(): string {
    return 'ErrorServerError'
  }
}
export class ErrorTemporarilyUnavailable extends ErrorAuthenticationGrant {
  toString(): string {
    return 'ErrorTemporarilyUnavailable'
  }
}

/**
 * A list of possible access token response errors.
 */
export class ErrorAccessTokenResponse extends ErrorOAuth2 {
  toString(): string {
    return 'ErrorAccessTokenResponse'
  }
}
export class ErrorInvalidClient extends ErrorAccessTokenResponse {
  toString(): string {
    return 'ErrorInvalidClient'
  }
}
export class ErrorInvalidGrant extends ErrorAccessTokenResponse {
  toString(): string {
    return 'ErrorInvalidGrant'
  }
}
export class ErrorUnsupportedGrantType extends ErrorAccessTokenResponse {
  toString(): string {
    return 'ErrorUnsupportedGrantType'
  }
}

/**
 * WWW-Authenticate error object structure for less error prone handling.
 */
export class ErrorWWWAuthenticate {
  public realm: string = ''
  public error: string = ''
}

export const RawErrorToErrorClassMap: { [_: string]: any } = {
  invalid_request: ErrorInvalidRequest,
  invalid_grant: ErrorInvalidGrant,
  unauthorized_client: ErrorUnauthorizedClient,
  access_denied: ErrorAccessDenied,
  unsupported_response_type: ErrorUnsupportedResponseType,
  invalid_scope: ErrorInvalidScope,
  server_error: ErrorServerError,
  temporarily_unavailable: ErrorTemporarilyUnavailable,
  invalid_client: ErrorInvalidClient,
  unsupported_grant_type: ErrorUnsupportedGrantType,
  invalid_json: ErrorInvalidJson,
  invalid_token: ErrorInvalidToken,
}

/**
 * Translate the raw error strings returned from the server into error classes.
 */
export function toErrorClass(rawError: string): ErrorOAuth2 {
  return new (RawErrorToErrorClassMap[rawError] || ErrorUnknown)()
}

/**
 * A convience function to turn, for example, `Bearer realm="bity.com",
 * error="invalid_client"` into `{ realm: "bity.com", error: "invalid_client"
 * }`.
 */
export function fromWWWAuthenticateHeaderStringToObject(a: string): ErrorWWWAuthenticate {
  const obj = a
    .slice('Bearer '.length)
    .replace(/"/g, '')
    .split(', ')
    .map((tokens) => {
      const [k, v] = tokens.split('=')
      return { [k]: v }
    })
    .reduce((a, c) => ({ ...a, ...c }), {})

  return { realm: obj.realm, error: obj.error }
}

/**
 * HTTP headers that we need to access.
 */
const HEADER_AUTHORIZATION = 'Authorization'
const HEADER_WWW_AUTHENTICATE = 'WWW-Authenticate'

/**
 * To store the OAuth client's data between websites due to redirection.
 */
export const LOCALSTORAGE_PREFIX = `oauth2authcodepkce`
export const LOCALSTORAGE_STATE_PREFIX = `${LOCALSTORAGE_PREFIX}-state`

/**
 * The maximum length for a code verifier for the best security we can offer.
 * Please note the NOTE section of RFC 7636 § 4.1 - the length must be >= 43,
 * but <= 128, **after** base64 url encoding. This means 32 code verifier bytes
 * encoded will be 43 bytes, or 96 bytes encoded will be 128 bytes. So 96 bytes
 * is the highest valid value that can be used.
 */
export const RECOMMENDED_CODE_VERIFIER_LENGTH = 96

/**
 * A sensible length for the state's length, for anti-csrf.
 */
export const RECOMMENDED_STATE_LENGTH = 32

/**
 * Character set to generate code verifier defined in rfc7636.
 */
const PKCE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'

/**
 * OAuth 2.0 client that ONLY supports authorization code flow, with PKCE.
 *
 * Many applications structure their OAuth usage in different ways. This class
 * aims to provide both flexible and easy ways to use this configuration of
 * OAuth.
 *
 * See `example.ts` for how you'd typically use this.
 *
 * For others, review this class's methods.
 */
export class OAuth2AuthCodePKCE {
  private config!: Configuration
  private state: State = {}
  private authCodeForAccessTokenRequest?: Promise<AccessContext>

  constructor(config: Configuration) {
    this.config = config
    this.recoverStoredState()
    return this
  }

  /**
   * Attach the OAuth logic to all fetch requests and translate errors (either
   * returned as json or through the `WWW-Authenticate` header) into nice error
   * classes.
   */
  public decorateFetchHTTPClient(fetch: HttpClient): HttpClient {
    return async (url: string, config: any, ...rest) => {
      if (!this.state.isHTTPDecoratorActive) {
        return fetch(url, config, ...rest)
      }

      const { token } = await this.getAccessToken()

      const configNew: any = Object.assign({}, config)
      if (!configNew.headers) {
        configNew.headers = {}
      }
      configNew.headers[HEADER_AUTHORIZATION] = `Bearer ${token!.value}`
      
      const res = await fetch(url, configNew, ...rest)
      
      if (res.ok) {
        return res
      }

      if (!res.headers.has(HEADER_WWW_AUTHENTICATE.toLowerCase())) {
        return res
      }
      
      const error = toErrorClass(
        fromWWWAuthenticateHeaderStringToObject(
          res.headers.get(HEADER_WWW_AUTHENTICATE.toLowerCase()),
        ).error,
      )

      if (error instanceof ErrorInvalidToken) {
        this.config.onAccessTokenExpiry(() => this.exchangeRefreshTokenForAccessToken())
      }

      return Promise.reject(error)
    }
  }

  /**
   * Resolve to a `boolean` indicating whether the user has just returned from
   * the auth server by checking for the `code` and `state` query string
   * parameters.
   *
   * If the `code` param is not present, resolves to `false`,
   * in which case the caller chould use `fetchAuthorizationCode` to redirect
   * the user to the auth server (starting the auth flow).
   *
   * If the `code` is present but the `state` is either missing or does not match the
   * one stored in `localStorage`, rejects with an `ErrorInvalidReturnedStateParam`.
   *
   * If `code` and `state` are both present and the `state` matches, sets `this.state.authorizationCode`
   * to the new `code` from the query param, updates `localStorage` with the current `this.state`, and
   * resolves to `true`.
   */
  public isReturningFromAuthServer(): Promise<boolean> {
    const error = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'error')
    if (error) {
      return Promise.reject(toErrorClass(error))
    }

    const code = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'code')
    if (!code) {
      return Promise.resolve(false)
    }

    const state = this.getStoredState() || {}

    const stateQueryParam = OAuth2AuthCodePKCE.extractParamFromUrl(location.href, 'state')
    if (stateQueryParam !== state.stateQueryParam) {
      console.warn(
        "state query string parameter doesn't match the one sent! Possible malicious activity somewhere.",
      )
      return Promise.reject(new ErrorInvalidReturnedStateParam())
    }

    // TODO: Investigate the implications of commenting the lines below.
    // I think it's correct because setting `hasAuthCodeBeenExchangedForAccessToken = false`
    // is sneaky and nonintuitive. Read more: 
    // https://github.com/BitySA/oauth2-auth-code-pkce/issues/38#issue-2780821550
    // state.hasAuthCodeBeenExchangedForAccessToken = false

    state.authorizationCode = code
    this.setAndStoreState(state)

    return Promise.resolve(true)
  }

  /**
   * Fetch an authorization grant via redirection. In a sense this function
   * doesn't return because of the redirect behavior (uses `location.replace`).
   *
   * @param oneTimeParams A way to specify "one time" used query string
   * parameters during the authorization code fetching process, usually for
   * values which need to change at run-time.
   */
  public async fetchAuthorizationCode(
    oneTimeParams?: ObjStringDict, // TODO: Probably remove these and add an interface for modifying `this.config.extraAuthorizationParams`
  ): Promise<void> {
    this.assertStateAndConfigArePresent()

    const { clientId, extraAuthorizationParams, redirectUrl, requestedScopes: scopes } = this.config
    const { codeChallenge, codeVerifier } = await OAuth2AuthCodePKCE.generatePKCECodes()
    const stateQueryParam = OAuth2AuthCodePKCE.generateRandomState(RECOMMENDED_STATE_LENGTH)

    this.state = {
      ...this.state,
      codeChallenge,
      codeVerifier,
      stateQueryParam,
      isHTTPDecoratorActive: true,
    }

    this.storeState()

    let url =
      this.config.authorizationUrl +
      `?response_type=code&` +
      `client_id=${encodeURIComponent(clientId)}&` +
      `redirect_uri=${encodeURIComponent(redirectUrl)}&` +
      `scope=${encodeURIComponent(scopes.join(' '))}&` +
      `state=${stateQueryParam}&` +
      `code_challenge=${encodeURIComponent(codeChallenge)}&` +
      `code_challenge_method=S256`

    if (extraAuthorizationParams || oneTimeParams) {
      const extraParameters: ObjStringDict = {
        ...extraAuthorizationParams,
        ...oneTimeParams,
      }

      url = `${url}&${OAuth2AuthCodePKCE.objectToQueryString(extraParameters)}`
    }

    location.replace(url)
  }

  /**
   * Tries to get the current access token. If there is none
   * it will fetch another one. If it is expired, it will fire
   * `this.config.onAccessTokenExpiry`, but it's up to the user to call the refresh token
   * function. This is because sometimes not using the refresh token facilities
   * is easier.
   */
  public getAccessToken(): Promise<AccessContext> {
    this.assertStateAndConfigArePresent()

    const {
      accessToken,
      authorizationCode,
      explicitlyExposedTokens,
      hasAuthCodeBeenExchangedForAccessToken,
      refreshToken,
      grantedScopes,
    } = this.state

    if (!authorizationCode) {
      return Promise.reject(new ErrorNoAuthCode())
    }

    if (this.authCodeForAccessTokenRequest) {
      return this.authCodeForAccessTokenRequest
    }

    if (!this.isAuthorized() || !hasAuthCodeBeenExchangedForAccessToken) {
      this.authCodeForAccessTokenRequest = this.exchangeAuthCodeForAccessToken()
      return this.authCodeForAccessTokenRequest
    }

    // Depending on the server (and config), refreshToken may not be available.
    if (refreshToken && this.isAccessTokenExpired()) {
      return this.config.onAccessTokenExpiry(() => this.exchangeRefreshTokenForAccessToken())
    }

    return Promise.resolve({
      token: accessToken,
      explicitlyExposedTokens,
      grantedScopes,
      refreshToken,
    })
  }

  /**
   * Refresh an access token from the remote service.
   */
  public async exchangeRefreshTokenForAccessToken(): Promise<AccessContext> {
    this.assertStateAndConfigArePresent()

    const { extraRefreshParams, clientId, tokenUrl } = this.config
    const { refreshToken } = this.state

    if (!refreshToken) {
      console.warn('No refresh token is present.')
    }

    let body =
      `grant_type=refresh_token&` +
      `refresh_token=${refreshToken?.value}&` +
      `client_id=${clientId}`

    if (extraRefreshParams) {
      body = `${tokenUrl}&${OAuth2AuthCodePKCE.objectToQueryString(extraRefreshParams)}`
    }

    try {
      const res = await fetch(tokenUrl, {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      })
      const json = await (res.status >= 400
        ? res.json().then((data) => Promise.reject(data))
        : res.json())
      const {
        access_token: accessToken,
        expires_in: expiresIn,
        refresh_token: refreshToken,
        scope: grantedScopesString,
      } = json

      // Update access token in `this.state`
      this.state.accessToken = {
        value: accessToken,
        expiry: new Date(Date.now() + parseInt(expiresIn) * 1000).toString(),
      }

      // Update refresh token in `this.state`
      if (refreshToken) {
        this.state.refreshToken = { value: refreshToken }
      }

      // If the server returned an explicit list of granted scopes, set them in `this.state`.
      // Otherwise assume all requested scopes were granted.
      if (grantedScopesString) {
        // Multiple scopes are passed and delimited by spaces,
        // despite using the singular name "scope".
        this.state.grantedScopes = grantedScopesString.split(' ')
      } else {
        this.state.grantedScopes = this.config.requestedScopes
      }

      // Finally, build the access context using the token and granted scopes
      let accessContext: AccessContext = {
        token: this.state.accessToken!,
        grantedScopes: this.state.grantedScopes,
      }

      // Add any explicitly exposed tokens to `this.state` and `accessContext`
      if (this.config.explicitlyExposedTokens) {
        const explicitlyExposedTokens = Object.fromEntries(
          this.config.explicitlyExposedTokens
            .map((tokenName: string): [string, string | undefined] => [tokenName, json[tokenName]])
            .filter(([_, tokenValue]: [string, string | undefined]) => tokenValue !== undefined),
        ) as ObjStringDict

        this.state.explicitlyExposedTokens = explicitlyExposedTokens
        accessContext.explicitlyExposedTokens = explicitlyExposedTokens
      }

      this.storeState()

      return accessContext
    } catch (e: any) {
      const error = e.error || 'There was a network error.'
      switch (error) {
        case 'invalid_grant':
          this.config.onInvalidGrant(() => this.fetchAuthorizationCode())
          break
        default:
          break
      }
      return await Promise.reject(toErrorClass(error))
    }
  }

  /**
   * Get the scopes that were granted by the authorization server.
   */
  public getGrantedScopes(): Scopes | undefined {
    return this.state.grantedScopes
  }

  /**
   * Return a bool indicating whether the OAuth HTTP decorator is active.
   */
  public getIsHTTPDecoratorActive(): boolean {
    return this.state.isHTTPDecoratorActive || false
  }

  /**
   * Tells if the client is authorized or not. This means the client has at
   * least once successfully fetched an access token. The access token could be
   * expired.
   */
  public isAuthorized(): boolean {
    return !!this.state.accessToken
  }

  /**
   * Checks to see if the access token has expired.
   */
  public isAccessTokenExpired(): boolean {
    return Boolean(this.state.accessToken && new Date() >= new Date(this.state.accessToken.expiry))
  }

  /**
   * Resets the state of the client. Equivalent to "logging out" the user.
   */
  public reset() {
    this.setAndStoreState({})
    this.authCodeForAccessTokenRequest = undefined
  }

  /**
   * Throw an error if the state or config are missing, meaning the client is in a bad state.
   * This should never happen, but the check is there just in case.
   */
  private assertStateAndConfigArePresent() {
    if (!this.state || !this.config) {
      throw new Error(`state or config is not set. state: ${this.state}, config: ${this.config}`)
    }
  }

  /**
   * Fetch an access token from the remote service. You may pass a custom
   * authorization grant code to be used instead of `this.state.authorizationCode`,
   * but this is non-standard usage.
   */
  private async exchangeAuthCodeForAccessToken(codeOverride?: string): Promise<AccessContext> {
    this.assertStateAndConfigArePresent()

    const { clientId, onInvalidGrant, redirectUrl, tokenUrl } = this.config
    const { authorizationCode = codeOverride, codeVerifier = '' } = this.state

    if (!codeVerifier) {
      console.warn('No code verifier is being sent.')
    } else if (!authorizationCode) {
      console.warn('No authorization grant code is being passed.')
    }

    const body =
      `grant_type=authorization_code&` +
      `code=${encodeURIComponent(authorizationCode || '')}&` +
      `redirect_uri=${encodeURIComponent(redirectUrl)}&` +
      `client_id=${encodeURIComponent(clientId)}&` +
      `code_verifier=${codeVerifier}`

    const res = await fetch(tokenUrl, {
      method: 'POST',
      body,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })
    const json = await res.json().catch((_) => ({ error: 'invalid_json' }))

    // If response is not OK, try to parse the error and reject with the error class.
    if (!res.ok) {
      const { error } = json
      switch (error) {
        case 'invalid_grant':
          onInvalidGrant(() => this.fetchAuthorizationCode())
          break
        default:
          break
      }
      return Promise.reject(toErrorClass(error))
    }

    const {
      access_token: accessToken,
      expires_in: expiresIn,
      refresh_token: refreshToken,
      scope: grantedScopesString,
    } = json

    // Set `this.state` to reflect that the auth code has been exchanged for an access token
    this.state.hasAuthCodeBeenExchangedForAccessToken = true

    // Update access token in `this.state`
    this.authCodeForAccessTokenRequest = undefined

    // Update access token in `this.state`
    this.state.accessToken = {
      value: accessToken,
      expiry: new Date(Date.now() + parseInt(expiresIn) * 1000).toString(),
    }

    // Update refresh token in `this.state`
    if (refreshToken) {
      this.state.refreshToken = { value: refreshToken }
    }

    // If the server returned an explicit list of granted scopes, set them in `this.state`.
    // Otherwise assume all requested scopes were granted.
    if (grantedScopesString) {
      // Multiple scopes are passed and delimited by spaces, despite
      // the singular name "scope" in the JSON response
      this.state.grantedScopes = grantedScopesString.split(' ')
    } else {
      this.state.grantedScopes = this.config.requestedScopes
    }

    // Finally, build the access context using the token and granted scopes
    let accessContext: AccessContext = {
      token: this.state.accessToken,
      grantedScopes: this.state.grantedScopes,
    }

    // Add any explicitly exposed tokens to `this.state` and `accessContext`
    if (this.config.explicitlyExposedTokens) {
      const explicitlyExposedTokens = Object.fromEntries(
        this.config.explicitlyExposedTokens
          .map((tokenName: string): [string, string | undefined] => [tokenName, json[tokenName]])
          .filter(([__1, tokenValue]: [string, string | undefined]) => tokenValue !== undefined),
      ) as ObjStringDict

      this.state.explicitlyExposedTokens = explicitlyExposedTokens
      accessContext.explicitlyExposedTokens = explicitlyExposedTokens
    }

    this.storeState()

    return accessContext
  }

  /**
   * Set `this.state` to the state stored in `localStorage`. If no state is
   * stored, it will be set to an empty object.
   */
  private recoverStoredState(): void {
    this.state = this.getStoredState() ?? {}
  }

  /**
   * Throw an error if `localStorage` is not available.
   */
  private assertLocalStorageAvailable(): void {
    if (typeof localStorage === 'undefined') {
      throw new ErrorLocalStorageUndefined()
    }
  }

  /**
   * The key used to store the state in `localStorage`. Hashes some fields from
   * `this.config` to generate a key unique to the client and the auth server combo.
   */
  public get stateStorageKey(): string {
    const hashable = JSON.stringify({
      authorizationUrl: this.config.authorizationUrl,
      clientId: this.config.clientId,
      extraAuthorizationParams: this.config.extraAuthorizationParams,
      extraRefreshParams: this.config.extraRefreshParams,
      redirectUrl: this.config.redirectUrl,
      requestedScopes: this.config.requestedScopes,
      tokenUrl: this.config.tokenUrl,
    })
    const hash = murmurhash.v3(hashable, 0xC4E55)
    return `${LOCALSTORAGE_STATE_PREFIX}-${hash}`
  }

  /**
   * Write the current `this.state` to `localStorage`.
   */
  private storeState(): void {
    this.assertLocalStorageAvailable()
    localStorage.setItem(this.stateStorageKey, JSON.stringify(this.state))
  }

  /**
   * Return the state stored in `localStorage`. Throws an error if `localStorage`
   * is not available.
   */
  public getStoredState(): State | null {
    this.assertLocalStorageAvailable()
    const storedState = localStorage.getItem(this.stateStorageKey)
    return storedState ? JSON.parse(storedState) : storedState
  }

  /**
   * Set `this.state` to the given `State`.
   */
  private setState(state: State): void {
    this.state = state
  }

  /**
   * Set `this.state` to the given `State` and saves the stringified object
   * to `localStorage`.
   */
  private setAndStoreState(state: State): void {
    this.setState(state)
    this.storeState()
  }

  /**
   * Implements *base64url-encode* ([RFC 4648 § 5](https://datatracker.ietf.org/doc/html/rfc4648#section-5))
   * without padding, which is NOT the same as regular base64 encoding.
   */
  static base64urlEncode(value: string): string {
    let base64 = btoa(value)
    base64 = base64.replace(/\+/g, '-')
    base64 = base64.replace(/\//g, '_')
    base64 = base64.replace(/=/g, '')
    return base64
  }

  /**
   * Extracts a query string parameter.
   */
  static extractParamFromUrl(url: URL, param: string): string {
    let queryString = url.split('?')
    if (queryString.length < 2) {
      return ''
    }

    // Account for hash URLs that SPAs usually use.
    queryString = queryString[1].split('#')

    const parts = queryString[0]
      .split('&')
      .reduce((a: string[], s: string) => a.concat(s.split('=')), [])

    if (parts.length < 2) {
      return ''
    }

    const paramIdx = parts.indexOf(param)
    return decodeURIComponent(paramIdx >= 0 ? parts[paramIdx + 1] : '')
  }

  /**
   * Converts the keys and values of an object to a url query string
   */
  static objectToQueryString(dict: ObjStringDict): string {
    return Object.entries(dict)
      .map(([key, val]: [string, string]) => `${key}=${encodeURIComponent(val)}`)
      .join('&')
  }

  /**
   * Generates a `code_verifier` and `code_challenge`, as specified in [rfc7636](https://datatracker.ietf.org/doc/html/rfc7636).
   */
  static async generatePKCECodes(): Promise<PKCECodes> {
    const output = new Uint32Array(RECOMMENDED_CODE_VERIFIER_LENGTH)
    crypto.getRandomValues(output)
    const codeVerifier = OAuth2AuthCodePKCE.base64urlEncode(
      Array.from(output)
        .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
        .join(''),
    )

    const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
    let hash = new Uint8Array(buffer)
    let binary = ''
    let hashLength = hash.byteLength
    for (let i: number = 0; i < hashLength; i++) {
      binary += String.fromCharCode(hash[i])
    }
    const value = binary
    const codeChallenge = OAuth2AuthCodePKCE.base64urlEncode(value)
    return { codeChallenge, codeVerifier }
  }

  /**
   * Generates random state to be passed for [anti-csrf](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
   */
  static generateRandomState(lengthOfState: number): string {
    const output = new Uint32Array(lengthOfState)
    crypto.getRandomValues(output)
    return Array.from(output)
      .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
      .join('')
  }
}
