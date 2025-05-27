import { SigilPlugin } from "@sigiljs/sigil"
import * as crypto from "crypto"
import WebTokensController, { TokenPayload } from "~/web-tokens-controller"

export interface AuthPluginConfig {
  /**
   * Secret key for tokens generation
   *
   * While optional, it is strongly recommended to set up
   * your own secret token for production environments
   *
   * @default Random 32 bytes long key
   */
  secretKey?: Buffer | string

  /**
   * List of protected routes
   *
   * If not set up, you will need to manually add modifier to each protected route
   */
  protectedRoutes?: string[]

  /**
   * Define custom names for refresh and access token headers
   *
   * @default X-Sigil-Refresh-Token, Authorization
   */
  authHeaders?: {
    refreshToken: string
    accessToken: string
  }
}

/**
 * Plugin for SigilJS framework that provides authentication with JWT-like tokens
 */
export default class AuthPlugin extends SigilPlugin<AuthPluginConfig> {
  public static name = "AuthPlugin"

  #webTokensController: WebTokensController

  constructor() {
    super()

    if (!this.$pluginConfig.secretKey) {
      this.logger({
        level: "warning",
        message: "No secret key found for web tokens generation, temporary key will be generated",
        json: { milestone: "secret", ok: false }
      })

      this.logger({
        level: "warning",
        message: "It is strongly recommended to avoid starting application without secret key in production environments"
      })
    }
    else this.logger({
      level: "info",
      message: "Successfully configured authentication plugin",
      json: { milestone: "secret", ok: true }
    })

    const secretKey = this.$pluginConfig.secretKey || crypto.randomBytes(32)
    this.#webTokensController = new WebTokensController(secretKey)
    this.$pluginConfig.secretKey = Buffer.from(String())
  }

  public onInitialize(): void {
    if (!this.$pluginConfig.protectedRoutes || this.$pluginConfig.protectedRoutes.length === 0) {
      this.logger({
        level: "warning",
        message: "Authentication middleware not configured, you'll need to manually set up modifiers for each protected route",
        condition: !this.$pluginConfig.secretKey,
        json: { milestone: "middleware", ok: false }
      })

      return
    }
    else this.logger({
      level: "info",
      message: `Successfully configured authentication middleware for ${this.$pluginConfig.protectedRoutes.length} protected route(s)`,
      condition: !this.$pluginConfig.secretKey,
      json: { milestone: "middleware", ok: true }
    })

    this.sigil.addMiddleware(async (req, res) => {
      if (!this.$pluginConfig.protectedRoutes?.some(r => req.path.startsWith(r))) return

      const accessToken = req.headers.get("authorization")
      if (!accessToken) return res.forbidden()

      if (!this.verifyAccessToken(accessToken)) return res.forbidden()
    })
  }

  /**
   * Issue new access token with specified payload
   *
   * @param payload access token payload
   * @returns {string} generated access token
   */
  public issueAccessToken(payload: any): string {
    return this.#webTokensController.issueWebToken(payload)
  }

  /**
   * Issue new refresh token
   *
   * @returns {{refreshToken: string, refreshTokenHash: string}} generated refresh token
   */
  public issueRefreshToken(): { refreshToken: string, refreshTokenHash: string } {
    return this.#webTokensController.issueRefreshToken()
  }

  /**
   * Check if specified access token is valid
   *
   * @param {string} token access token
   * @param allowExpired if true, valid tokens will still valid even if expired
   * @returns {boolean} is valid
   */
  public verifyAccessToken(token: string, allowExpired?: boolean): boolean {
    return this.#webTokensController.verifyWebToken(token, allowExpired)
  }

  /**
   * Check refresh token integrity with stored hash
   *
   * @param {string} hash stored hash
   * @param {string} token refresh token
   * @returns {boolean} is valid
   */
  public verifyRefreshToken(hash: string, token: string): boolean {
    return this.#webTokensController.verifyRefreshToken(hash, token)
  }

  /**
   * Decode specified access token
   *
   * @param {string} token access token to decode
   * @returns {TokenPayload | null} decode access token payload or null if in invalid format
   */
  public decodeWebToken<T = any>(token: string): TokenPayload<T> | null {
    return this.#webTokensController.decodeWebToken(token)
  }

  /**
   * @internal
   */
  public __$getAuthHeaders() {
    return {
      refreshTokenHeader: this.$pluginConfig.authHeaders?.refreshToken || "X-Sigil-Refresh-Token",
      accessTokenHeader: this.$pluginConfig.authHeaders?.accessToken || "Authorization"
    }
  }
}