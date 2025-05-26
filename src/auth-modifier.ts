import { ClientRequest, Modifier } from "@sigiljs/sigil"
import { InternalServerError } from "@sigiljs/sigil/responses"
import { AuthPlugin } from "~/index"


interface IAuthModifier {
  /** Refresh token or null if not presented */
  refreshToken: string | null

  /** Access token or null if not presented */
  accessToken: string | null

  /** True if access token presented, valid and not expired */
  accessTokenValid: boolean
}

/**
 * Authentication modifier that injects access and refresh
 * tokens from headers into request
 *
 * Automatically check if access token is valid
 */
export default class AuthModifier extends Modifier<IAuthModifier> {
  constructor() {
    super()
  }

  public onRequest(request: ClientRequest<any>) {
    const authPlugin = this.sigil?.plugin(AuthPlugin)
    if (!authPlugin) throw new InternalServerError("Auth plugin not installed")

    const { refreshTokenHeader, accessTokenHeader } = authPlugin.__$getAuthHeaders()
    const refreshToken = request.headers.get(refreshTokenHeader) || null
    const accessToken = request.headers.get(accessTokenHeader) || null

    return {
      refreshToken,
      accessToken,
      accessTokenValid: accessToken ? authPlugin.verifyAccessToken(accessToken) : false
    }
  }
}