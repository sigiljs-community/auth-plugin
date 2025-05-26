import * as crypto from "node:crypto"

interface TokenHeader {
  iat: number
  exp: number
}

export interface TokenPayload<T = any> {
  header: TokenHeader
  payload: T
  b64_header: string
  b64_payload: string
  receivedMac: string
}

export default class WebTokensController {
  readonly #secretKey: Buffer

  constructor(secretKey: Buffer | string) {
    this.#secretKey = Buffer.isBuffer(secretKey) ? secretKey : Buffer.from(secretKey)
  }

  public issueWebToken(payload: any, expiresIn: number = 5 * 60 * 1000) {
    const expiresAt = Date.now() + expiresIn

    const b64_payload = Buffer.from(JSON.stringify(payload)).toString("base64url")
    const b64_header = Buffer.from(JSON.stringify({
      exp: expiresAt,
      iat: Date.now()
    })).toString("base64url")

    const mac = this.deriveMac(b64_payload, b64_header)

    return `${ b64_header }.${ b64_payload }.${ mac }`
  }

  public verifyRefreshToken(hash: string, refreshToken: string) {
    const refreshTokenHash = crypto.createHash("sha512")
      .update(refreshToken)
      .digest("base64url")

    const sig = Buffer.from(refreshTokenHash, "base64url")
    const ref = Buffer.from(hash, "base64url")

    return !(sig.length !== ref.length || !crypto.timingSafeEqual(sig, ref))
  }

  public issueRefreshToken() {
    const refreshToken = crypto.randomBytes(64).toString("base64url")
    const refreshTokenHash = crypto.createHash("sha512")
      .update(refreshToken)
      .digest("base64url")

    return {
      refreshToken,
      refreshTokenHash
    }
  }

  public verifyWebToken(token: string, allowExpired = false) {
    try {
      const webTokenDetails = this.decodeWebToken(token)
      if (!webTokenDetails) return false

      const { header, b64_header, b64_payload, receivedMac } = webTokenDetails

      const skew = 60 * 1000
      if (Date.now() - skew > header.exp && !allowExpired) return false

      const derivedMac = this.deriveMac(b64_payload, b64_header)

      const sig = Buffer.from(derivedMac, "utf8")
      const ref = Buffer.from(receivedMac, "utf8")

      return !(sig.length !== ref.length || !crypto.timingSafeEqual(sig, ref))
    }
    catch {
      return false
    }
  }

  public decodeWebToken<T = any>(token: string): TokenPayload<T> | null {
    const splitToken = token.split(".")

    if (splitToken.length !== 3) return null

    const [b64_header, b64_payload, receivedMac] = splitToken

    try {
      const header = JSON.parse(Buffer.from(b64_header, "base64url").toString("utf8")) as TokenHeader

      const payload = JSON.parse(Buffer.from(b64_payload, "base64url").toString("utf8")) as T

      return { header, payload, b64_header, b64_payload, receivedMac }
    }
    catch (err: any) {
      return null
    }
  }

  private deriveMac(b64_header: string, b64_payload: string) {
    const encodedData = `${ b64_header }.${ b64_payload }`

    const h = crypto.createHmac("sha512", this.#secretKey)
    h.update(encodedData)

    return h.digest("base64url")
  }
}