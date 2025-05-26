# Sigil Auth Plugin

Plugin for SigilJS framework that provides authentication with JWT-like tokens
## Installation

```bash
npm install @sigiljs-community/auth-plugin
# or
yarn add @sigiljs-community/auth-plugin
```


## Usage

### Import and register the plugin

```typescript
import { Sigil } from "@sigiljs/sigil"
import { AuthPlugin } from "@sigiljs-community/auth-plugin"

const app = new Sigil()

// Register plugin with settings
app.addPlugin(AuthPlugin, {
  /**
   * Secret key for tokens generation
   *
   * While optional, it is strongly recommended to set up
   * your own secret token for production environments
   *
   * @default Random 32 bytes long key
   */
  secretKey: "",

  /**
   * List of protected routes
   *
   * If not set up, you will need to manually add modifier to each protected route
   */
  protectedRoutes: [],

  /**
   * Define custom names for refresh and access token headers
   *
   * @default X-Sigil-Refresh-Token, Authorization
   */
  authHeaders: {
    refreshToken: "X-Refresh-Token",
    accessToken: "Authorization"
  }
})
```

_See available plugin methods for more information_

### Protecting specified route
If protected routes not set up, you will need to provide AuthModifier for each protected route manually

AuthModifier also injects following fields in the request: `accessToken`, `accessTokenValid`, `refreshToken`, so it is still
useful even if protected routes are set up

```typescript
import { AuthModifier } from "@sigiljs-community/auth-plugin"

const route = app.createRoute("/", {
  modifiers: [AuthModifier]
})

route.get("/", request => {
  return request.accessToken // <- string or null
})
```

## License

You can copy and paste the MIT license summary from below.

```text
MIT License

Copyright (c) 2022 Kurai Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

