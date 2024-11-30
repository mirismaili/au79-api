declare namespace NodeJS {
  // noinspection JSUnusedGlobalSymbols
  type ProcessEnv = {
    readonly CORS_ORIGIN: string
    readonly RPID: string
    readonly REDIS_URL: string
    readonly DATABASE_URL: string
    readonly PEPPER: string
    readonly PORT?: string
  }
}
