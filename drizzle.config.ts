import {defineConfig} from 'drizzle-kit'

// noinspection JSUnusedGlobalSymbols
export default defineConfig({
  out: './drizzle',
  schema: './src/db/schema.ts',
  dialect: 'postgresql',
  dbCredentials: {url: process.env.DATABASE_URL},
})
