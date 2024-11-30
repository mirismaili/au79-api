// noinspection JSUnusedGlobalSymbols

import {init as initCuid} from '@paralleldrive/cuid2'
import type {AuthenticatorTransportFuture} from '@simplewebauthn/types'
import {relations, sql} from 'drizzle-orm'
import {
  bigint,
  boolean,
  char,
  check,
  customType,
  index,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  varchar,
} from 'drizzle-orm/pg-core'

const createId = initCuid({length: 24})

const uint8 = customType<{data: Uint8Array; driverData: string; notNull: true; default: false}>({
  dataType: () => 'bytea',
  toDriver: (value) => `\\x${Buffer.from(value).toString('hex')}`,
  fromDriver: (value) => Uint8Array.from(Buffer.from(value.slice(2 /* Remove '\x' prefix */), 'hex')),
})

const typedCsv = <T>() =>
  customType<{
    data: T[]
    driverData: string
    notNull: true
    default: false
    config: {length: number}
  }>({
    dataType: (config) => (config ? `varchar(${config.length})` : 'varchar'),
    toDriver: (value) => value.join(','),
    fromDriver: (value) => value.split(',') as T[],
  })

export const usersTable = pgTable(
  'user',
  {
    id: char({length: 24})
      .$defaultFn(() => createId())
      .primaryKey(),
    username: varchar({length: 127}).unique().notNull(),
    passwordHash: varchar('password_hash', {}),
    phone: bigint({mode: 'number'}),
    email: varchar({length: 255}),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    lastModified: timestamp('last_modified', {mode: 'date'}).defaultNow().notNull(),
  },
  (table) => [check('username_min_length', sql`length(${table.username}) >= 5`)],
)

/** @see https://simplewebauthn.dev/docs/packages/server#additional-data-structures */
export const passkeysTable = pgTable(
  'passkey',
  {
    id: text().primaryKey(),
    publicKey: uint8('public_key').notNull(),
    userId: char('user_id', {length: 24}).references(() => usersTable.id),
    webauthnUserId: text('webauthn_user_id').notNull(), // A UNIQUE constraint on `webAuthnUserId + userId` also achieves maximum user privacy
    counter: bigint({mode: 'number'}).notNull(),
    deviceType: varchar('device_type', {length: 32}).notNull(), // Longest possible value is currently 12 characters // Ex: 'singleDevice' | 'multiDevice'
    backedUp: boolean('backed_up').notNull(),
    transports: typedCsv<AuthenticatorTransportFuture>()({length: 255}) // Store string array as a CSV string // Ex: ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'].join(',')
      .notNull()
      .default(sql`''`),
  },
  (table) => [index().on(table.webauthnUserId), uniqueIndex().on(table.webauthnUserId, table.userId)],
)

export const usersRelations = relations(usersTable, ({many}) => ({passkeys: many(passkeysTable)}))
export const passkeyRelations = relations(passkeysTable, ({one}) => ({
  user: one(usersTable, {fields: [passkeysTable.userId], references: [usersTable.id]}),
}))
