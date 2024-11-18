// noinspection JSUnusedGlobalSymbols

import {init as initCuid} from '@paralleldrive/cuid2'
import {relations} from 'drizzle-orm'
import {
  bigint,
  boolean,
  char,
  customType,
  index,
  integer,
  pgTable,
  serial,
  text,
  timestamp,
  uniqueIndex,
  varchar,
} from 'drizzle-orm/pg-core'

const createId = initCuid({length: 24})

const bytea = customType<{data: Uint8Array; driverData: Buffer; notNull: false; default: false}>({
  dataType: () => 'bytea',
  toDriver: (value) => Buffer.from(value),
})

export const usersTable = pgTable('user', {
  id: char({length: 24})
    .$defaultFn(() => createId())
    .primaryKey(),
  username: varchar({length: 127}).notNull().unique(),
  passwordHash: varchar('password_hash', {}),
  phone: bigint({mode: 'number'}).notNull().unique(),
  email: varchar({length: 255}).notNull().unique(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  lastModified: timestamp('last_modified', {mode: 'date'}).defaultNow().notNull(),
})

/** @see https://simplewebauthn.dev/docs/packages/server#additional-data-structures */
export const passkeysTable = pgTable(
  'passkey',
  {
    id: text().primaryKey(),
    publicKey: bytea('public_key').notNull(),
    userId: char('user_id', {length: 24}).references(() => usersTable.id),
    webauthnUserId: text('webauthn_user_id').notNull(), // A UNIQUE constraint on `webAuthnUserId + userId` also achieves maximum user privacy
    counter: bigint({mode: 'number'}).notNull(),
    deviceType: varchar('device_type', {length: 32}).notNull(), // Longest possible value is currently 12 characters // Ex: 'singleDevice' | 'multiDevice'
    backedUp: boolean('backed_up').notNull(),
    transports: varchar({length: 255}), // Store string array as a CSV string // Ex: ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'].join(',')
  },
  (table) => [
    {
      webauthnUserIdIdx: index().on(table.webauthnUserId),
      webauthnUserIdAndUserIdIdx: uniqueIndex().on(table.webauthnUserId, table.userId),
    },
  ],
)

export const usersRelations = relations(usersTable, ({many}) => ({passkeys: many(passkeysTable)}))
export const passkeyRelations = relations(passkeysTable, ({one}) => ({
  user: one(usersTable, {fields: [passkeysTable.userId], references: [usersTable.id]}),
}))
