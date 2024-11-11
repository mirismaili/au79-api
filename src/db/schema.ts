import {createId} from '@paralleldrive/cuid2'
import {integer, pgTable, serial, timestamp, varchar} from 'drizzle-orm/pg-core'

export const usersTable = pgTable('user', {
  id: varchar('id')
    .$defaultFn(() => createId())
    .primaryKey(),
  username: varchar('username').notNull().unique(),
  passwordHash: varchar('password_hash', {}).notNull(),
  email: varchar('email').notNull().unique(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
})
