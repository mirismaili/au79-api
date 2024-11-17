import * as drizzleSchema from '@/db/schema'
import {cors} from '@elysiajs/cors'
import {swagger} from '@elysiajs/swagger'
import {generateRegistrationOptions, verifyRegistrationResponse} from '@simplewebauthn/server'
import type {AuthenticatorTransportFuture, Base64URLString, WebAuthnCredential} from '@simplewebauthn/types'
import {eq} from 'drizzle-orm'
import {drizzle} from 'drizzle-orm/node-postgres'
import {createInsertSchema} from 'drizzle-typebox'
import {Elysia, t} from 'elysia'

const {passkeysTable, usersTable} = drizzleSchema
const db = drizzle(Bun.env.DATABASE_URL!, {schema: drizzleSchema})

const insertUserSchema = createInsertSchema(usersTable, {
  email: t.String({format: 'email'}),
})
const usernameSchema = {...t.Index(insertUserSchema, ['username']), minLength: 5}

const tSession = t.Object({
  challenge: t.String(),
  username: t.String(),
  webauthnUserId: t.String(),
  userId: t.Optional(t.String()),
})

/** @see https://github.com/sinclairzx81/typebox#unsafe-types */
const tStringEnum = <T extends string[]>(values: readonly [...T]) => t.Unsafe<T[number]>({...t.String(), enum: values})

const tBase64URLString = t.Unsafe<Base64URLString>(t.String({contentEncoding: 'base64'}))

const app = new Elysia()
  .use(swagger({path: 'open-api'}))
  .use(cors({origin: 'http://localhost:7900', methods: ['GET', 'POST'], credentials: true}))
  .group('/auth', (app) =>
    app
      .get(
        '/register',
        async ({query: {username}, cookie: {session}}) => {
          const user = await db.query.usersTable.findFirst({
            where: eq(usersTable.username, username),
            with: {passkeys: true},
          })

          const options = await generateRegistrationOptions({
            rpName: 'Au79 API',
            rpID: 'localhost',
            userName: username,
            timeout: 60_000,
            attestationType: 'none',
            /**
             * Passing in a user's list of already-registered credential IDs here prevents users from
             * registering the same authenticator multiple times. The authenticator will simply throw an
             * error in the browser if it's asked to perform registration when it recognizes one of the
             * credential ID's.
             */
            excludeCredentials: user?.passkeys.map((passkey) => ({
              id: passkey.id,
              transports: passkey.transports?.split(',') as AuthenticatorTransportFuture[],
            })),
            authenticatorSelection: {
              residentKey: 'discouraged',
              /**
               * Wondering why user verification isn't required? See here:
               *
               * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
               */
              userVerification: 'preferred',
            },
            /**
             * Support the two most common algorithms: ES256, and RS256
             * @see https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md
             */
            supportedAlgorithmIDs: [ES256, RS256],
          })

          /**
           * The server needs to temporarily remember this value for verification, so don't lose it until
           * after you verify the registration response.
           */
          session.set({
            sameSite: 'none',
            secure: true,
            httpOnly: true,
            partitioned: true,
            value: {challenge: options.challenge, username, webauthnUserId: options.user.id},
          })

          return options
        },
        {
          query: t.Object({username: usernameSchema}),
          cookie: t.Cookie(
            {
              session: t.Optional(t.Partial(tSession)),
            },
            // {
            //   secrets: 'Fischl von Luftschloss Narfidort', // TODO: process.env.COOKIES_SECRET
            //   sign: ['session'],
            // },
          ),
        },
      )
      .post(
        '/register',
        async ({body, cookie: {session}, error}) => {
          console.log('body', body)
          const sessionValue = session.value
          session.remove()
          const expectedChallenge = sessionValue.challenge

          const {verification, err} = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: 'http://localhost:7900',
            expectedRPID: 'localhost',
            requireUserVerification: false, // TODO
          })
            .then((verification) => ({verification, err: undefined}))
            .catch((e) => ({verification: undefined, err: e as Error}))
          console.log('verification', verification)
          if (err) {
            console.error(err)
            return error(400, err.message)
          }

          const {verified, registrationInfo} = verification

          if (!verified) return error(401, 'Verification failed. Try again.')

          console.log('sessionValue', sessionValue)
          if (registrationInfo) {
            let [user] = await db
              .insert(usersTable)
              .values({username: sessionValue.username, email: '', phone: 98})
              .onConflictDoNothing()
              .returning()
            user ??= (await db.query.usersTable.findFirst({
              where: eq(usersTable.username, sessionValue.username),
              with: {passkeys: true},
            }))!

            const {credential, credentialBackedUp, credentialDeviceType} = registrationInfo

            await db
              .insert(passkeysTable)
              .values({
                ...credential,
                transports: body.response.transports?.join(','),
                userId: user.id,
                webauthnUserId: sessionValue.webauthnUserId,
                backedUp: credentialBackedUp,
                deviceType: credentialDeviceType,
              })
              .onConflictDoNothing()
          }

          return 'Verified' as const
        },
        {
          body: t.Object({
            id: tBase64URLString,
            rawId: tBase64URLString,
            response: t.Object({
              clientDataJSON: tBase64URLString,
              attestationObject: tBase64URLString,
              authenticatorData: t.Optional(tBase64URLString),
              transports: t.Optional(
                t.Array(tStringEnum(['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'] as const)),
              ),
              publicKeyAlgorithm: t.Optional(t.Number()),
              publicKey: t.Optional(tBase64URLString),
            }),
            authenticatorAttachment: tStringEnum(['cross-platform', 'platform'] as const),
            clientExtensionResults: t.Object({
              appid: t.Optional(t.Boolean()),
              credProps: t.Optional(t.Object({rk: t.Optional(t.Boolean())})),
              hmacCreateSecret: t.Optional(t.Boolean()),
            }),
            type: t.Literal<PublicKeyCredentialType>('public-key'),
          }),
          cookie: t.Cookie({session: tSession}),
        },
      ),
  )
  .listen(Bun.env.PORT ?? 7979)

console.info(`🦊 Elysia is running at ${app.server!.url}`)

const ES256 = -7
const RS256 = -257
