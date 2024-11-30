import * as drizzleSchema from '@/db/schema'
import {cors} from '@elysiajs/cors'
import {swagger} from '@elysiajs/swagger'
import {init as initCuid} from '@paralleldrive/cuid2'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import type {Base64URLString} from '@simplewebauthn/types'
import {eq} from 'drizzle-orm'
import {drizzle} from 'drizzle-orm/node-postgres'
import {Elysia, t} from 'elysia'
import {createClient} from 'redis'
import {EntityId, Repository, Schema} from 'redis-om'

const createId = initCuid({length: 24})

const redisClient = createClient({url: process.env.REDIS_URL})
redisClient.on('error', console.error)
await redisClient.connect()

type RegistrationSession = {challenge: string; userId: string; webauthnUserId: string}
const registrationSessionRepository = new Repository(
  new Schema<RegistrationSession>('registrationSession', {
    challenge: {type: 'string'},
    userId: {type: 'string'},
    webauthnUserId: {type: 'string'},
  }),
  redisClient,
)

type AuthenticationSession = {challenge: string; userId: string}
const authenticationSessionRepository = new Repository(
  new Schema<AuthenticationSession>('authenticationSession', {
    challenge: {type: 'string'},
    userId: {type: 'string'},
  }),
  redisClient,
)

const {passkeysTable, usersTable} = drizzleSchema
const db = drizzle(process.env.DATABASE_URL, {schema: drizzleSchema})

/** @see https://github.com/sinclairzx81/typebox#unsafe-types */
const tStringEnum = <T extends string[]>(values: readonly [...T]) => t.Unsafe<T[number]>({...t.String(), enum: values})

const tBase64URLString = t.Unsafe<Base64URLString>(t.String({contentEncoding: 'base64'}))

const AUTHENTICATION_TIMEOUT = 60

const app = new Elysia()
  .use(swagger({path: 'open-api'}))
  .use(cors({origin: process.env.CORS_ORIGIN, methods: ['GET', 'POST'], credentials: true}))
  .group('/auth', (app) =>
    app
      .get(
        '/register',
        async ({query: {username, phone, email}, cookie: {session}}) => {
          const [newUser] = await db
            .insert(usersTable)
            .values({username, phone: phone ? +phone : undefined, email})
            .onConflictDoNothing()
            .returning()

          const user = newUser
            ? {...newUser, passkeys: []}
            : (await db.query.usersTable.findFirst({where: eq(usersTable.username, username), with: {passkeys: true}}))!

          const options = await generateRegistrationOptions({
            rpName: 'Au79 API',
            rpID: process.env.RPID,
            userName: username,
            timeout: AUTHENTICATION_TIMEOUT * 1000,
            attestationType: 'none',
            /**
             * Passing in a user's list of already-registered credential IDs here prevents users from
             * registering the same authenticator multiple times. The authenticator will simply throw an
             * error in the browser if it's asked to perform registration when it recognizes one of the
             * credential ID's.
             */
            excludeCredentials: user.passkeys.map((passkey) => ({
              id: passkey.id,
              transports: passkey.transports,
            })),
            authenticatorSelection: {
              residentKey: 'discouraged',
              // Wondering why user verification isn't required? See: https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
              userVerification: 'preferred',
            },
            // Support the two most common algorithms: ES256, and RS256. See: https://chromium.googlesource.com/chromium/src/+/main/content/browser/webauth/pub_key_cred_params.md
            supportedAlgorithmIDs: [ES256, RS256],
          })

          const sessionId = createId()

          registrationSessionRepository
            .save(sessionId, {
              challenge: options.challenge,
              userId: user.id,
              webauthnUserId: options.user.id,
            })
            .then(async (registrationSession) => {
              const entityId = (registrationSession as RegistrationSession & {[EntityId]: string})[EntityId]
              console.assert(entityId === sessionId)
              await registrationSessionRepository.expire(entityId, AUTHENTICATION_TIMEOUT + 60)
            })
            .catch(console.error)

          session.set({
            sameSite: 'none',
            secure: true,
            httpOnly: true,
            partitioned: true,
          })
          session.value = sessionId
          return options
        },
        {
          query: t.Object({
            username: t.String({minLength: 0}),
            phone: t.Optional(t.String({minLength: 6, pattern: '^\\d*$'})),
            email: t.Optional(t.String({format: 'email'})),
          }),
          cookie: t.Cookie({session: t.Optional(t.String())}),
        },
      )
      .post(
        '/register',
        async ({body, cookie: {session}, error}) => {
          const {
            challenge: expectedChallenge,
            userId,
            webauthnUserId,
          } = await registrationSessionRepository.fetch(session.value)

          session.set({sameSite: 'none', secure: true, httpOnly: true, partitioned: true, expires: new Date(0)}) // Remove session

          if (!expectedChallenge) return error('Unauthorized', 'Session not found. It maybe expired.') // https://stackoverflow.com/questions/1653493/what-http-status-code-is-supposed-to-be-used-to-tell-the-client-the-session-has

          const {verification, err} = await verifyRegistrationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: process.env.CORS_ORIGIN,
            expectedRPID: process.env.RPID,
            requireUserVerification: false, // TODO
          })
            .then((verification) => ({verification, err: undefined}))
            .catch((e) => ({verification: undefined, err: e as Error}))
          if (err) {
            console.error(err)
            return error('Bad Request', err.message)
          }

          const {verified, registrationInfo} = verification

          if (!verified) return error('Unauthorized', 'Verification failed. Try again.')

          if (registrationInfo) {
            const user = (await db.query.usersTable.findFirst({
              where: eq(usersTable.id, userId),
              with: {passkeys: true},
            }))!

            const {credential, credentialBackedUp, credentialDeviceType} = registrationInfo

            await db
              .insert(passkeysTable)
              .values({
                ...credential,
                transports: body.response.transports,
                userId: user.id,
                webauthnUserId,
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
          cookie: t.Cookie({session: t.String()}),
        },
      )
      .get(
        '/authenticate',
        async ({query: {username}, cookie: {session}, error}) => {
          const user = await db.query.usersTable.findFirst({
            where: eq(usersTable.username, username),
            with: {passkeys: true},
          })

          if (!user?.passkeys.length) return error('Not Found', 'User not found')

          const options = await generateAuthenticationOptions({
            timeout: AUTHENTICATION_TIMEOUT,
            allowCredentials: user.passkeys.map((passkey) => ({
              id: passkey.id,
              type: 'public-key',
              transports: passkey.transports,
            })),
            // Wondering why user verification isn't required? See: https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
            userVerification: 'preferred',
            rpID: process.env.RPID,
          })

          const sessionId = createId()

          authenticationSessionRepository
            .save(sessionId, {
              challenge: options.challenge,
              userId: user.id,
            })
            .then(async (registrationSession) => {
              const entityId = (registrationSession as RegistrationSession & {[EntityId]: string})[EntityId]
              console.assert(entityId === sessionId)
              await authenticationSessionRepository.expire(entityId, AUTHENTICATION_TIMEOUT + 60)
            })
            .catch(console.error)

          session.set({
            sameSite: 'none',
            secure: true,
            httpOnly: true,
            partitioned: true,
          })
          session.value = sessionId
          return options
        },
        {
          query: t.Object({
            username: t.String({minLength: 0}),
          }),
          cookie: t.Cookie({session: t.Optional(t.String())}),
        },
      )
      .post(
        '/authenticate',
        async ({body, cookie: {session}, error}) => {
          const {challenge: expectedChallenge, userId} = await authenticationSessionRepository.fetch(session.value)

          session.set({sameSite: 'none', secure: true, httpOnly: true, partitioned: true, expires: new Date(0)}) // Remove session

          if (!expectedChallenge) return error('Unauthorized', 'Session not found. It maybe expired.') // https://stackoverflow.com/questions/1653493/what-http-status-code-is-supposed-to-be-used-to-tell-the-client-the-session-has

          const user = (await db.query.usersTable.findFirst({
            where: eq(usersTable.id, userId),
            with: {passkeys: true},
          }))!

          const dbCredential = user.passkeys.find(({id}) => id === body.id)

          if (!dbCredential) return error('Bad Request', 'Authenticator is not registered with this site')

          const {verification, err} = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge,
            expectedOrigin: process.env.CORS_ORIGIN,
            expectedRPID: process.env.RPID,
            credential: {
              ...dbCredential,
              transports: dbCredential.transports,
            },
            requireUserVerification: false,
          })
            .then((verification) => ({verification, err: undefined}))
            .catch((e) => ({verification: undefined, err: e as Error}))
          if (err) {
            console.error(err)
            return error('Bad Request', err.message)
          }

          const {verified, authenticationInfo} = verification

          if (!verified) return error('Unauthorized', 'Verification failed. Try again.')

          // Update the credential's counter in the DB to the newest count in the authentication
          db.update(passkeysTable).set({counter: authenticationInfo.newCounter}).catch(console.error)

          return 'Verified' as const
        },
        {
          body: t.Object({
            id: tBase64URLString,
            rawId: tBase64URLString,
            response: t.Object({
              clientDataJSON: tBase64URLString,
              authenticatorData: tBase64URLString,
              signature: tBase64URLString,
              userHandle: t.Optional(tBase64URLString),
            }),
            authenticatorAttachment: tStringEnum(['cross-platform', 'platform'] as const),
            clientExtensionResults: t.Object({
              appid: t.Optional(t.Boolean()),
              credProps: t.Optional(t.Object({rk: t.Optional(t.Boolean())})),
              hmacCreateSecret: t.Optional(t.Boolean()),
            }),
            type: t.Literal<PublicKeyCredentialType>('public-key'),
          }),
          cookie: t.Cookie({session: t.String()}),
        },
      ),
  )
  .listen(process.env.PORT ?? 7979)

console.info(`🦊 Elysia is running at ${app.server!.url}`)

const ES256 = -7
const RS256 = -257
