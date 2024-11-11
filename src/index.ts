import {usersTable} from '@/db/schema'
import {cors} from '@elysiajs/cors'
import type {VerifiedRegistrationResponse} from '@simplewebauthn/server'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server'
import type {AuthenticatorTransportFuture, RegistrationResponseJSON, WebAuthnCredential} from '@simplewebauthn/types'
import {drizzle} from 'drizzle-orm/node-postgres'
import {createInsertSchema} from 'drizzle-typebox'
import {Elysia, t} from 'elysia'

const db = drizzle(Bun.env.DATABASE_URL!)

const _createUser = createInsertSchema(usersTable, {
  email: t.String({format: 'email'}),
})
const createUser = t.Intersect([
  t.Omit(_createUser, ['id', 'createdAt', 'passwordHash']),
  t.Object({password: t.String()}),
])

const credentials: {id: string; transports?: AuthenticatorTransportFuture[]}[] = []

const app = new Elysia()
  .use(cors({origin: 'http://localhost:7900', methods: ['GET', 'POST'], credentials: true}))
  .group('/auth', (app) =>
    app
      .get(
        '/register',
        async ({cookie: {session}}) => {
          const options = await generateRegistrationOptions({
            rpName: 'Au79 API',
            rpID: 'localhost',
            userName: 'username',
            timeout: 60000,
            attestationType: 'none',
            /**
             * Passing in a user's list of already-registered credential IDs here prevents users from
             * registering the same authenticator multiple times. The authenticator will simply throw an
             * error in the browser if it's asked to perform registration when it recognizes one of the
             * credential ID's.
             */
            excludeCredentials: credentials.map((cred) => ({
              id: cred.id,
              type: 'public-key',
              transports: cred.transports,
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
          session.value = {currentChallenge: options.challenge}

          return options
        },
        {
          cookie: t.Cookie({
            session: t.Optional(t.Object({currentChallenge: t.String()})),
          }),
        },
      )
      .post(
        '/register',
        async ({body, cookie: {session}, error}) => {
          const expectedChallenge = session.value.currentChallenge

          const {verification, err} = await verifyRegistrationResponse({
            response: body as RegistrationResponseJSON,
            expectedChallenge,
            expectedOrigin: 'http://localhost:7900',
            expectedRPID: 'localhost',
            requireUserVerification: false, // TODO
          })
            .then((verification) => ({verification, err: undefined}))
            .catch((e) => ({verification: undefined, err: e as Error}))

          if (err) {
            console.error(err)
            return error(400, err.message)
          }

          const {verified, registrationInfo} = verification

          if (verified && registrationInfo) {
            const {credential} = registrationInfo

            const existingCredential = credentials.find((cred) => cred.id === credential.id)

            if (!existingCredential) {
              /**
               * Add the returned credential to the user's list of credentials
               */
              const newCredential: WebAuthnCredential = {
                id: credential.id,
                publicKey: credential.publicKey,
                counter: credential.counter,
                transports: (body as RegistrationResponseJSON).response.transports,
              }
              credentials.push(newCredential)
            }
          }

          session.remove()

          return {verified}
        },
        {
          cookie: t.Cookie({
            session: t.Object({currentChallenge: t.String()}),
          }),
        },
      ),
  )
  .listen(Bun.env.PORT ?? 7979)

console.info(`🦊 Elysia is running at ${app.server!.url}`)

const ES256 = -7
const RS256 = -257
