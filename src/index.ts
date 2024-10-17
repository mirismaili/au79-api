import {Elysia} from 'elysia'

const app = new Elysia().get('/', () => 'Hello Elysia').listen(Bun.env.PORT ?? 7979)

console.info(`🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`)
