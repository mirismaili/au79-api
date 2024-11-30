CREATE TABLE IF NOT EXISTS "passkey" (
	"id" text PRIMARY KEY NOT NULL,
	"public_key" "bytea" NOT NULL,
	"user_id" char(24),
	"webauthn_user_id" text NOT NULL,
	"counter" bigint NOT NULL,
	"device_type" varchar(32) NOT NULL,
	"backed_up" boolean NOT NULL,
	"transports" varchar(255) DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "user" (
	"id" char(24) PRIMARY KEY NOT NULL,
	"username" varchar(127) NOT NULL,
	"password_hash" varchar,
	"phone" bigint,
	"email" varchar(255),
	"created_at" timestamp DEFAULT now() NOT NULL,
	"last_modified" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "user_username_unique" UNIQUE("username"),
	CONSTRAINT "username_min_length" CHECK (length("user"."username") >= 5)
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "passkey" ADD CONSTRAINT "passkey_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "passkey_webauthn_user_id_index" ON "passkey" USING btree ("webauthn_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "passkey_webauthn_user_id_user_id_index" ON "passkey" USING btree ("webauthn_user_id","user_id");