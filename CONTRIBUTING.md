# CONTRIBUTING

We would love to have contributions from each and every one of you in the community be it big or small and you are the ones who motivate us to do better than what we do today.

## Code Of Conduct

Please help us keep all our projects open and inclusive. Kindly follow our [Code of Conduct](CODE_OF_CONDUCT.md) to keep the ecosystem healthy and friendly for all.

## Quick Start

With Go and PostgreSQL installed, this is the whole setup:

```bash
make db-setup   # starts PostgreSQL, creates the auth schema, runs migrations
make test       # runs the test suite
```

`make db-setup` needs no Docker. It runs a PostgreSQL cluster that belongs to
this checkout: the data lives in `.postgres/`, no system-wide PostgreSQL is
touched, and `make db-down` stops it again. It finds the PostgreSQL binaries
itself on Debian/Ubuntu and Homebrew; set `PG_BIN` if yours live elsewhere.

If a PostgreSQL is already listening on port 5432, that one is used as-is and
nothing is started, however you happen to be running it.

To run the server:

```bash
cp example.env .env
make server
```

`make test` prepares the database for you. Set `DB_AUTO_SETUP=0` to stop it
doing so when you are managing the database yourself.

A full and up to date list of commands can be found in the project's `Makefile`
or by running `make help`.

## Setup and Tooling

Auth -- as the name implies -- is a user registration and authentication API developed in [Go](https://go.dev).

It connects to a [PostgreSQL](https://www.postgresql.org) database in order to store authentication data. Database migrations live in [`migrations/`](migrations), are embedded into the binary at build time, and are applied by the `auth migrate` subcommand -- no external migration tool is needed.

Therefore, to contribute to Auth you will need to install these tools.

### Install Tools

- Install [Go](https://go.dev). The required version is pinned by the `go`
  directive in [`go.mod`](go.mod); `make check-go-version` verifies that every
  place the version is pinned agrees with it.

- Install [PostgreSQL](https://www.postgresql.org)

```zsh
# Via Homebrew on macOS
brew install postgresql@15
```

You do not need to run it yourself; `make db-up` starts one for this checkout.
It only needs the binaries to be installed.

- Clone the Auth [repository](https://github.com/supabase/auth)

```zsh
git clone https://github.com/supabase/auth
```

### Install Auth

To begin installation, be sure to start from the root directory.

- `cd auth`

To complete installation, you will:

- Start PostgreSQL
- Create the DB Schema and Migrations
- Setup a local `.env` for environment variables
- Compile Auth
- Run the Auth binary executable

#### Installation Steps

1. Start PostgreSQL:

```zsh
make db-up
```

This runs a cluster belonging to this checkout, with its data in `.postgres/`.
If you already have a PostgreSQL listening on `5432` -- from
[homebrew on macOS](https://formulae.brew.sh/formula/postgresql), say -- that one
is used instead and nothing new is started.

3. Next compile the Auth binary:

When you fork a repository, GitHub does not automatically copy all the tags (tags are not included by default). To ensure the correct tag is set before building the binary, you need to fetch the tags from the upstream repository and push them to your fork. Follow these steps:

```zsh
# Fetch the tags from the upstream repository
git fetch upstream --tags

# Push the tags to your fork
git push origin --tags
```

Then build the binary by running:

```zsh
make build
```

4. To apply the database migrations, run:

```zsh
make migrate_test
```

You should see log messages that indicate that the Auth migrations were applied successfully:

```terminal
INFO[0000] Auth migrations applied successfully
DEBU[0000] after status
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210710035447"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210722035447"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210730183235"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20210909172000"]
[POP] 2021/12/15 10:44:36 sql - SELECT EXISTS (SELECT schema_migrations.* FROM schema_migrations AS schema_migrations WHERE version = $1) | ["20211122151130"]
Version          Name                         Status
20210710035447   alter_users                  Applied
20210722035447   adds_confirmed_at            Applied
20210730183235   add_email_change_confirmed   Applied
20210909172000   create_identities_table      Applied
20211122151130   create_user_id_idx           Applied
```

That lists each migration that was applied. Note: there may be more migrations than those listed.

4. Create a `.env` file in the root of the project and copy the following config in [example.env](example.env). Set the values to GOTRUE_SMS_TEST_OTP_VALID_UNTIL in the `.env` file.

5. In order to have Auth connect to your PostgreSQL database, it is important to set a connection string like:

```
DATABASE_URL="postgres://supabase_auth_admin:root@localhost:5432/postgres"
```

> Important: Auth requires a set of SMTP credentials to run, you can generate your own SMTP credentials via an SMTP provider such as AWS SES, SendGrid, MailChimp, SendInBlue or any other SMTP providers.

6. Then finally Start Auth
7. Verify that Auth is Available

### Starting Auth

Start Auth by running the executable:

```zsh
./auth
```

This command will re-run migrations and then indicate that Auth has started:

```zsh
INFO[0000] Auth API started on: localhost:9999
```

### How To Verify that Auth is Available

To test that your Auth is up and available, you can query the `health` endpoint at `http://localhost:9999/health`. You should see a response similar to:

```json
{
  "description": "Auth is a user registration and authentication API",
  "name": "Auth",
  "version": ""
}
```

To see the current settings, make a request to `http://localhost:9999/settings`. The
response reports which sign-in methods your configuration has enabled:

```json
{
  "external": {
    "email": true,
    "phone": false,
    "github": false,
    "google": false
  },
  "disable_signup": false,
  "mailer_autoconfirm": false,
  "phone_autoconfirm": false,
  "sms_provider": "",
  "saml_enabled": false,
  "saml_private_key_next_configured": false,
  "passkeys_enabled": false
}
```

The `external` object above is abridged -- it carries one key per supported
provider. See [`openapi.yaml`](openapi.yaml) for the full schema.

## How to Use Admin API Endpoints

To test the admin endpoints (or other api endpoints), you can invoke via HTTP requests. Using [Insomnia](https://insomnia.rest/products/insomnia) can help you issue these requests.

You will need to know the `GOTRUE_JWT_SECRET` configured in the `.env` settings.

Also, you must generate a JWT with the signature which has the `supabase_admin` role (or one that is specified in `GOTRUE_JWT_ADMIN_ROLES`).

For example:

```json
{
  "role": "supabase_admin"
}
```

You can sign this payload using the [JWT.io Debugger](https://jwt.io/#debugger-io) but make sure that `secret base64 encoded` is unchecked.

Then you can use this JWT as a Bearer token for admin requests.

### Create User (aka Sign Up a User)

To create a new user, `POST /admin/users` with the payload:

```json
{
  "email": "user@example.com",
  "password": "12345678"
}
```

#### Request

```
POST /admin/users HTTP/1.1
Host: localhost:9999
User-Agent: insomnia/2021.7.2
Content-Type: application/json
Authorization: Bearer <YOUR_SIGNED_JWT>
Accept: */*
Content-Length: 57
```

#### Response

And you should get a new user:

```json
{
  "id": "e78c512d-68e4-482b-901b-75003e89acae",
  "aud": "authenticated",
  "role": "authenticated",
  "email": "user@example.com",
  "phone": "",
  "app_metadata": {
    "provider": "email",
    "providers": ["email"]
  },
  "user_metadata": {},
  "identities": null,
  "created_at": "2021-12-15T12:40:03.507551-05:00",
  "updated_at": "2021-12-15T12:40:03.512067-05:00"
}
```

### List/Find Users

To create a new user, make a request to `GET /admin/users`.

#### Request

```
GET /admin/users HTTP/1.1
Host: localhost:9999
User-Agent: insomnia/2021.7.2
Authorization: Bearer <YOUR*SIGNED_JWT>
Accept: */\_
```

#### Response

The response from `/admin/users` should return all users:

```json
{
  "aud": "authenticated",
  "users": [
    {
      "id": "b7fd0253-6e16-4d4e-b61b-5943cb1b2102",
      "aud": "authenticated",
      "role": "authenticated",
      "email": "user+4@example.com",
      "phone": "",
      "app_metadata": {
        "provider": "email",
        "providers": ["email"]
      },
      "user_metadata": {},
      "identities": null,
      "created_at": "2021-12-15T12:43:58.12207-05:00",
      "updated_at": "2021-12-15T12:43:58.122073-05:00"
    },
    {
      "id": "d69ae847-99be-4642-868f-439c2cdd9af4",
      "aud": "authenticated",
      "role": "authenticated",
      "email": "user+3@example.com",
      "phone": "",
      "app_metadata": {
        "provider": "email",
        "providers": ["email"]
      },
      "user_metadata": {},
      "identities": null,
      "created_at": "2021-12-15T12:43:56.730209-05:00",
      "updated_at": "2021-12-15T12:43:56.730213-05:00"
    },
    {
      "id": "7282cf42-344e-4474-bdf6-d48e4968a2e4",
      "aud": "authenticated",
      "role": "authenticated",
      "email": "user+2@example.com",
      "phone": "",
      "app_metadata": {
        "provider": "email",
        "providers": ["email"]
      },
      "user_metadata": {},
      "identities": null,
      "created_at": "2021-12-15T12:43:54.867676-05:00",
      "updated_at": "2021-12-15T12:43:54.867679-05:00"
    },
    {
      "id": "e78c512d-68e4-482b-901b-75003e89acae",
      "aud": "authenticated",
      "role": "authenticated",
      "email": "user@example.com",
      "phone": "",
      "app_metadata": {
        "provider": "email",
        "providers": ["email"]
      },
      "user_metadata": {},
      "identities": null,
      "created_at": "2021-12-15T12:40:03.507551-05:00",
      "updated_at": "2021-12-15T12:40:03.507554-05:00"
    }
  ]
}
```

### Running Database Migrations

If you need to run any new migrations:

```zsh
make migrate_test
```

## Testing

Currently, we don't use a separate test database, so the same database created when installing Auth to run locally is used.

```sh
# Starts PostgreSQL, creates the auth schema and applies the migrations
$ make db-setup

# Executes the tests
$ make test
```

`make test` depends on `db-setup`, so in practice `make test` on a fresh
checkout is enough. `DB_AUTO_SETUP=0 make test` skips that preparation.

`make test` is the fast feedback loop: no coverage profiling and no `-v`.
`make test-coverage` is the fuller run CI uses -- it writes `coverage.out` and
enforces the per-package coverage gate in `hack/coverage.sh`.

Useful companions while working on migrations:

```sh
$ make db-reset    # drop everything and rebuild from the migrations
$ make db-psql     # psql shell on the development database
$ make db-status   # is PostgreSQL running?
$ make db-down     # stop the PostgreSQL that db-up started
```

### Regenerating schema.sql

`schema.sql` is a committed dump of the `auth` schema. It is not used to build
the database -- the migrations are the source of truth -- but it makes schema
changes visible in review. After adding a migration, regenerate it:

```sh
$ make db-schema
```

Because the dump comes from whichever PostgreSQL you have installed, a
different major version can produce a different file. If the diff looks larger
than the migration you added, check your PostgreSQL version before committing.

### Customizing the PostgreSQL Port

The `db-*` targets take `PGPORT`:

```sh
$ PGPORT=7432 make db-setup
```

The test suite is a separate matter. It reads `hack/test.env`, and `confload`
loads that file with `godotenv.Overload`, so values in the file override the
environment. To move the tests off 5432 you also have to edit the port in
`hack/test.env`:

```
DATABASE_URL="postgres://supabase_auth_admin:root@localhost:7432/postgres"
```

> Note: this is not recommended, and please do not check the change in.

## Helpful Database Commands

```zsh
# psql shell on the development database
make db-psql

# Stop the PostgreSQL that db-up started
make db-down

# Drop the auth schema and its roles, then rebuild from the migrations
make db-reset
```

To throw the cluster away entirely, stop it and delete its data directory:

```zsh
make db-down && rm -rf .postgres
```

## Updating Package Dependencies

- `make deps`
- `go mod tidy` if necessary

## Submitting Pull Requests

We actively welcome your pull requests.

- Fork the repo and create your branch from `master`.
- If you've added code that should be tested, add tests.
- If you've changed APIs, update the documentation.
- Ensure the test suite passes.
- Make sure your code lints.

### Checklist for Submitting Pull Requests

- Is there a corresponding issue created for it? If so, please include it in the PR description so we can track / refer to it.
- Does your PR follow the [semantic-release commit guidelines](https://github.com/angular/angular.js/blob/master/DEVELOPERS.md#-git-commit-guidelines)?
- If the PR is a `feat`, an [RFC](https://github.com/supabase/rfcs) or a detailed description of the design implementation is required. The former (RFC) is preferred before starting on the PR.
- Are the existing tests passing?
- Have you written some tests for your PR?

## Guidelines for Implementing Additional OAuth Providers

> ⚠️ We won't be accepting any additional oauth / sms provider contributions for now because we intend to support these through webhooks or a generic provider in the future.

Please ensure that an end-to-end test is done for the OAuth provider implemented.

An end-to-end test includes:

- Creating an application on the oauth provider site
- Generating your own client_id and secret
- Testing that `http://localhost:9999/authorize?provider=MY_COOL_NEW_PROVIDER` redirects you to the provider sign-in page
- The callback is handled properly
- Gotrue redirects to the `SITE_URL` or one of the URI's specified in the `URI_ALLOW_LIST` with the access_token, provider_token, expiry and refresh_token as query fragments

### Writing tests for the new OAuth provider implemented

Since implementing an additional OAuth provider consists of making api calls to an external api, we set up a mock server to attempt to mock the responses expected from the OAuth provider.

## License

By contributing to Auth, you agree that your contributions will be licensed
under its [MIT license](LICENSE).
