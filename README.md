# Go RESTful API Starter Kit

# Migration
- https://github.com/golang-migrate/migrate/blob/master/database/postgres/TUTORIAL.md
```
# Install
brew install golang-migrate

# View options
migrate -help

# Create migration files
migrate create -ext sql -dir db/migration account

# Run migration
migrate -database YOUR_DATABASE_URL -path PATH_TO_YOUR_MIGRATIONS up/down
migrate -path db/migration -database "postgresql://user:pass@localhost:5432/simple_bank?sslmode=disable" -verbose up

```

# Good Reads
- https://scene-si.org/2018/03/12/handling-http-requests-with-go-chi/
- https://scene-si.org/2018/05/08/protecting-api-access-with-jwt/
- JWT Flow: https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/