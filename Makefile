migrate-up:
	migrate -path db/migration -database "postgresql://mvtnghia:@localhost:5432/mvt?sslmode=disable" -verbose up

migrate-down:
	migrate -path db/migration -database "postgresql://root:secret@localhost:5432/mvt?sslmode=disable" -verbose down

.PHONY: migrate-up migrate-down