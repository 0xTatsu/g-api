# A starter kit for Go API development
[![codecov](https://codecov.io/gh/0xTatsu/g-api/branch/main/graph/badge.svg?token=77ILCE8419)](https://codecov.io/gh/0xTatsu/g-api)

## Motivation
The best way to be an expert in something is to start working on it ... from scratch.

## Architecture: SOLID principles 
- This repo is structured in a way that there is clear separation of 
functionalities for your controller, business logic and database operations. 
- Dependencies are injected from outside to inside. 
- Swapping a router or database library to a different one becomes much easier. 

This is the idea behind [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html). 
This way, it is easy to switch whichever library to another of your choice.

## TODO
- [x] Framework-less and net/http compatible handler
- [x] Router/Mux with [Chi Router](https://github.com/go-chi/chi)
- [x] Environment [Viper](https://github.com/spf13/viper)
- [x] Logger [Zap](https://github.com/uber-go/zap)
- [x] JWT Authentication
- [ ] Google/Facebook/Apple Authentication
- [ ] Scans and auto-generate [Swagger](https://github.com/swaggo/swag) docs using a declarative comments format

# TO READ 
- https://medium.com/@benbjohnson/structuring-applications-in-go-3b04be4ff091

# Good Reads
- https://scene-si.org/2018/03/12/handling-http-requests-with-go-chi/
- https://scene-si.org/2018/05/08/protecting-api-access-with-jwt/
- JWT Flow: https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/
- https://blog.questionable.services/article/http-handler-error-handling-revisited/
- https://use-the-index-luke.com/no-offset