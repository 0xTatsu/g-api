package repo

import (
	"context"

	"github.com/go-pg/pg/v10"

	"github.com/0xTatsu/mvtn-api/model"
)

//go:generate mockery --name AccountRepo --case snake
type AccountRepo interface {
	GetByID(ctx context.Context, id int64) (*model.Account, error)
	GetByEmail(ctx context.Context, email string) (*model.Account, error)
	Update(ctx context.Context, account *model.Account) error
	Create(ctx context.Context, account *model.Account) (*model.Account, error)
}

type Account struct {
	db *pg.DB
}

func NewAccount(db *pg.DB) *Account {
	return &Account{db: db}
}

func (a *Account) GetByID(ctx context.Context, id int64) (*model.Account, error) {
	account := &model.Account{ID: id}
	err := a.db.ModelContext(ctx, account).Select()

	return account, err
}

func (a *Account) GetByEmail(ctx context.Context, email string) (*model.Account, error) {
	account := &model.Account{Email: email}
	err := a.db.ModelContext(ctx, account).Select()

	return account, err
}

func (a *Account) Update(ctx context.Context, account *model.Account) error {
	_, err := a.db.ModelContext(ctx, account).WherePK().Update()

	return err
}

func (a *Account) Create(ctx context.Context, account *model.Account) (*model.Account, error) {
	_, err := a.db.ModelContext(ctx, account).Insert()

	return account, err
}
