package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgconn"
	"gorm.io/gorm"

	"github.com/0xTatsu/g-api/model"
)

//go:generate mockery --name UserRepo --case snake
type UserRepo interface {
	GetByID(ctx context.Context, id uint) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	Create(ctx context.Context, user *model.User) (*model.User, error)
}

type User struct {
	db *gorm.DB
}

func NewUser(db *gorm.DB) *User {
	return &User{db: db}
}

func (a *User) GetByID(ctx context.Context, id uint) (*model.User, error) {
	user := &model.User{ID: id}
	err := a.db.WithContext(ctx).Where(user).First(user).Error

	return user, err
}

func (a *User) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{Email: email}
	err := a.db.WithContext(ctx).Where(user).First(user).Error

	return user, err
}

func (a *User) Update(ctx context.Context, user *model.User) error {
	err := a.db.WithContext(ctx).Model(&user).Updates(user).Error

	return err
}

func (a *User) Create(ctx context.Context, user *model.User) (*model.User, error) {
	err := a.db.WithContext(ctx).Create(&user).Error

	var pgErr *pgconn.PgError
	if ok := errors.As(err, &pgErr); ok && pgErr.Code == "23505" {
		return nil, fmt.Errorf("%w, %s", ErrDuplicateKey, err)
	}

	return user, err
}
