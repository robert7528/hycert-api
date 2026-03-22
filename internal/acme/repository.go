package acme

import (
	"gorm.io/gorm"
)

// Repository handles ACME account and order persistence.
type Repository struct{}

// NewRepository creates a new ACME Repository.
func NewRepository() *Repository {
	return &Repository{}
}

// ── ACME Account ────────────────────────────────────────────────────────────

func (r *Repository) CreateAccount(db *gorm.DB, acct *AcmeAccount) error {
	return db.Create(acct).Error
}

func (r *Repository) FindAccountByID(db *gorm.DB, id uint) (*AcmeAccount, error) {
	var acct AcmeAccount
	if err := db.First(&acct, id).Error; err != nil {
		return nil, err
	}
	return &acct, nil
}

func (r *Repository) FindAllAccounts(db *gorm.DB, q *AccountListQuery) ([]AcmeAccount, int64, error) {
	tx := db.Model(&AcmeAccount{})

	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	tx = tx.Order("created_at DESC").Offset((page - 1) * pageSize).Limit(pageSize)

	var accounts []AcmeAccount
	if err := tx.Find(&accounts).Error; err != nil {
		return nil, 0, err
	}
	return accounts, total, nil
}

func (r *Repository) UpdateAccount(db *gorm.DB, acct *AcmeAccount) error {
	return db.Save(acct).Error
}

func (r *Repository) DeleteAccount(db *gorm.DB, id uint) error {
	return db.Delete(&AcmeAccount{}, id).Error
}

// ── ACME Order ──────────────────────────────────────────────────────────────

func (r *Repository) CreateOrder(db *gorm.DB, order *AcmeOrder) error {
	return db.Create(order).Error
}

func (r *Repository) FindOrderByID(db *gorm.DB, id uint) (*AcmeOrder, error) {
	var order AcmeOrder
	if err := db.First(&order, id).Error; err != nil {
		return nil, err
	}
	return &order, nil
}

func (r *Repository) FindAllOrders(db *gorm.DB, q *OrderListQuery) ([]AcmeOrder, int64, error) {
	tx := db.Model(&AcmeOrder{})

	if q.AccountID > 0 {
		tx = tx.Where("account_id = ?", q.AccountID)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	tx = tx.Order("created_at DESC").Offset((page - 1) * pageSize).Limit(pageSize)

	var orders []AcmeOrder
	if err := tx.Find(&orders).Error; err != nil {
		return nil, 0, err
	}
	return orders, total, nil
}

func (r *Repository) UpdateOrder(db *gorm.DB, order *AcmeOrder) error {
	return db.Save(order).Error
}

func (r *Repository) DeleteOrder(db *gorm.DB, id uint) error {
	return db.Delete(&AcmeOrder{}, id).Error
}

// FindRenewableOrders finds orders due for renewal across all active auto-renew orders.
// An order is renewable when its associated certificate expires within renew_before_days.
func (r *Repository) FindRenewableOrders(db *gorm.DB) ([]AcmeOrder, error) {
	var orders []AcmeOrder
	err := db.Raw(`
		SELECT o.* FROM hycert_acme_orders o
		JOIN hycert_certificates c ON c.id = o.certificate_id AND c.deleted_at IS NULL
		WHERE o.auto_renew = true
		  AND o.status = 'valid'
		  AND o.deleted_at IS NULL
		  AND c.not_after <= NOW() + INTERVAL '1 day' * o.renew_before_days
		  AND c.not_after > NOW()
	`).Scan(&orders).Error
	return orders, err
}
