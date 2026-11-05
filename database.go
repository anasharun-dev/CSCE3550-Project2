package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

// keyStore persists RSA private keys on disk. All queries use bound parameters.
type keyStore struct{ db *sql.DB }

func openKeyStore(path string) (*keyStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &keyStore{db: db}, nil
}
func (s *keyStore) Close() error { return s.db.Close() }
func (s *keyStore) saveKey(key signingKey) (string, error) {
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key.PrivateKey)})
	result, err := s.db.Exec("INSERT INTO keys(key,exp) VALUES (?,?)", data, key.ExpiresAt.Unix())
	if err != nil {
		return "", err
	}
	id, err := result.LastInsertId()
	return strconv.FormatInt(id, 10), err
}
func (s *keyStore) decodeRow(kid int64, data []byte, exp int64) (signingKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return signingKey{}, fmt.Errorf("invalid private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return signingKey{}, err
	}
	return signingKey{PrivateKey: key, Kid: strconv.FormatInt(kid, 10), ExpiresAt: time.Unix(exp, 0)}, nil
}
func (s *keyStore) ensureKeys(now time.Time) error {
	var validCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp > ?", now.Unix()).Scan(&validCount); err != nil {
		return err
	}
	if validCount == 0 {
		key, err := generateSigningKey(now.Add(2 * time.Hour))
		if err != nil {
			return err
		}
		if _, err = s.saveKey(key); err != nil {
			return err
		}
	}
	var expiredCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM keys WHERE exp <= ?", now.Unix()).Scan(&expiredCount); err != nil {
		return err
	}
	if expiredCount == 0 {
		key, err := generateSigningKey(now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if _, err = s.saveKey(key); err != nil {
			return err
		}
	}
	return nil
}
func (s *keyStore) findKey(now int64, expired bool) (signingKey, error) {
	op := "exp > ?"
	order := "exp DESC"
	if expired {
		op = "exp <= ?"
		order = "exp DESC"
	}
	// Both fragments are fixed application constants, never user-provided SQL.
	query := "SELECT kid,key,exp FROM keys WHERE " + op + " ORDER BY " + order + " LIMIT 1"
	var kid, exp int64
	var data []byte
	err := s.db.QueryRow(query, now).Scan(&kid, &data, &exp)
	if err != nil {
		return signingKey{}, err
	}
	return s.decodeRow(kid, data, exp)
}
func (s *keyStore) listValid(now int64) ([]signingKey, error) {
	rows, err := s.db.Query("SELECT kid,key,exp FROM keys WHERE exp > ? ORDER BY kid", now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []signingKey{}
	for rows.Next() {
		var kid, exp int64
		var data []byte
		if err := rows.Scan(&kid, &data, &exp); err != nil {
			return nil, err
		}
		key, err := s.decodeRow(kid, data, exp)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
