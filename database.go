package main

import (
    "database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
)

func setupDatabase(dbPath string) (*sql.DB, error) {
    log.Printf("Conectando a la base de datos en: %s", dbPath)
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }

    if err = db.Ping(); err != nil {
        db.Close()
        return nil, err
    }

    log.Println("Base de datos conectada exitosamente.")
    return db, nil
}
