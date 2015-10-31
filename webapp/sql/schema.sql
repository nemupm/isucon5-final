-- CREATE USER isucon;
-- CREATE DATABASE isucon5f OWNER isucon ENCODING 'utf8';

-- \connect isucon5f

CREATE TYPE grades AS ENUM ('micro', 'small', 'standard', 'premium');

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(256) NOT NULL,
  salt VARCHAR(32) NOT NULL,
  passhash bytea NOT NULL,
  grade grades
);

-- CREATE EXTENSION pgcrypto;

CREATE TYPE token_types AS ENUM ('header', 'param');

CREATE TABLE endpoints (
  service VARCHAR(32) NOT NULL PRIMARY KEY,
  meth VARCHAR(16) NOT NULL,
  token_type token_types,
  token_key VARCHAR(64),
  uri TEXT
);

CREATE TABLE subscriptions (
  user_id INTEGER REFERENCES users (id) NOT NULL PRIMARY KEY,
  arg TEXT
);

CREATE TABLE subscriptions2 (
  user_id INTEGER NOT NULL PRIMARY KEY,
  ken VARCHAR(64),
  ken2 VARCHAR(64),
  surname VARCHAR(64),
  givenname VARCHAR(64),
  tenki VARCHAR(64),
  perfectsec_req VARCHAR(64),
  perfectsec_token VARCHAR(64),
  perfectsec_attacked VARCHAR(64)
);
