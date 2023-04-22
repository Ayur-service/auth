CREATE SCHEMA IF NOT EXISTS ayur_auth;

SET SEARCH_PATH TO ayur_auth;


CREATE TABLE IF NOT EXISTS users (
    ayur_id varchar(12) PRIMARY KEY ,
    phone_number varchar(10) NOT NULL,
    fp_hash varchar(300) NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_users_fp_hash ON users(fp_hash);
CREATE INDEX IF NOT EXISTS ix_users_phone_number ON users(phone_number);

CREATE TABLE IF NOT EXISTS hospital_staff (
    username varchar(15) PRIMARY KEY,
    password varchar(300) NOT NULL,
    hospital_id varchar(15) NOT NULL,
    is_admin boolean default FALSE NOT NULL ,
    access varchar(10) ARRAY NOT NULL  /* refactor it into m2m */
);

-- CREATE TABLE IF NOT EXISTS access (
--     id SERIAL PRIMARY KEY,
--     typ varchar(10) NOT NULL
-- );

-- INSERT INTO access(typ) VALUES ('read'), ('write');

-- CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- CREATE EXTENSION IF NOT EXISTS btree_gin;
-- CREATE INDEX IF NOT EXISTS nameIdx ON users USING GIN (phone_number);