CREATE TABLE account
(
    id         serial                NOT NULL CONSTRAINT account_pk PRIMARY KEY,
    email      varchar(100)          NOT NULL,
    last_login date    DEFAULT now() NOT NULL,
    active     boolean DEFAULT TRUE  NOT NULL,
    ROLES      CHARACTER varying[]
);


ALTER TABLE account OWNER TO mvtnghia;
CREATE UNIQUE INDEX account_email_uindex ON account (email);