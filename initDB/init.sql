create table if not exists public.users (
    id varchar(32) primary key,
    username varchar(50) unique not null,
    password varchar(500) not null,
    email varchar(320) unique not null,
    last_login timestamptz
)