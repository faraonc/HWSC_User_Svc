#!/usr/bin/env bash

docker rm -f devtest;\
docker run --name devtest --mount type=bind,source="$(pwd)",target=/sql -d postgres:alpine;\
sleep 5;\
docker exec -it devtest psql -U postgres -c "CREATE DATABASE testdb;";\
docker exec -it devtest psql -U postgres -f /sql/S1_CREATE_DOMAINS.sql;\
docker exec -it devtest psql -U postgres -f /sql/S2_CREATE_USER_TABLE.sql;\
docker exec -it devtest psql -U postgres -f /sql/S3_CREATE_DOCUMENT_TABLE.sql;\
docker exec -it devtest psql -U postgres -f /sql/S4_CREATE_SHARED_TABLE.sql;\
docker exec -it devtest psql -U postgres -f /sql/test_insert.sql;\
docker exec -it devtest psql -U postgres -c "TABLE user_account;";\
docker exec -it devtest psql -U postgres -c "TABLE documents;";\
docker exec -it devtest psql -U postgres -c "TABLE shared_documents;";\

