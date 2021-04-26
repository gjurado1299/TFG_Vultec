# Makefile for Vultec management

all: help 

help:
	@echo "Usage: "
	@echo "  make migrate"
	@echo "  make reload_everything"
	@echo "  make create_su"
	@echo "  make drop_db"
	@echo "  make create_db"
	@echo "  make populate"
	@echo "  make runserver"

reload_everything: drop_db create_db migrate create_su populate

migrate:
	python3 manage.py makemigrations scanner
	python3 manage.py migrate

create_su:
	python3 manage.py createsuperuser

drop_db:
	dropdb -U gonxo -h localhost tfg

create_db:
	createdb -U gonxo -h localhost tfg

populate:
	python3 ./populate.py

runserver:
	python3 manage.py runserver 0.0.0.0:8000
