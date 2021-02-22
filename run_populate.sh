#!/bin/bash

# Drop Database
dropdb -U gonxo -h localhost tfg

# Create Database
createdb -U gonxo -h localhost tfg

# Migrations
python3 manage.py makemigrations scanner
python3 manage.py migrate
python3 manage.py createsuperuser

# Populate database
python3 ./populate.py
