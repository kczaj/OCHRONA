# OCHRONA
Projekt na przedmiot Ochrona danych w systemach informatycznych

## Przygotowanie do uruchomienia
Nalezy do folderu /src/nginx/ dodać plik z kluczem prywatny oraz w korzeniu repozytorium 
dodać plik .env w którym znajdą się poniższe zmienne:
- SECRET_KEY
- MYSQL_ROOT_PASSWORD
- PEPPER

Format zapisu zmiennych jest następujący: <nazwa_zmiennej>=<wartosc_zmiennej>
Zmienne oddzielone są od siebie "enterami".

## Sposób uruchomienia
Do uruchomienia projektu nalezy uzyc polecenia: docker-compose up